package models

import (
	errors "errors"
	sort "sort"
	strings "strings"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// APIKey is the non-browser way in. It exists so that a script, a cron job, a
// CI pipeline, or another service can call the same API a signed-in person
// calls, without inventing a second permission model for them.
//
// A key carries a role from the same set users do -- admin or user -- so
// whatever an admin may do in the UI an admin-scoped key may do over HTTP,
// and a user-scoped key is limited to exactly what a non-admin account is.
// There is no separate scope language to keep in step with the role checks.
//
// # A key can never outrank its owner
//
// The role here is a *request*, and it is bounded twice. IssueAPIKey refuses
// to mint an admin key for a non-admin account, and NarrowRole re-applies the
// ceiling on every request. The second check is what covers an account that
// is demoted after the key was minted: the stored role still says admin, and
// the effective role does not.
//
// # Same "<id>.<secret>" shape as sessions, and the same hash
//
// The id is the bolt key, so authenticating a key is one O(1) fetch and one
// hash comparison -- see references/architecture.md on why a salted hash
// cannot be looked up. sha256 rather than bcrypt because this runs on every
// request against a 256-bit random secret, exactly like a session; bcrypt
// here would be a latency tax that buys nothing.
type APIKey struct {
	ID         string     `json:"id"`
	UserID     uint64     `json:"user_id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	SecretHash string     `json:"secret_hash"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	// CreatedBy is the admin who minted this key as its owner, through
	// IssueAPIKeyFor. Zero means the owner made it, or it came from a shell,
	// and rows from before this field read as zero too. It is what lets the
	// person a key acts as see that someone else made it.
	CreatedBy uint64 `json:"created_by,omitempty"`
	// Set by DeleteAPIKey. A deleted key is dead and out of every listing,
	// but RestoreAPIKey can bring it back for RestoreWindow.
	SoftDelete
}

var (
	ErrAPIKeyLimit    = errors.New( "this account already holds the maximum number of live API keys" )
	ErrAPIKeyRole     = errors.New( "an API key cannot be given a role its owner does not have" )
	ErrAPIKeyDisabled = errors.New( "cannot issue an API key for a disabled account" )
	ErrAPIKeyDead     = errors.New( "only a live API key can have its expiry changed" )
)

const (
	// APIKeyMaxPerUser bounds how many live keys one account can hold. Any
	// signed-in user can mint keys, so without a cap a single account can
	// grow the bucket without limit. 25 is far past what a person needs and
	// low enough to stay a bound; revoking or deleting one frees a slot.
	APIKeyMaxPerUser = 25

	// apiKeyMaxRowsPerUser bounds the rows one account keeps, dead keys
	// included. The live cap alone does not bound anything: mint, revoke,
	// repeat, and the retained history grows by one row each time, and every
	// listing and quota check decrypts all of it. When an account reaches
	// this, issuing a key drops its oldest dead rows to make room.
	apiKeyMaxRowsPerUser = 100

	// apiKeyTouchInterval is how stale LastUsedAt is allowed to get.
	//
	// "When was this key last used" is the question an operator asks before
	// revoking something, so it is worth recording -- but bolt has a single
	// writer, and a write per authenticated request would put every handler
	// that needs the database behind it. Writing at most once per interval
	// keeps the answer useful (to within 15 minutes) and the cost negligible.
	apiKeyTouchInterval = 15 * time.Minute

	// apiKeyRetention is how long a dead key's row is kept before the purge
	// loop drops it. A revoked key that vanished immediately would make the
	// listing lie about what existed last week, which is the wrong trade for
	// a record this small; keeping it forever is the other wrong trade.
	apiKeyRetention = 30 * 24 * time.Hour

	// APIKeyMaxDays bounds an explicit expiry. Zero still means "never
	// expires", asked for deliberately; this only stops a typo from producing
	// a date so far out that it is the same thing by accident.
	APIKeyMaxDays = 3650
)

// APIKeyTTLFromDays turns a requested lifetime in days into a duration, and
// lives here rather than in a handler so that the HTTP API, the control
// socket, and the CLI cannot end up disagreeing about what "0 days" means.
//
// nil means "use the configured default", 0 means "never expires", and a
// number means that many days. ok is false for a value that is out of range.
func APIKeyTTLFromDays( days *int , fallback time.Duration ) ( ttl time.Duration , ok bool ) {
	if days == nil {
		ttl , ok = fallback , true
		return
	}
	if *days < 0 || *days > APIKeyMaxDays { return }
	ok = true
	if *days > 0 {
		ttl = time.Duration( *days ) * 24 * time.Hour
	}
	return
}

func ( key *APIKey ) Revoked() ( result bool ) {
	result = key.RevokedAt != nil
	return
}

func ( key *APIKey ) Expired() ( result bool ) {
	result = key.ExpiresAt != nil && time.Now().UTC().After( *key.ExpiresAt )
	return
}

// Live means the key would authenticate right now, as far as the key itself
// is concerned. Whether its owner is still enabled is a separate question,
// asked in LoadAPIKey.
func ( key *APIKey ) Live() ( result bool ) {
	result = key.Revoked() == false && key.Expired() == false && key.Deleted() == false
	return
}

// ValidAPIKeyName bounds the label a key is given. It is free text a user
// controls, same as a display name, and it exists only so a list of keys is
// readable -- "deploy bot", "grafana", "my laptop".
func ValidAPIKeyName( name string ) ( result bool ) {
	trimmed := strings.TrimSpace( name )
	result = len( trimmed ) >= 1 && len( trimmed ) <= 80
	return
}

// NarrowRole is the permission ceiling, applied on every request that
// authenticates with a key: the effective role is the *lower* of the account's
// role and the key's.
//
// Storing the key's role and then re-deriving the effective one, rather than
// trusting what was stored, is what makes demotion work. If an admin mints an
// admin key and later becomes an ordinary user, the row still says admin --
// and every request it authenticates is treated as a user.
func NarrowRole( account_role string , key_role string ) ( result string ) {
	result = RoleUser
	if account_role == RoleAdmin && key_role == RoleAdmin {
		result = RoleAdmin
	}
	return
}

// IssueAPIKey returns the raw credential exactly once. It is never stored and
// cannot be recovered -- if it is lost, revoke or delete the key and mint
// another.
//
// ttl of zero means the key never expires. That is a deliberate option rather
// than an oversight: a CI job nobody will remember to re-key is worse served
// by a credential that dies silently at 3am. It has to be asked for
// explicitly; the default comes from configuration.
func IssueAPIKey( store *db.Store , user_id uint64 , name string , role string , ttl time.Duration ) ( credential string , key *APIKey , err error ) {
	credential , key , err = issueAPIKey( store , user_id , name , role , ttl , 0 )
	return
}

// IssueAPIKeyFor is an admin minting a key that acts as someone else, so it
// follows the ladder deleting an account does, for the same reason -- acting
// as an account is as much power over it as removing it:
//
//   - nobody mints for the owner (ErrOwnerProtected) -- a shell still can,
//     through IssueAPIKey;
//   - only the owner mints for another admin (ErrOwnerRequired).
//
// Your own account is simply your own key. The rules are checked inside the
// issuing transaction, so ownership cannot move between the check and the key.
func IssueAPIKeyFor( store *db.Store , actor_id uint64 , user_id uint64 , name string , role string , ttl time.Duration ) ( credential string , key *APIKey , err error ) {
	if actor_id == user_id {
		credential , key , err = IssueAPIKey( store , user_id , name , role , ttl )
		return
	}
	credential , key , err = issueAPIKey( store , user_id , name , role , ttl , actor_id )
	return
}

// issueAPIKey is both of the above. A created_by of zero means the key is its
// owner's own, or came from a shell, and no ladder applies.
func issueAPIKey( store *db.Store , user_id uint64 , name string , role string , ttl time.Duration , created_by uint64 ) ( credential string , key *APIKey , err error ) {
	// The owner is loaded inside the transaction below rather than taking the
	// caller's word for the role. Every route into this function -- the HTTP
	// API, the control socket, the CLI -- then gets the same ceiling without
	// each having to remember it.
	if ValidRole( role ) == false {
		role = RoleUser
	}

	key_id := encryption.GenerateURLToken( 12 )
	secret := encryption.GenerateURLToken( 32 )
	now := time.Now().UTC()
	key = &APIKey{
		ID:         key_id,
		UserID:     user_id,
		Name:       strings.TrimSpace( name ),
		Role:       role,
		SecretHash: encryption.Sha256Hex( secret ),
		CreatedAt:  now,
		CreatedBy:  created_by,
	}
	if ttl > 0 {
		expires := now.Add( ttl )
		key.ExpiresAt = &expires
	}

	// The owner check, the quota check, and the insert share one transaction.
	// Counted in one transaction and inserted in another, sixteen concurrent
	// requests can all see 24 live keys and all insert, which is how a "max
	// 25" turns into 40.
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		owner := &User{}
		if tx_err = tx.Get( db.BucketUsers , encryption.Uint64ToBytes( user_id ) , owner ); tx_err != nil { return }
		if created_by != 0 {
			owner_id , owner_err := ownerIDTx( tx )
			if owner_err != nil {
				tx_err = owner_err
				return
			}
			if owner_id == user_id {
				tx_err = ErrOwnerProtected
				return
			}
			if owner.IsAdmin() && created_by != owner_id {
				tx_err = ErrOwnerRequired
				return
			}
		}
		if owner.Disabled() {
			tx_err = ErrAPIKeyDisabled
			return
		}
		if role == RoleAdmin && owner.IsAdmin() == false {
			tx_err = ErrAPIKeyRole
			return
		}

		owned := []*APIKey{}
		tx_err = tx.ForEach( db.BucketAPIKeys ,
			func() any { return &APIKey{} } ,
			func( key []byte , item any ) bool {
				if stored := item.( *APIKey ); stored.UserID == user_id {
					owned = append( owned , stored )
				}
				return true
			} )
		if tx_err != nil { return }

		live := 0
		dead := []*APIKey{}
		for _ , stored := range owned {
			if stored.Live() {
				live += 1
			} else {
				dead = append( dead , stored )
			}
		}
		if live >= APIKeyMaxPerUser {
			tx_err = ErrAPIKeyLimit
			return
		}
		// Oldest dead rows first. Live keys are capped well below the row
		// limit, so there is always a dead row to drop when the limit is hit.
		sort.Slice( dead , func( i int , j int ) bool { return dead[ i ].CreatedAt.Before( dead[ j ].CreatedAt ) } )
		for excess := len( owned ) + 1 - apiKeyMaxRowsPerUser; excess > 0 && len( dead ) > 0; excess -= 1 {
			if tx_err = tx.Delete( db.BucketAPIKeys , []byte( dead[ 0 ].ID ) ); tx_err != nil { return }
			dead = dead[ 1: ]
		}

		tx_err = tx.Put( db.BucketAPIKeys , []byte( key_id ) , key )
		return
	} )
	if err != nil {
		key = nil
		return
	}
	credential = key_id + "." + secret
	return
}

// LoadAPIKey returns nil (with no error) for anything that is not a usable
// key -- wrong shape, unknown id, bad secret, expired, revoked, or belonging
// to a disabled account. Callers only ever need "is this request
// authenticated", and folding every failure into one answer avoids leaking
// which check failed.
//
// Note what is *not* here: a disabled account does not have its keys revoked,
// the way it has its sessions destroyed. A session is a browser artifact and
// destroying it costs nothing; a key is a configured integration, and tearing
// every integration's credential down because someone was disabled for an
// afternoon is a footgun with no security gain -- the check below already
// refuses the request either way.
func LoadAPIKey( store *db.Store , credential string ) ( key *APIKey , user *User ) {
	key_id , secret , ok := splitCredential( credential )
	if ok == false { return }

	found := &APIKey{}
	if err := store.Get( db.BucketAPIKeys , []byte( key_id ) , found ); err != nil { return }

	if encryption.ConstantTimeEqual( found.SecretHash , encryption.Sha256Hex( secret ) ) == false { return }
	if found.Live() == false { return }

	loaded_user , err := GetUser( store , found.UserID )
	if err != nil || loaded_user.Disabled() { return }

	touchAPIKey( store , found )
	key , user = found , loaded_user
	return
}

// touchAPIKey records use at most once per apiKeyTouchInterval. Failures are
// ignored on purpose: this is bookkeeping, and a request that authenticated
// correctly should not fail because a timestamp could not be written.
func touchAPIKey( store *db.Store , key *APIKey ) {
	now := time.Now().UTC()
	if key.LastUsedAt != nil && now.Sub( *key.LastUsedAt ) < apiKeyTouchInterval {
		return
	}
	store.UpdateValue( db.BucketAPIKeys , []byte( key.ID ) ,
		func() any { return &APIKey{} } ,
		func( item any ) ( mutate_err error ) {
			item.( *APIKey ).LastUsedAt = &now
			return
		} )
	key.LastUsedAt = &now
	return
}

func GetAPIKey( store *db.Store , key_id string ) ( key *APIKey , err error ) {
	key = &APIKey{}
	err = store.Get( db.BucketAPIKeys , []byte( key_id ) , key )
	if err != nil { key = nil }
	return
}

// sortAPIKeys puts keys oldest first. A key's bucket key is a random token, so
// the bucket order means nothing and would change a page's rows between calls.
func sortAPIKeys( keys []*APIKey ) {
	sort.SliceStable( keys , func( i int , j int ) bool { return keys[ i ].CreatedAt.Before( keys[ j ].CreatedAt ) } )
}

// ListAPIKeys returns every key in the database, newest last, leaving out
// deleted ones. Only the admin endpoint and the CLI use it; a user asking for
// "my keys" goes through ListAPIKeysForUser.
func ListAPIKeys( store *db.Store ) ( keys []*APIKey , err error ) {
	keys = []*APIKey{}
	err = store.ForEach( db.BucketAPIKeys ,
		func() any { return &APIKey{} } ,
		func( key []byte , item any ) bool {
			if stored := item.( *APIKey ); stored.Deleted() == false {
				keys = append( keys , stored )
			}
			return true
		} )
	sortAPIKeys( keys )
	return
}

func ListAPIKeysForUser( store *db.Store , user_id uint64 ) ( keys []*APIKey , err error ) {
	keys = []*APIKey{}
	err = store.ForEach( db.BucketAPIKeys ,
		func() any { return &APIKey{} } ,
		func( key []byte , item any ) bool {
			stored := item.( *APIKey )
			if stored.UserID == user_id && stored.Deleted() == false {
				keys = append( keys , stored )
			}
			return true
		} )
	sortAPIKeys( keys )
	return
}

func CountLiveAPIKeysForUser( store *db.Store , user_id uint64 ) ( count int , err error ) {
	err = store.ForEach( db.BucketAPIKeys ,
		func() any { return &APIKey{} } ,
		func( key []byte , item any ) bool {
			stored := item.( *APIKey )
			if stored.UserID == user_id && stored.Live() {
				count += 1
			}
			return true
		} )
	return
}

// RevokeAPIKey marks a key dead. It is idempotent -- revoking twice keeps the
// first timestamp -- and it goes through UpdateValue so that two concurrent
// revocations cannot have one overwrite the other with a stale copy of the row.
//
// The row is marked rather than deleted so that a listing can still show the
// key existed and when it died. The `purge` job removes it later.
func RevokeAPIKey( store *db.Store , key_id string ) ( err error ) {
	err = store.UpdateValue( db.BucketAPIKeys , []byte( key_id ) ,
		func() any { return &APIKey{} } ,
		func( item any ) ( mutate_err error ) {
			key := item.( *APIKey )
			if key.RevokedAt == nil {
				now := time.Now().UTC()
				key.RevokedAt = &now
			}
			return
		} )
	return
}

// RenameAPIKey changes a key's label, which is all a name is: nothing about what
// the key may do hangs off it, so a dead key can be renamed too. db.ErrNotFound
// when there is no such key or it is deleted.
//
// expect, when not nil, is the name the caller believes is stored, as in
// RenameUser: a *RenameConflictError if it is not, which keeps an undo from
// overwriting a rename made somewhere else.
func RenameAPIKey( store *db.Store , key_id string , name string , expect *string ) ( err error ) {
	err = store.UpdateValue( db.BucketAPIKeys , []byte( key_id ) ,
		func() any { return &APIKey{} } ,
		func( item any ) ( mutate_err error ) {
			key := item.( *APIKey )
			if key.Deleted() {
				mutate_err = db.ErrNotFound
				return
			}
			if expect != nil && key.Name != strings.TrimSpace( *expect ) {
				mutate_err = &RenameConflictError{ Current: key.Name }
				return
			}
			key.Name = strings.TrimSpace( name )
			return
		} )
	return
}

// SetAPIKeyExpiry gives a live key a new expiry, counted from now; a ttl of zero
// means it never expires, as when issuing one.
//
// A dead key stays dead (ErrAPIKeyDead). Reviving an expired key here would turn
// an edit into a way round the expiry, and a revoked one would break the promise
// that revoking is final: a new key is the way back. db.ErrNotFound when there
// is no such key or it is deleted.
//
// actor_id is who is asking. Keeping someone else's key alive is as much power
// over that account as minting one for it, so it follows the same ladder as
// IssueAPIKeyFor: nobody touches the owner's keys, and only the owner touches
// another admin's. Otherwise an admin holding a stolen key could keep it going.
func SetAPIKeyExpiry( store *db.Store , key_id string , actor_id uint64 , ttl time.Duration ) ( key *APIKey , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		stored := &APIKey{}
		if tx_err = tx.Get( db.BucketAPIKeys , []byte( key_id ) , stored ); tx_err != nil { return }
		if stored.Deleted() {
			tx_err = db.ErrNotFound
			return
		}
		if stored.Live() == false {
			tx_err = ErrAPIKeyDead
			return
		}
		if actor_id != stored.UserID {
			holder := &User{}
			if tx_err = tx.Get( db.BucketUsers , encryption.Uint64ToBytes( stored.UserID ) , holder ); tx_err != nil { return }
			owner_id , owner_err := ownerIDTx( tx )
			if owner_err != nil {
				tx_err = owner_err
				return
			}
			if owner_id == stored.UserID {
				tx_err = ErrOwnerProtected
				return
			}
			if holder.IsAdmin() && actor_id != owner_id {
				tx_err = ErrOwnerRequired
				return
			}
		}
		stored.ExpiresAt = nil
		if ttl > 0 {
			expires := time.Now().UTC().Add( ttl )
			stored.ExpiresAt = &expires
		}
		if tx_err = tx.Put( db.BucketAPIKeys , []byte( key_id ) , stored ); tx_err != nil { return }
		key = stored
		return
	} )
	return
}

// DeleteAPIKey takes a key off every listing and stops it working, now.
// db.ErrNotFound when there is no such key or it is already deleted.
//
// Unlike revoking, this can be undone: the row is only marked, and
// RestoreAPIKey brings it back -- working again -- for RestoreWindow, after
// which the purge removes it. Revoke is the one-way switch for a key that
// may have leaked; delete is tidying up, and tidying up the wrong row is the
// mistake an undo exists for. The routes decide who may ask.
func DeleteAPIKey( store *db.Store , key_id string , actor_id uint64 ) ( err error ) {
	err = store.UpdateValue( db.BucketAPIKeys , []byte( key_id ) ,
		func() any { return &APIKey{} } ,
		func( item any ) ( mutate_err error ) {
			if item.( *APIKey ).markDeleted( actor_id ) == false {
				mutate_err = db.ErrNotFound
			}
			return
		} )
	return
}

// RestoreAPIKey undoes DeleteAPIKey. ErrRestoreGone, ErrRestoreForbidden or
// ErrRestoreExpired when it may not happen, and ErrAPIKeyLimit when bringing
// it back would put its owner over the live key cap -- the same cap
// IssueAPIKey keeps, checked in the same transaction for the same reason.
func RestoreAPIKey( store *db.Store , key_id string , actor_id uint64 , actor_is_admin bool ) ( key *APIKey , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		found := &APIKey{}
		if tx_err = tx.Get( db.BucketAPIKeys , []byte( key_id ) , found ); tx_err != nil {
			if errors.Is( tx_err , db.ErrNotFound ) { tx_err = ErrRestoreGone }
			return
		}
		if tx_err = found.unmarkDeleted( actor_id , actor_is_admin ); tx_err != nil { return }
		if found.Live() {
			live := 0
			tx_err = tx.ForEach( db.BucketAPIKeys ,
				func() any { return &APIKey{} } ,
				func( key []byte , item any ) bool {
					if stored := item.( *APIKey ); stored.UserID == found.UserID && stored.Live() {
						live += 1
					}
					return true
				} )
			if tx_err != nil { return }
			if live >= APIKeyMaxPerUser {
				tx_err = ErrAPIKeyLimit
				return
			}
		}
		tx_err = tx.Put( db.BucketAPIKeys , []byte( key_id ) , found )
		key = found
		return
	} )
	if err != nil { key = nil }
	return
}

// PurgeAPIKey removes a key's row outright, with no way back. Only the CLI
// uses it (directly or through the control socket): an operator at a shell
// has no Undo button, so a soft delete there would only leave the row lying
// around.
//
// Get and delete share one transaction so a missing key is reported as
// db.ErrNotFound rather than silently succeeding, which bolt's Delete would.
func PurgeAPIKey( store *db.Store , key_id string ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		if tx_err = tx.Get( db.BucketAPIKeys , []byte( key_id ) , &APIKey{} ); tx_err != nil { return }
		tx_err = tx.Delete( db.BucketAPIKeys , []byte( key_id ) )
		return
	} )
	return
}

// PurgeDeadAPIKeys drops rows for keys that have been revoked or expired for
// longer than apiKeyRetention, and deleted ones past RestoreWindow. Dead keys are already refused by LoadAPIKey, so
// this is only housekeeping -- one transaction, for the same reason as
// PurgeExpiredSessions.
func PurgeDeadAPIKeys( store *db.Store ) ( removed int , err error ) {
	cutoff := time.Now().UTC().Add( -apiKeyRetention )
	removed , err = store.DeleteWhere( db.BucketAPIKeys ,
		func() any { return &APIKey{} } ,
		func( key []byte , item any ) bool {
			stored := item.( *APIKey )
			if stored.RevokedAt != nil && stored.RevokedAt.Before( cutoff ) {
				return true
			}
			if stored.deletedLongAgo() {
				return true
			}
			return stored.ExpiresAt != nil && stored.ExpiresAt.Before( cutoff )
		} )
	return
}
