package models

import (
	errors "errors"
	sort "sort"
	strings "strings"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// Session is the server side of a login. The cookie never carries the user id
// or the role -- only an opaque reference -- so revoking access is a matter of
// deleting this record, with no token denylist to maintain.
//
// The credential is shaped "<id>.<secret>": the id is the bolt key, so lookup
// is a single O(1) fetch, and only the secret's hash is stored. A stolen
// database therefore contains nothing that can be replayed as a cookie.
type Session struct {
	UserID     uint64    `json:"user_id"`
	SecretHash string    `json:"secret_hash"`
	CSRFToken  string    `json:"csrf_token"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	// What the account owner sees on their devices list. All three are
	// optional: the address and browser are recorded just after the session
	// is made, and a session from before they existed has none.
	IP         string     `json:"ip,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	// ID is the record's key, filled in when a session is read. It is not
	// stored, since the key already says it, and is no use without the secret.
	ID string `json:"-"`
}

// sessionTouchInterval bounds how often last-seen is written. Every request
// loads the session, and bolt has one writer, so an exact time would cost a
// write per request for a number nobody reads to the second.
const sessionTouchInterval = 15 * time.Minute

// SessionUserAgentMax is how much of a User-Agent header is kept.
const SessionUserAgentMax = 256

// ErrSessionNotFound answers both an unknown session and someone else's, so
// the difference cannot be used to find out which ids exist.
var ErrSessionNotFound = errors.New( "session not found" )

func splitCredential( raw string ) ( id string , secret string , ok bool ) {
	parts := strings.SplitN( raw , "." , 2 )
	if len( parts ) != 2 || parts[ 0 ] == "" || parts[ 1 ] == "" { return }
	id , secret , ok = parts[ 0 ] , parts[ 1 ] , true
	return
}

// newSession builds a session without storing it. Its callers --
// startSignInTx, FinishChallenge, JoinInviteLink -- store it in the
// same transaction that checks the link and the account are still good, so
// there is deliberately no CreateSession that writes one on its own.
// SessionID is the record key inside a session credential, or "".
func SessionID( credential string ) ( session_id string ) {
	session_id , _ , _ = splitCredential( credential )
	return
}

func newSession( user_id uint64 , ttl time.Duration ) ( session_id string , credential string , session *Session ) {
	session_id = encryption.GenerateURLToken( 16 )
	secret := encryption.GenerateURLToken( 32 )
	now := time.Now().UTC()
	session = &Session{
		UserID:     user_id,
		SecretHash: encryption.Sha256Hex( secret ),
		CSRFToken:  encryption.GenerateURLToken( 24 ),
		CreatedAt:  now,
		ExpiresAt:  now.Add( ttl ),
	}
	credential = session_id + "." + secret
	return
}

// LoadSession returns nil (with no error) for anything that is not a live
// session -- wrong shape, unknown id, bad secret, expired, or belonging to a
// disabled user. Callers only ever need to ask "am I logged in", and folding
// every failure into the same answer avoids leaking which check failed.
func LoadSession( store *db.Store , credential string ) ( session *Session , user *User ) {
	session_id , secret , ok := splitCredential( credential )
	if ok == false { return }

	found := &Session{}
	if err := store.Get( db.BucketSessions , []byte( session_id ) , found ); err != nil { return }

	if encryption.ConstantTimeEqual( found.SecretHash , encryption.Sha256Hex( secret ) ) == false { return }
	if time.Now().UTC().After( found.ExpiresAt ) {
		store.Delete( db.BucketSessions , []byte( session_id ) )
		return
	}

	loaded_user , err := GetUser( store , found.UserID )
	if err != nil || loaded_user.Disabled() { return }

	found.ID = session_id
	session , user = found , loaded_user
	return
}

// RecordSessionDevice notes where a session was signed in from. The session is
// made inside the sign-in transaction, which has no request to read this from,
// so it is added straight after; failing here is ignored, because a sign-in
// that worked should not fail over what the devices list will show. An update
// rather than a write, so it cannot bring back a session that has just ended.
func RecordSessionDevice( store *db.Store , credential string , ip string , user_agent string ) {
	session_id , _ , ok := splitCredential( credential )
	if ok == false { return }
	now := time.Now().UTC()
	store.UpdateValue( db.BucketSessions , []byte( session_id ) ,
		func() any { return &Session{} } ,
		func( item any ) ( mutate_err error ) {
			session := item.( *Session )
			session.IP = ip
			session.UserAgent = user_agent
			session.LastSeenAt = &now
			return
		} )
}

// sessionExpiry is when a session used now should end: ttl from now, but never
// later than max_age after it was signed in, and never earlier than it already
// ends, so shortening the ttl does not cut off a session mid-use.
func sessionExpiry( session *Session , now time.Time , ttl time.Duration , max_age time.Duration ) ( expires time.Time ) {
	expires = now.Add( ttl )
	if limit := session.CreatedAt.Add( max_age ); expires.After( limit ) {
		expires = limit
	}
	if expires.Before( session.ExpiresAt ) {
		expires = session.ExpiresAt
	}
	return
}

// TouchSession records use at most once per sessionTouchInterval, and moves the
// session's end out in the same write, so someone using the app every day is
// not signed out at a date set when they signed in. Without a password that
// would mean asking an admin for a new link. extended says the end moved, which
// is the caller's cue to send the cookie again: it has its own expiry.
//
// It is called for requests a person made, not from LoadSession: a live stream
// re-checking its session every few seconds is not the person being there.
// Failures are ignored for the same reason as touchAPIKey.
func TouchSession( store *db.Store , session *Session , ttl time.Duration , max_age time.Duration ) ( extended bool ) {
	now := time.Now().UTC()
	if session.LastSeenAt != nil && now.Sub( *session.LastSeenAt ) < sessionTouchInterval {
		return
	}
	expires := sessionExpiry( session , now , ttl , max_age )
	update_err := store.UpdateValue( db.BucketSessions , []byte( session.ID ) ,
		func() any { return &Session{} } ,
		func( item any ) ( mutate_err error ) {
			stored := item.( *Session )
			stored.LastSeenAt = &now
			stored.ExpiresAt = expires
			return
		} )
	session.LastSeenAt = &now
	if update_err != nil { return }
	extended = expires.After( session.ExpiresAt )
	session.ExpiresAt = expires
	return
}

// ListSessionsForUser is an account's live sessions, newest first.
func ListSessionsForUser( store *db.Store , user_id uint64 ) ( sessions []*Session , err error ) {
	sessions = []*Session{}
	now := time.Now().UTC()
	err = store.ForEach( db.BucketSessions ,
		func() any { return &Session{} } ,
		func( key []byte , item any ) bool {
			stored := item.( *Session )
			if stored.UserID == user_id && now.After( stored.ExpiresAt ) == false {
				stored.ID = string( key )
				sessions = append( sessions , stored )
			}
			return true
		} )
	sort.Slice( sessions , func( a int , b int ) ( less bool ) {
		less = sessions[ a ].CreatedAt.After( sessions[ b ].CreatedAt )
		return
	} )
	return
}

// RevokeSession ends one of an account's own sessions. The ownership check and
// the delete share a transaction, so what was checked is what goes.
func RevokeSession( store *db.Store , user_id uint64 , session_id string ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		session := &Session{}
		tx_err = tx.Get( db.BucketSessions , []byte( session_id ) , session )
		if errors.Is( tx_err , db.ErrNotFound ) || ( tx_err == nil && session.UserID != user_id ) {
			tx_err = ErrSessionNotFound
			return
		}
		if tx_err != nil { return }
		tx_err = tx.Delete( db.BucketSessions , []byte( session_id ) )
		return
	} )
	return
}

// RevokeOtherSessions ends every session an account holds but keep_session_id.
func RevokeOtherSessions( store *db.Store , user_id uint64 , keep_session_id string ) ( removed int , err error ) {
	removed , err = store.DeleteWhere( db.BucketSessions ,
		func() any { return &Session{} } ,
		func( key []byte , item any ) bool {
			return item.( *Session ).UserID == user_id && string( key ) != keep_session_id
		} )
	return
}

func DestroySession( store *db.Store , credential string ) ( err error ) {
	session_id , _ , ok := splitCredential( credential )
	if ok == false { return }
	err = store.Delete( db.BucketSessions , []byte( session_id ) )
	return
}

// destroySessionsForUser deletes every session an account holds, inside the
// caller's transaction. It is not exported because deleting sessions is only
// ever half of a revocation: SetUserDisabled and RevokeAllCredentials run it
// together with the account change in one transaction, so a login link
// redeemed at the same moment either lands before (and its session is
// deleted here) or after (and sees the change).
func destroySessionsForUser( tx *db.Tx , user_id uint64 ) ( removed int , err error ) {
	removed , err = tx.DeleteWhere( db.BucketSessions ,
		func() any { return &Session{} } ,
		func( key []byte , item any ) bool {
			return item.( *Session ).UserID == user_id
		} )
	return
}

// PurgeExpiredSessions is called on a timer from main. Expired rows are
// already refused by LoadSession, so this is only housekeeping to stop the
// bolt file growing without bound -- but it still runs as one transaction,
// because bolt has a single writer and an hourly sweep that took one
// transaction per row would stall every request handler waiting to write.
func PurgeExpiredSessions( store *db.Store ) ( removed int , err error ) {
	now := time.Now().UTC()
	removed , err = store.DeleteWhere( db.BucketSessions ,
		func() any { return &Session{} } ,
		func( key []byte , item any ) bool {
			return now.After( item.( *Session ).ExpiresAt )
		} )
	return
}
