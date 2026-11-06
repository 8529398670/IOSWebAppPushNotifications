// Package models holds one file per stored record type. There is no ORM and
// no query builder -- each file is a small set of plain functions over the db
// store, which is enough for a bolt key/value file and keeps the storage
// layer readable end to end.
package models

import (
	strings "strings"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User: links are the way in. A password is optional and off by default (see
// password.go): an account gets one only by signing in with a link first, so
// there is no signup, and the owner decides whether passwords work at all. See
// references/architecture.md.
type User struct {
	ID          uint64     `json:"id"`
	DisplayName string     `json:"display_name"`
	Role        string     `json:"role"`
	CreatedAt   time.Time  `json:"created_at"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
	// PinHash is the optional PIN asked for when someone signs back in
	// through an invite link. It is not a password: nothing else checks it.
	// See pin.go.
	PinHash string `json:"pin_hash,omitempty"`
	// What password sign-in needs: a unique name to look the account up by,
	// since display names are not unique, and a bcrypt hash of what the
	// browser derived from the password. See password.go.
	Username     string `json:"username,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
	// PasswordBlocked is the owner's per-account block. It stops the password
	// working and keeps the hash, so unblocking restores it.
	PasswordBlocked bool `json:"password_blocked,omitempty"`
	// TOTP secrets are encrypted here as well as with the record, because
	// server.encrypt_at_rest can be off and a secret cannot be hashed. See
	// two_factor.go.
	TOTPSecret     string   `json:"totp_secret,omitempty"`
	TOTPPending    string   `json:"totp_pending,omitempty"`
	TOTPLastStep   uint64   `json:"totp_last_step,omitempty"`
	RecoveryHashes []string `json:"recovery_hashes,omitempty"`
}

func ( user *User ) Disabled() ( result bool ) {
	result = user.DisabledAt != nil
	return
}

func ( user *User ) IsAdmin() ( result bool ) {
	result = user.Role == RoleAdmin
	return
}

func ValidRole( role string ) ( result bool ) {
	result = role == RoleAdmin || role == RoleUser
	return
}

// ValidDisplayName bounds the one piece of free text a user controls. The cap
// is about keeping the database and the UI sane; escaping for display is the
// frontend's job (see static/js/dom.js, which never uses innerHTML for
// user-supplied values).
func ValidDisplayName( display_name string ) ( result bool ) {
	trimmed := strings.TrimSpace( display_name )
	result = len( trimmed ) >= 1 && len( trimmed ) <= 80
	return
}

// CreateUser stores a new account. The first admin ever created -- by the
// first-run bootstrap or `manage bootstrap-admin` -- also becomes the owner,
// in the same transaction, so there is no moment where admins exist and no
// owner does. See owner.go.
//
// Ids come from the bucket's sequence and are never reused, so a deleted
// account's id can never come back as a different person.
func CreateUser( store *db.Store , display_name string , role string ) ( user *User , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		user , tx_err = createUserTx( tx , display_name , role )
		return
	} )
	if err != nil { user = nil }
	return
}

// createUserTx is CreateUser inside the caller's transaction, for an account
// that has to be created together with something else -- joining through an
// invite link creates the account, takes a place on the link, and starts the
// session all at once.
func createUserTx( tx *db.Tx , display_name string , role string ) ( user *User , err error ) {
	next_id , err := tx.NextSequence( db.BucketUsers )
	if err != nil { return }
	user = &User{
		ID:          next_id,
		DisplayName: strings.TrimSpace( display_name ),
		Role:        role,
		CreatedAt:   time.Now().UTC(),
	}
	if err = tx.Put( db.BucketUsers , encryption.Uint64ToBytes( user.ID ) , user ); err != nil { return }
	if role != RoleAdmin { return }
	owner_id , err := ownerIDTx( tx )
	if err != nil || owner_id != 0 { return }
	err = setOwnerTx( tx , user.ID )
	return
}

func GetUser( store *db.Store , user_id uint64 ) ( user *User , err error ) {
	user = &User{}
	err = store.Get( db.BucketUsers , encryption.Uint64ToBytes( user_id ) , user )
	if err != nil { user = nil }
	return
}

func ListUsers( store *db.Store ) ( users []*User , err error ) {
	users = []*User{}
	err = store.ForEach( db.BucketUsers ,
		func() any { return &User{} } ,
		func( key []byte , item any ) bool {
			users = append( users , item.( *User ) )
			return true
		} )
	return
}

func SaveUser( store *db.Store , user *User ) ( err error ) {
	err = store.Put( db.BucketUsers , encryption.Uint64ToBytes( user.ID ) , user )
	return
}

// RenameUser and SetUserDisabled both edit a record that already exists, so
// the read and the write land in one transaction rather than GetUser followed
// by SaveUser. That is what stops two concurrent admin requests from each
// reading the old row and the slower one silently discarding the other's
// change.
//
// expect, when not nil, is the name the caller believes is stored, checked in
// the same transaction: a *RenameConflictError if it is not. It is what makes
// an undo of a rename safe -- putting the old name back must not overwrite
// one somebody chose in another tab since.
func RenameUser( store *db.Store , user_id uint64 , display_name string , expect *string ) ( err error ) {
	err = store.UpdateValue( db.BucketUsers , encryption.Uint64ToBytes( user_id ) ,
		func() any { return &User{} } ,
		func( item any ) ( mutate_err error ) {
			user := item.( *User )
			if expect != nil && user.DisplayName != strings.TrimSpace( *expect ) {
				mutate_err = &RenameConflictError{ Current: user.DisplayName }
				return
			}
			user.DisplayName = strings.TrimSpace( display_name )
			return
		} )
	return
}

// RenameUserAs is RenameUser for one account acting on another: any admin may
// rename an ordinary user, and only the owner may rename an admin
// (ErrOwnerRequired), because a name is how people tell who they are dealing
// with. Your own name goes through RenameUser, from the Account screen.
func RenameUserAs( store *db.Store , user_id uint64 , actor_id uint64 , display_name string , expect *string ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		key := encryption.Uint64ToBytes( user_id )
		user := &User{}
		if tx_err = tx.Get( db.BucketUsers , key , user ); tx_err != nil { return }
		owner_id , tx_err := ownerIDTx( tx )
		if tx_err != nil { return }
		if user.IsAdmin() && actor_id != owner_id {
			tx_err = ErrOwnerRequired
			return
		}
		if expect != nil && user.DisplayName != strings.TrimSpace( *expect ) {
			tx_err = &RenameConflictError{ Current: user.DisplayName }
			return
		}
		user.DisplayName = strings.TrimSpace( display_name )
		tx_err = tx.Put( db.BucketUsers , key , user )
		return
	} )
	return
}

// SetUserRole makes an account an admin or an ordinary user, and says whether
// that changed anything. The rules follow deleting: nobody changes their own
// role (ErrRoleSelf), the owner is always an admin (ErrOwnerProtected, transfer
// ownership first), and only the owner takes an admin's rights away
// (ErrOwnerRequired). Any admin may make one, as any admin can create one.
//
// Becoming an admin ends the account's sessions and unused login links in the
// same transaction. Whoever holds an invite link can sign in as an account that
// joined through it, so a session already open may not be the person being
// promoted. An admin cannot sign in through an invite link, so a new login link
// is the way back in.
//
// Losing admin rights ends nothing: the role is read on every request, so it
// applies at once, and API keys narrow to it (see NarrowRole). Invite links the
// account made stop working while it is not an admin (see inviteLinkUsable).
func SetUserRole( store *db.Store , user_id uint64 , actor_id uint64 , role string ) ( changed bool , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		key := encryption.Uint64ToBytes( user_id )
		user := &User{}
		if tx_err = tx.Get( db.BucketUsers , key , user ); tx_err != nil { return }
		if user_id == actor_id {
			tx_err = ErrRoleSelf
			return
		}
		owner_id , tx_err := ownerIDTx( tx )
		if tx_err != nil { return }
		if user_id == owner_id {
			tx_err = ErrOwnerProtected
			return
		}
		if user.Role == role { return }
		if user.IsAdmin() && actor_id != owner_id {
			tx_err = ErrOwnerRequired
			return
		}
		user.Role = role
		if tx_err = tx.Put( db.BucketUsers , key , user ); tx_err != nil { return }
		changed = true
		if user.IsAdmin() == false { return }
		if _ , tx_err = destroySessionsForUser( tx , user_id ); tx_err != nil { return }
		if _ , tx_err = deletePendingLoginTokens( tx , user_id ); tx_err != nil { return }
		tx_err = deleteChallengesForUser( tx , user_id )
		return
	} )
	if err != nil { changed = false }
	return
}

// RenameConflictError is RenameUser's answer when the name was not what the
// caller expected: someone changed it since. Current is the name it has now.
type RenameConflictError struct {
	Current string
}

func ( conflict *RenameConflictError ) Error() ( result string ) {
	result = "the name was changed somewhere else in the meantime"
	return
}

// SetUserDisabled disables or re-enables an account. Disabling also deletes
// every session the account holds and every login link it has not used yet,
// in the same transaction as the change itself: a session or a link that
// survived would come back to life the moment the account was re-enabled.
// API keys are deliberately left alone -- see LoadAPIKey -- and use
// RevokeAllCredentials when they should die too.
//
// The owner cannot be disabled by any route, the CLI included: the owner is
// always an enabled admin (see owner.go). Transfer ownership first.
func SetUserDisabled( store *db.Store , user_id uint64 , disabled bool ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		key := encryption.Uint64ToBytes( user_id )
		user := &User{}
		if tx_err = tx.Get( db.BucketUsers , key , user ); tx_err != nil { return }
		if disabled {
			if tx_err = refuseOwnerTx( tx , user_id ); tx_err != nil { return }
			now := time.Now().UTC()
			user.DisabledAt = &now
		} else {
			user.DisabledAt = nil
		}
		if tx_err = tx.Put( db.BucketUsers , key , user ); tx_err != nil { return }
		if disabled == false { return }
		if _ , tx_err = destroySessionsForUser( tx , user_id ); tx_err != nil { return }
		if _ , tx_err = deletePendingLoginTokens( tx , user_id ); tx_err != nil { return }
		tx_err = deleteChallengesForUser( tx , user_id )
		return
	} )
	return
}

// AnyAdminExists decides whether the server prints a first-run login link on
// boot. Once one admin exists, that bootstrap path stays closed.
func AnyAdminExists( store *db.Store ) ( result bool , err error ) {
	err = store.ForEach( db.BucketUsers ,
		func() any { return &User{} } ,
		func( key []byte , item any ) bool {
			user := item.( *User )
			if user.IsAdmin() && user.Disabled() == false {
				result = true
				return false
			}
			return true
		} )
	return
}
