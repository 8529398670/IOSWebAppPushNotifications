package models

import (
	errors "errors"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

var ErrLoginTokenInvalid = errors.New( "login token is invalid, expired, or already used" )

// LoginToken is this project's entire replacement for a signup form and a
// password reset flow. An admin (or the first-run bootstrap) mints one for a
// specific user; redeeming the link is the login.
//
// Same "<id>.<secret>" shape as Session, but the secret is bcrypt-hashed
// rather than sha256'd. bcrypt is affordable here precisely because it runs
// once per redemption instead of once per request, and the id prefix is what
// keeps that to a single hash comparison -- hashing every candidate row would
// hand anyone a trivial way to pin the CPU.
type LoginToken struct {
	UserID     uint64     `json:"user_id"`
	SecretHash string     `json:"secret_hash"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
}

func ( token *LoginToken ) Usable() ( result bool ) {
	result = token.UsedAt == nil && time.Now().UTC().After( token.ExpiresAt ) == false
	return
}

// IssueLoginToken returns the raw credential exactly once. It is never stored
// and cannot be recovered -- if it is lost, mint another one.
//
// An account has at most one pending link. Issuing a new one deletes any
// unused link the account already had, in the same transaction, so "send
// them a new link" also kills the old one -- which is what you want when the
// old one went to the wrong place, and costs nothing when it simply expired.
func IssueLoginToken( store *db.Store , user_id uint64 , ttl time.Duration ) ( credential string , err error ) {
	credential , err = issueToken( store , user_id , ttl , true )
	return
}

// IssueInstallToken is a login link that leaves the account's other pending
// links alone. Each Home Screen install gets its own, and someone adding two
// apps in a row must not find the first link dead when they open it.
// Revoking credentials and disabling the account still clear it, and it is
// redeemed exactly as a login link is, two-factor included.
func IssueInstallToken( store *db.Store , user_id uint64 , ttl time.Duration ) ( credential string , err error ) {
	credential , err = issueToken( store , user_id , ttl , false )
	return
}

func issueToken( store *db.Store , user_id uint64 , ttl time.Duration , replace_pending bool ) ( credential string , err error ) {
	token_id := encryption.GenerateURLToken( 12 )
	secret := encryption.GenerateURLToken( 24 )
	// bcrypt outside the transaction, so the single writer is not held for it.
	secret_hash , err := encryption.BcryptHash( secret )
	if err != nil { return }

	now := time.Now().UTC()
	token := &LoginToken{
		UserID:     user_id,
		SecretHash: secret_hash,
		CreatedAt:  now,
		ExpiresAt:  now.Add( ttl ),
	}
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		if tx_err = tx.Get( db.BucketUsers , encryption.Uint64ToBytes( user_id ) , &User{} ); tx_err != nil { return }
		if replace_pending {
			if _ , tx_err = deletePendingLoginTokens( tx , user_id ); tx_err != nil { return }
		}
		tx_err = tx.Put( db.BucketLoginTokens , []byte( token_id ) , token )
		return
	} )
	if err != nil { return }
	credential = token_id + "." + secret
	return
}

// RedeemLoginToken consumes a login link and creates the session it grants,
// returning the session credential for the cookie.
//
// The bcrypt comparison runs before the write transaction, so bolt's single
// writer is never held for the deliberately slow part -- otherwise anyone
// holding a valid token id could stall every writer by submitting wrong
// secrets. Everything that decides the outcome is then re-checked inside one
// transaction: the token is still unused and unexpired, it is the same token
// that was compared, and the account exists and is enabled. Marking the token
// used and storing the session happen there too. So two requests racing the
// same link cannot both get a session, and a link redeemed while the account
// is being disabled either lands first (and SetUserDisabled deletes its
// session) or lands second (and is refused).
func RedeemLoginToken( store *db.Store , credential string , rules SignInRules ) ( signed *SignIn , err error ) {
	token_id , secret , ok := splitCredential( credential )
	if ok == false {
		err = ErrLoginTokenInvalid
		return
	}

	found := &LoginToken{}
	if store.Get( db.BucketLoginTokens , []byte( token_id ) , found ) != nil || found.Usable() == false {
		err = ErrLoginTokenInvalid
		return
	}
	if encryption.BcryptCompare( found.SecretHash , secret ) == false {
		err = ErrLoginTokenInvalid
		return
	}

	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		current := &LoginToken{}
		if tx.Get( db.BucketLoginTokens , []byte( token_id ) , current ) != nil ||
			current.Usable() == false ||
			encryption.ConstantTimeEqual( current.SecretHash , found.SecretHash ) == false {
			tx_err = ErrLoginTokenInvalid
			return
		}
		owner := &User{}
		if tx.Get( db.BucketUsers , encryption.Uint64ToBytes( current.UserID ) , owner ) != nil || owner.Disabled() {
			tx_err = ErrLoginTokenInvalid
			return
		}

		now := time.Now().UTC()
		current.UsedAt = &now
		if tx_err = tx.Put( db.BucketLoginTokens , []byte( token_id ) , current ); tx_err != nil { return }

		signed , tx_err = startSignInTx( tx , owner , rules )
		return
	} )
	if err != nil { signed = nil }
	return
}

// deletePendingLoginTokens removes every unused link an account holds,
// inside the caller's transaction. Used ones are left for the `purge` job, so
// a second click on a spent link still fails as "already used".
func deletePendingLoginTokens( tx *db.Tx , user_id uint64 ) ( removed int , err error ) {
	removed , err = tx.DeleteWhere( db.BucketLoginTokens ,
		func() any { return &LoginToken{} } ,
		func( key []byte , item any ) bool {
			token := item.( *LoginToken )
			return token.UserID == user_id && token.UsedAt == nil
		} )
	return
}

// deleteLoginTokensForUser removes every link an account holds, used ones
// included, inside the caller's transaction. Only DeleteUser wants this: once
// the account is gone, "already used" has nothing left to refer to.
func deleteLoginTokensForUser( tx *db.Tx , user_id uint64 ) ( removed int , err error ) {
	removed , err = tx.DeleteWhere( db.BucketLoginTokens ,
		func() any { return &LoginToken{} } ,
		func( key []byte , item any ) bool {
			return item.( *LoginToken ).UserID == user_id
		} )
	return
}

// PurgeExpiredLoginTokens drops spent and stale rows. Used tokens are kept
// until they expire rather than deleted on redemption, so that a second click
// on a link fails as "already used" instead of looking like it never existed.
// One transaction, for the same reason as PurgeExpiredSessions.
func PurgeExpiredLoginTokens( store *db.Store ) ( removed int , err error ) {
	now := time.Now().UTC()
	removed , err = store.DeleteWhere( db.BucketLoginTokens ,
		func() any { return &LoginToken{} } ,
		func( key []byte , item any ) bool {
			return now.After( item.( *LoginToken ).ExpiresAt )
		} )
	return
}
