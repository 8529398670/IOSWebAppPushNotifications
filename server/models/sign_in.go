package models

import (
	errors "errors"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// The one place a proven first factor turns into a signed-in browser.
//
// A login link, an invite link and a password all end here, inside the
// transaction that spent them. An account with two-factor on gets a
// short-lived challenge instead of a session, so a way of signing in cannot
// forget to ask for the code: there is no other path to a session for an
// existing account. (Joining through an invite link makes a new account,
// which has no 2FA yet.)
//
// A challenge is shaped "<id>.<secret>" like every other credential, and it
// is sha256'd for the same reason: the secret is random, there is nothing to
// brute force. It lives for ChallengeTTL and is used once.

const ChallengeTTL = 5 * time.Minute

// ErrChallengeInvalid covers expired, used, never existed, and an account
// that can no longer sign in.
var ErrChallengeInvalid = errors.New( "that sign-in has expired, start again" )

// SignInRules is what decides how a sign-in ends, from the running
// configuration.
type SignInRules struct {
	SessionTTL time.Duration
	TwoFactor  bool
}

// SignIn is a first factor that was accepted. Exactly one of
// SessionCredential and Challenge is set.
type SignIn struct {
	UserID            uint64
	SessionCredential string
	Challenge         string
}

type signInChallenge struct {
	UserID     uint64    `json:"user_id"`
	SecretHash string    `json:"secret_hash"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func ( challenge *signInChallenge ) live( secret string ) ( result bool ) {
	result = time.Now().UTC().After( challenge.ExpiresAt ) == false &&
		encryption.ConstantTimeEqual( challenge.SecretHash , encryption.Sha256Hex( secret ) )
	return
}

// startSignInTx stores a session, or a challenge if this account has to give
// a code.
func startSignInTx( tx *db.Tx , user *User , rules SignInRules ) ( signed *SignIn , err error ) {
	if rules.TwoFactor && user.TwoFactorOn() {
		challenge_id := encryption.GenerateURLToken( 12 )
		secret := encryption.GenerateURLToken( 24 )
		challenge := &signInChallenge{
			UserID:     user.ID,
			SecretHash: encryption.Sha256Hex( secret ),
			ExpiresAt:  time.Now().UTC().Add( ChallengeTTL ),
		}
		if err = tx.Put( db.BucketSignInChallenges , []byte( challenge_id ) , challenge ); err != nil { return }
		signed = &SignIn{ UserID: user.ID , Challenge: challenge_id + "." + secret }
		return
	}
	session_id , credential , session := newSession( user.ID , rules.SessionTTL )
	if err = tx.Put( db.BucketSessions , []byte( session_id ) , session ); err != nil { return }
	signed = &SignIn{ UserID: user.ID , SessionCredential: credential }
	return
}

// ChallengeUserID says whose challenge this is, or ok false for anything that
// is not a live one. The route needs to know before it checks a code, to
// count the guess.
func ChallengeUserID( store *db.Store , credential string ) ( user_id uint64 , ok bool ) {
	challenge_id , secret , split_ok := splitCredential( credential )
	if split_ok == false { return }
	challenge := &signInChallenge{}
	if store.Get( db.BucketSignInChallenges , []byte( challenge_id ) , challenge ) != nil { return }
	if challenge.live( secret ) == false { return }
	user_id , ok = challenge.UserID , true
	return
}

// FinishChallenge spends a challenge and a code on a session, in one
// transaction, so two requests with the same code cannot both sign in, and an
// account disabled meanwhile is refused. Returns ErrChallengeInvalid or
// ErrWrongCode; a wrong code leaves the challenge alive for another try.
func FinishChallenge( store *db.Store , credential string , code string , session_ttl time.Duration , secret_key string ) ( signed *SignIn , method string , err error ) {
	challenge_id , secret , ok := splitCredential( credential )
	if ok == false {
		err = ErrChallengeInvalid
		return
	}
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		challenge := &signInChallenge{}
		if tx.Get( db.BucketSignInChallenges , []byte( challenge_id ) , challenge ) != nil || challenge.live( secret ) == false {
			tx_err = ErrChallengeInvalid
			return
		}
		key := encryption.Uint64ToBytes( challenge.UserID )
		user := &User{}
		if tx.Get( db.BucketUsers , key , user ) != nil || user.Disabled() || user.TwoFactorOn() == false {
			tx_err = ErrChallengeInvalid
			return
		}
		if method , tx_err = checkCode( user , code , secret_key ); tx_err != nil { return }
		if tx_err = tx.Put( db.BucketUsers , key , user ); tx_err != nil { return }
		if tx_err = tx.Delete( db.BucketSignInChallenges , []byte( challenge_id ) ); tx_err != nil { return }
		session_id , session_credential , session := newSession( user.ID , session_ttl )
		if tx_err = tx.Put( db.BucketSessions , []byte( session_id ) , session ); tx_err != nil { return }
		signed = &SignIn{ UserID: user.ID , SessionCredential: session_credential }
		return
	} )
	if err != nil { signed , method = nil , "" }
	return
}

// deleteChallengesForUser removes every challenge an account holds, inside the
// caller's transaction: a challenge is a sign-in in progress, so anything that
// ends an account's sign-ins ends these too.
func deleteChallengesForUser( tx *db.Tx , user_id uint64 ) ( err error ) {
	_ , err = tx.DeleteWhere( db.BucketSignInChallenges ,
		func() any { return &signInChallenge{} } ,
		func( key []byte , item any ) bool {
			return item.( *signInChallenge ).UserID == user_id
		} )
	return
}

func PurgeExpiredChallenges( store *db.Store ) ( removed int , err error ) {
	now := time.Now().UTC()
	removed , err = store.DeleteWhere( db.BucketSignInChallenges ,
		func() any { return &signInChallenge{} } ,
		func( key []byte , item any ) bool {
			return now.After( item.( *signInChallenge ).ExpiresAt )
		} )
	return
}
