package models

import (
	errors "errors"
	regexp "regexp"
	strings "strings"
	sync "sync"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// Password sign-in, which the owner turns on with auth.passwords.
//
// The server never sees a password. static/js/password.js derives a digest
// from it in the browser (PBKDF2, salted with this install's salt and the
// username), and that digest is what travels and what bcrypt hashes here. So:
//
//   - A leaked database cannot be replayed: it holds a bcrypt of the digest.
//   - A compromised server, or a stray log, cannot expose a password someone
//     reuses elsewhere.
//   - The digest still works as a password on the wire. This is no substitute
//     for HTTPS: anyone reading the traffic could replay it, or change the
//     page.
//   - Rules about the password itself (its length) live in the browser,
//     because the server cannot see it. Skipping them only weakens your own
//     account.
//
// The salt comes from a public route and is the same for everyone, because a
// per-user one would need a lookup that says which usernames exist.
//
// A digest is 43 base64url characters, safely under bcrypt's 72-byte limit.

const metaSaltKey = "password_salt"

var (
	usernamePattern = regexp.MustCompile( `^[a-z0-9._-]{3,32}$` )
	digestPattern   = regexp.MustCompile( `^[A-Za-z0-9_-]{43}$` )

	ErrBadUsername     = errors.New( "a username is 3 to 32 letters, digits, dots, dashes or underscores" )
	ErrBadDigest       = errors.New( "that is not a password digest" )
	ErrUsernameTaken   = errors.New( "that username is taken" )
	ErrPasswordBlocked = errors.New( "passwords are blocked for this account" )

	// Compared against when there is no account to compare with, so an
	// unknown name takes as long to refuse as a wrong password. The value is
	// never a match for anything; only the time it takes matters.
	dummyHash     string
	dummyHashOnce sync.Once
)

func NormalizeUsername( value string ) ( result string ) {
	result = strings.ToLower( strings.TrimSpace( value ) )
	return
}

func ( user *User ) HasPassword() ( result bool ) {
	result = user.PasswordHash != ""
	return
}

// PasswordUsable says whether a password can sign this account in right now.
func ( user *User ) PasswordUsable( passwords_enabled bool ) ( result bool ) {
	result = passwords_enabled && user.HasPassword() && user.PasswordBlocked == false
	return
}

// InstallSalt is this install's salt, made the first time it is asked for.
// Not a secret: it only stops one install's digests being useful against
// another's.
func InstallSalt( store *db.Store ) ( salt string , err error ) {
	err = store.Get( db.BucketMeta , []byte( metaSaltKey ) , &salt )
	if err == nil || errors.Is( err , db.ErrNotFound ) == false { return }
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		tx_err = tx.Get( db.BucketMeta , []byte( metaSaltKey ) , &salt )
		if errors.Is( tx_err , db.ErrNotFound ) == false { return }
		salt = encryption.GenerateURLToken( 16 )
		tx_err = tx.Put( db.BucketMeta , []byte( metaSaltKey ) , salt )
		return
	} )
	return
}

func usernameTakenTx( tx *db.Tx , username string , user_id uint64 ) ( taken bool , err error ) {
	err = tx.ForEach( db.BucketUsers ,
		func() any { return &User{} } ,
		func( key []byte , item any ) bool {
			other := item.( *User )
			taken = other.Username == username && other.ID != user_id
			return taken == false
		} )
	return
}

// SetPassword sets the account's username and password, or with an empty
// digest removes the password.
//
// The two go together because the digest is salted with the username: a new
// name is a new digest. The old password is not asked for, because this is
// also how a forgotten one is replaced after signing in with a link, and a
// session can already mint itself a link. 2FA is what protects this, so an
// account that has it must give a code.
//
// Every other session of the account ends, in case the reason for changing a
// password is that someone else has it.
func SetPassword( store *db.Store , user_id uint64 , username string , digest string , keep_session_id string , code string , two_factor_enabled bool , secret_key string ) ( err error ) {
	clearing := digest == ""
	name := NormalizeUsername( username )
	password_hash := ""
	if clearing == false {
		if usernamePattern.MatchString( name ) == false {
			err = ErrBadUsername
			return
		}
		if digestPattern.MatchString( digest ) == false {
			err = ErrBadDigest
			return
		}
		// bcrypt outside the transaction, so the single writer is not held
		// for it.
		if password_hash , err = encryption.BcryptHash( digest ); err != nil { return }
	}

	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		key := encryption.Uint64ToBytes( user_id )
		user := &User{}
		if tx_err = tx.Get( db.BucketUsers , key , user ); tx_err != nil { return }
		if user.PasswordBlocked {
			tx_err = ErrPasswordBlocked
			return
		}
		if two_factor_enabled && user.TwoFactorOn() {
			if _ , tx_err = checkCode( user , code , secret_key ); tx_err != nil { return }
		}
		if clearing == false {
			taken , taken_err := usernameTakenTx( tx , name , user_id )
			if taken_err != nil {
				tx_err = taken_err
				return
			}
			if taken {
				tx_err = ErrUsernameTaken
				return
			}
			user.Username = name
		}
		user.PasswordHash = password_hash
		if tx_err = tx.Put( db.BucketUsers , key , user ); tx_err != nil { return }
		_ , tx_err = tx.DeleteWhere( db.BucketSessions ,
			func() any { return &Session{} } ,
			func( session_key []byte , item any ) bool {
				return item.( *Session ).UserID == user_id && string( session_key ) != keep_session_id
			} )
		return
	} )
	return
}

// SetPasswordBlocked is the owner's per-account switch. The hash stays, so
// unblocking restores the password, and sessions stay signed in: this is
// about how an account signs in, not about ending access.
func SetPasswordBlocked( store *db.Store , user_id uint64 , blocked bool ) ( err error ) {
	err = store.UpdateValue( db.BucketUsers , encryption.Uint64ToBytes( user_id ) ,
		func() any { return &User{} } ,
		func( item any ) ( mutate_err error ) {
			item.( *User ).PasswordBlocked = blocked
			return
		} )
	return
}

// findByUsername is a scan: with every record encrypted there is no index to
// search, and this runs once per sign-in, behind the attempt limits.
func findByUsername( store *db.Store , username string ) ( found *User ) {
	users , err := ListUsers( store )
	if err != nil { return }
	for _ , user := range users {
		if user.Username == username {
			found = user
			return
		}
	}
	return
}

// CheckPassword returns the account these sign in, or nil. Every way of being
// wrong costs one bcrypt comparison, so the time taken says nothing about
// which it was.
func CheckPassword( store *db.Store , username string , digest string ) ( user *User ) {
	name := NormalizeUsername( username )
	good_digest := digestPattern.MatchString( digest )
	var found *User
	if name != "" { found = findByUsername( store , name ) }
	if found == nil || good_digest == false || found.Disabled() || found.PasswordBlocked || found.HasPassword() == false {
		dummyHashOnce.Do( func() {
			dummyHash , _ = encryption.BcryptHash( encryption.GenerateURLToken( 24 ) )
		} )
		if good_digest == false { digest = strings.Repeat( "-" , 43 ) }
		encryption.BcryptCompare( dummyHash , digest )
		return
	}
	if encryption.BcryptCompare( found.PasswordHash , digest ) {
		user = found
	}
	return
}

// StartPasswordSignIn turns a checked password into a sign-in; nil if it no
// longer stands. bcrypt ran outside the single writer, so everything it
// depended on is checked again here: a password changed, an account disabled
// or blocked in between is refused.
func StartPasswordSignIn( store *db.Store , checked *User , rules SignInRules ) ( signed *SignIn , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		current := &User{}
		if tx.Get( db.BucketUsers , encryption.Uint64ToBytes( checked.ID ) , current ) != nil ||
			current.Disabled() || current.PasswordBlocked || current.PasswordHash != checked.PasswordHash {
			return
		}
		signed , tx_err = startSignInTx( tx , current , rules )
		return
	} )
	if err != nil { signed = nil }
	return
}
