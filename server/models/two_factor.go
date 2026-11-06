package models

import (
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	strings "strings"
	time "time"
	unicode "unicode"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// Two-factor sign-in: a code from an authenticator app (TOTP), with recovery
// codes for a lost phone. It is optional per person, and auth.two_factor
// decides whether it is offered at all.
//
// The secret has to be readable to check a code, so unlike every other
// credential here it cannot be hashed. It is encrypted on its own with the
// secret key, on top of whatever the record gets, because
// server.encrypt_at_rest can be off.
//
// Asking for the code at sign-in is sign_in.go.

const RecoveryCodeCount = 10

const (
	CodeMethodTOTP     = "totp"
	CodeMethodRecovery = "recovery"
)

var (
	// ErrWrongCode: the code was not right, or was empty, or was already used.
	ErrWrongCode = errors.New( "that code is not right" )
	// ErrTwoFactorOn: setup was started on an account that already has 2FA.
	ErrTwoFactorOn = errors.New( "two-factor sign-in is already on" )
	// ErrTwoFactorOff: something that needs 2FA on an account without it.
	ErrTwoFactorOff = errors.New( "two-factor sign-in is not on" )
)

func ( user *User ) TwoFactorOn() ( result bool ) {
	result = user.TOTPSecret != ""
	return
}

func normalizeRecoveryCode( code string ) ( result string ) {
	var builder strings.Builder
	for _ , character := range strings.ToUpper( code ) {
		if unicode.IsLetter( character ) || unicode.IsDigit( character ) {
			builder.WriteRune( character )
		}
	}
	result = builder.String()
	return
}

func cleanCode( code string ) ( result string ) {
	result = strings.ReplaceAll( strings.TrimSpace( code ) , " " , "" )
	return
}

func matchesTOTP( encrypted_secret string , code string , after_step uint64 , secret_key string ) ( step uint64 , ok bool , err error ) {
	secret , err := encryption.ChaChaDecryptBase64String( secret_key , encrypted_secret )
	if err != nil { return }
	step , ok , err = encryption.TOTPMatch( secret , code , time.Now().Unix() , after_step )
	return
}

func isDigits( code string ) ( result bool ) {
	for _ , character := range code {
		if character < '0' || character > '9' { return }
	}
	result = code != ""
	return
}

// checkCode checks a code against an account and uses it up: a TOTP step can
// not be used twice, and a recovery code is gone once used. Returns
// CodeMethodTOTP or CodeMethodRecovery, or ErrWrongCode.
//
// It changes the user it is given, so the caller decides when that is stored
// -- in the transaction that does whatever the code was for.
func checkCode( user *User , code string , secret_key string ) ( method string , err error ) {
	code = cleanCode( code )
	if code == "" {
		err = ErrWrongCode
		return
	}

	if len( code ) == encryption.TOTPDigits && isDigits( code ) {
		step , ok , match_err := matchesTOTP( user.TOTPSecret , code , user.TOTPLastStep , secret_key )
		if match_err != nil {
			err = match_err
			return
		}
		if ok == false {
			err = ErrWrongCode
			return
		}
		user.TOTPLastStep = step
		method = CodeMethodTOTP
		return
	}

	wanted := encryption.Sha256Hex( normalizeRecoveryCode( code ) )
	kept := []string{}
	found := false
	for _ , stored := range user.RecoveryHashes {
		if encryption.ConstantTimeEqual( stored , wanted ) {
			found = true
			continue
		}
		kept = append( kept , stored )
	}
	if found == false {
		err = ErrWrongCode
		return
	}
	user.RecoveryHashes = kept
	method = CodeMethodRecovery
	return
}

// StartTwoFactorSetup makes a secret for the person to add to their app, and
// holds it until they prove it worked. Starting again replaces it.
func StartTwoFactorSetup( store *db.Store , user_id uint64 , secret_key string ) ( secret string , err error ) {
	new_secret := encryption.TOTPNewSecret()
	encrypted , err := encryption.ChaChaEncryptString( secret_key , new_secret )
	if err != nil { return }
	err = store.UpdateValue( db.BucketUsers , encryption.Uint64ToBytes( user_id ) ,
		func() any { return &User{} } ,
		func( item any ) ( mutate_err error ) {
			user := item.( *User )
			if user.TwoFactorOn() {
				mutate_err = ErrTwoFactorOn
				return
			}
			user.TOTPPending = encrypted
			return
		} )
	if err == nil { secret = new_secret }
	return
}

// ConfirmTwoFactorSetup turns 2FA on, once a code proves the app has the
// secret. It returns the recovery codes -- the only time they exist in
// readable form.
func ConfirmTwoFactorSetup( store *db.Store , user_id uint64 , code string , secret_key string ) ( codes []string , err error ) {
	new_codes := make( []string , RecoveryCodeCount )
	hashes := make( []string , RecoveryCodeCount )
	for index := range new_codes {
		new_codes[ index ] = encryption.RecoveryCode()
		hashes[ index ] = encryption.Sha256Hex( normalizeRecoveryCode( new_codes[ index ] ) )
	}
	err = store.UpdateValue( db.BucketUsers , encryption.Uint64ToBytes( user_id ) ,
		func() any { return &User{} } ,
		func( item any ) ( mutate_err error ) {
			user := item.( *User )
			if user.TwoFactorOn() {
				mutate_err = ErrTwoFactorOn
				return
			}
			if user.TOTPPending == "" {
				mutate_err = ErrWrongCode
				return
			}
			step , ok , match_err := matchesTOTP( user.TOTPPending , cleanCode( code ) , 0 , secret_key )
			if match_err != nil {
				mutate_err = match_err
				return
			}
			if ok == false {
				mutate_err = ErrWrongCode
				return
			}
			user.TOTPSecret = user.TOTPPending
			user.TOTPPending = ""
			user.TOTPLastStep = step
			user.RecoveryHashes = hashes
			return
		} )
	if err == nil { codes = new_codes }
	return
}

// clearTwoFactor takes every trace of 2FA off a user.
func clearTwoFactor( user *User ) {
	user.TOTPSecret = ""
	user.TOTPPending = ""
	user.TOTPLastStep = 0
	user.RecoveryHashes = nil
}

// DisableTwoFactor turns 2FA off, which takes a valid code: a stolen session
// must not be able to remove it.
func DisableTwoFactor( store *db.Store , user_id uint64 , code string , secret_key string ) ( err error ) {
	err = store.UpdateValue( db.BucketUsers , encryption.Uint64ToBytes( user_id ) ,
		func() any { return &User{} } ,
		func( item any ) ( mutate_err error ) {
			user := item.( *User )
			if user.TwoFactorOn() == false {
				mutate_err = ErrTwoFactorOff
				return
			}
			if _ , mutate_err = checkCode( user , code , secret_key ); mutate_err != nil { return }
			clearTwoFactor( user )
			return
		} )
	return
}

// rekeyFields is every field sealed on its own with the secret key, by bucket.
var rekeyFields = map[string][]string{
	db.BucketUsers:    { "totp_secret" , "totp_pending" },
	db.BucketWebhooks: { "secret" },
	db.BucketFiles:    { "key" },
	db.BucketPushKeys: { "private_key" },
}

// RekeyRecord is what moving the database to a new key has to do beyond the
// record's own encryption: a TOTP secret is encrypted again on its own (see
// the top of this file), so it has to be opened with the old key and sealed
// with the new one. Anything else that encrypts a field with the secret key
// belongs here too, or that field is lost at the next rotation.
//
// The record is edited as raw JSON so that fields this code never touches
// come back exactly as they went in.
func RekeyRecord( old_key string , new_key string ) ( rewrite func( bucket string , plain []byte ) ( []byte , error ) ) {
	rewrite = func( bucket string , plain []byte ) ( result []byte , err error ) {
		result = plain
		fields := rekeyFields[ bucket ]
		if len( fields ) == 0 { return }
		record := map[string]json.RawMessage{}
		if err = json.Unmarshal( plain , &record ); err != nil { return }
		changed := false
		for _ , field := range fields {
			raw , present := record[ field ]
			if present == false { continue }
			var sealed string
			if err = json.Unmarshal( raw , &sealed ); err != nil { return }
			if sealed == "" { continue }
			secret , open_err := encryption.ChaChaDecryptBase64String( old_key , sealed )
			if open_err != nil {
				err = fmt.Errorf( "%s: %w" , field , open_err )
				return
			}
			if sealed , err = encryption.ChaChaEncryptString( new_key , secret ); err != nil { return }
			if record[ field ] , err = json.Marshal( sealed ); err != nil { return }
			changed = true
		}
		if changed {
			result , err = json.Marshal( record )
		}
		return
	}
	return
}
