package models

import (
	errors "errors"
	regexp "regexp"
	strings "strings"
	unicode "unicode"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// A PIN is what stops anyone holding an invite link from signing in as
// anyone who joined through it. It is asked for only there: login links,
// sessions and API keys never look at it, so it is not a password (password.go
// is, and has nothing to do with it).

var ErrBadPin = errors.New( "a PIN is 4 to 8 digits" )

var pinPattern = regexp.MustCompile( `^[0-9]{4,8}$` )

// SetUserPin sets or (with "") clears the PIN. It is bcrypt-hashed: four
// digits is a small space, so the hash is only half the protection -- the
// claim route also limits attempts per account (AttemptGuard).
func SetUserPin( store *db.Store , user_id uint64 , pin string ) ( err error ) {
	hash := ""
	if pin != "" {
		if pinPattern.MatchString( pin ) == false {
			err = ErrBadPin
			return
		}
		if hash , err = encryption.BcryptHash( pin ); err != nil { return }
	}
	err = store.UpdateValue( db.BucketUsers , encryption.Uint64ToBytes( user_id ) ,
		func() any { return &User{} } ,
		func( item any ) ( mutate_err error ) {
			item.( *User ).PinHash = hash
			return
		} )
	return
}

func ( user *User ) HasPin() ( result bool ) {
	result = user.PinHash != ""
	return
}

// CheckPin is true for an account with no PIN, whatever was typed.
func ( user *User ) CheckPin( pin string ) ( ok bool ) {
	if user.PinHash == "" {
		ok = true
		return
	}
	ok = pin != "" && encryption.BcryptCompare( user.PinHash , pin )
	return
}

// normalizeName folds a name for comparison: case, spacing, and
// punctuation should not make "Anna-Marie" a stranger to "anna marie".
func normalizeName( name string ) ( result string ) {
	var builder strings.Builder
	for _ , character := range strings.ToLower( strings.TrimSpace( name ) ) {
		if unicode.IsLetter( character ) || unicode.IsDigit( character ) {
			builder.WriteRune( character )
		}
	}
	result = builder.String()
	return
}

func editDistance( a string , b string ) ( distance int ) {
	left , right := []rune( a ) , []rune( b )
	previous := make( []int , len( right )+1 )
	for index := range previous {
		previous[ index ] = index
	}
	for i := 1; i <= len( left ); i++ {
		current := make( []int , len( right )+1 )
		current[ 0 ] = i
		for j := 1; j <= len( right ); j++ {
			cost := 1
			if left[ i-1 ] == right[ j-1 ] { cost = 0 }
			current[ j ] = min( previous[ j ]+1 , current[ j-1 ]+1 , previous[ j-1 ]+cost )
		}
		previous = current
	}
	distance = previous[ len( right ) ]
	return
}

// NameCloseness scores how alike two names are: 0 is the same name once
// case and punctuation are ignored, larger is further apart, and -1 means
// "not similar enough to suggest". This is the "did you mean...?" behind
// invite links.
func NameCloseness( typed string , existing string ) ( score int ) {
	a , b := normalizeName( typed ) , normalizeName( existing )
	if a == "" || b == "" {
		score = -1
		return
	}
	if a == b { return }
	if len( []rune( a ) ) >= 3 && ( strings.HasPrefix( b , a ) || strings.HasPrefix( a , b ) ) {
		score = 1
		return
	}
	distance := editDistance( a , b )
	allowed := 1
	if len( []rune( b ) ) >= 6 { allowed = 2 }
	if distance > allowed {
		score = -1
		return
	}
	score = distance + 1
	return
}
