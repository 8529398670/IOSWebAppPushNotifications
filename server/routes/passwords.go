package routes

import (
	errors "errors"
	strconv "strconv"

	fiber "github.com/gofiber/fiber/v3"

	db "ipb/server/db"
	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

// Password sign-in (models/password.go). None of this exists while
// auth.passwords is off -- RequirePasswords answers 404 -- except
// /api/login/options, which is how the signed-out page finds out.
//
// Passwords never reach these routes: password_digest is what the browser
// derived from one (static/js/password.js).

// How many wrong passwords one address gets, across every name. Every attempt
// costs a bcrypt, which is what this protects.
const passwordAddressMaxFailures = 30

type passwordLoginRequest struct {
	Username       string `json:"username"`
	PasswordDigest string `json:"password_digest"`
}

type setPasswordRequest struct {
	Username       string `json:"username"`
	PasswordDigest string `json:"password_digest"`
	Code           string `json:"code"`
	CSRFToken      string `json:"csrf_token"`
}

type passwordAccessRequest struct {
	Allowed   *bool  `json:"allowed"`
	CSRFToken string `json:"csrf_token"`
}

// RequirePasswords makes every password route answer 404 while auth.passwords
// is off. Per request, for the same reason as RequireMCP.
func ( handlers *Handlers ) RequirePasswords( c fiber.Ctx ) ( err error ) {
	if handlers.cfg().PasswordsEnabled == false {
		err = notFound( c , "not found" )
		return
	}
	err = c.Next()
	return
}

// GetLoginOptions is what the signed-out page needs to know. Public, and the
// same for everyone: the salt is not a secret, and there is deliberately
// nothing here that depends on a username.
func ( handlers *Handlers ) GetLoginOptions( c fiber.Ctx ) ( err error ) {
	cfg := handlers.cfg()
	payload := fiber.Map{ "passwords": cfg.PasswordsEnabled , "two_factor": cfg.TwoFactorEnabled }
	if cfg.PasswordsEnabled {
		salt , salt_err := models.InstallSalt( handlers.Store )
		if salt_err != nil {
			err = serverError( c , salt_err )
			return
		}
		payload[ "salt" ] = salt
	}
	err = c.JSON( payload )
	return
}

// PasswordLogin signs in with a password. Unknown name, wrong password, a
// blocked or disabled account: all the same answer, after the same bcrypt. No
// CSRF token, for the same reason as /api/login.
func ( handlers *Handlers ) PasswordLogin( c fiber.Ctx ) ( err error ) {
	if sameOriginJSON( c ) == false {
		err = forbidden( c , "login must be submitted from this site's own login page" )
		return
	}
	var body passwordLoginRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}

	name := models.NormalizeUsername( body.Username )
	if len( name ) > 64 { name = name[ :64 ] }
	address := c.IP()
	if handlers.PasswordNames.Locked( name ) || handlers.PasswordAddresses.Locked( address ) {
		err = tooMany( c , "login_locked" )
		return
	}

	var signed *models.SignIn
	user := models.CheckPassword( handlers.Store , name , body.PasswordDigest )
	if user != nil {
		var sign_in_err error
		if signed , sign_in_err = models.StartPasswordSignIn( handlers.Store , user , handlers.signInRules() ); sign_in_err != nil {
			err = serverError( c , sign_in_err )
			return
		}
	}
	if signed == nil {
		handlers.PasswordNames.Record( name , false )
		handlers.PasswordAddresses.Record( address , false )
		handlers.auditAs( c , logs.Anonymous() , logs.KindAuth , logs.LevelWarn , "password refused" , nil )
		err = badRequest( c , "invalid_login" )
		return
	}
	handlers.PasswordNames.Record( name , true )
	message := "signed in with a password"
	if signed.Challenge != "" { message = "password accepted, waiting for a code" }
	handlers.auditAs( c , handlers.logUser( user.ID , security.MethodSession ) , logs.KindAuth , logs.LevelInfo , message , nil )
	err = handlers.signInResponse( c , signed , fiber.Map{ "ok": true } , fiber.StatusOK )
	return
}

// sessionID is the id of the session this request came with, to leave it
// alone when the account's others end.
func ( handlers *Handlers ) sessionID( c fiber.Ctx ) ( session_id string ) {
	credential , err := handlers.Guard.DecryptCookie( c.Cookies( handlers.cfg().CookieName ) )
	if err != nil { return }
	session_id = models.SessionID( credential )
	return
}

// SetPassword sets the account's username and password, or with an empty
// password_digest removes the password. Session only: a key that could set one
// could turn itself into a session.
func ( handlers *Handlers ) SetPassword( c fiber.Ctx ) ( err error ) {
	var body setPasswordRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}

	cfg := handlers.cfg()
	user_id := security.UserFrom( c ).ID
	if handlers.Codes.Locked( user_id ) {
		err = tooMany( c , "two_factor_locked" )
		return
	}
	set_err := models.SetPassword( handlers.Store , user_id , body.Username , body.PasswordDigest , handlers.sessionID( c ) ,
		body.Code , cfg.TwoFactorEnabled , cfg.SecretKey )
	switch {
	case errors.Is( set_err , models.ErrBadUsername ):
		err = badRequest( c , "bad_username" )
		return
	case errors.Is( set_err , models.ErrBadDigest ):
		err = badRequest( c , "bad_digest" )
		return
	case errors.Is( set_err , models.ErrUsernameTaken ):
		err = conflict( c , "username_taken" , nil )
		return
	case errors.Is( set_err , models.ErrPasswordBlocked ):
		err = forbidden( c , "password_blocked" )
		return
	case errors.Is( set_err , models.ErrWrongCode ):
		handlers.Codes.Record( user_id , false )
		err = forbidden( c , "two_factor_wrong" )
		return
	case set_err != nil:
		err = serverError( c , set_err )
		return
	}
	message := "password changed"
	if body.PasswordDigest == "" { message = "password removed" }
	handlers.audit( c , logs.KindAuth , message , nil )
	err = c.JSON( fiber.Map{ "ok": true , "has_password": body.PasswordDigest != "" } )
	return
}

// SetPasswordAccess is the owner's per-account switch (RequireOwner).
// {allowed: false} stops this account's password working and stops it setting
// one.
func ( handlers *Handlers ) SetPasswordAccess( c fiber.Ctx ) ( err error ) {
	var body passwordAccessRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	user_id , parse_err := strconv.ParseUint( c.Params( "user_id" ) , 10 , 64 )
	if parse_err != nil {
		err = badRequest( c , "invalid user id" )
		return
	}
	if body.Allowed == nil {
		err = badRequest( c , "allowed must be true or false" )
		return
	}
	block_err := models.SetPasswordBlocked( handlers.Store , user_id , *body.Allowed == false )
	if errors.Is( block_err , db.ErrNotFound ) {
		err = notFound( c , "no such user" )
		return
	}
	if block_err != nil {
		err = serverError( c , block_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "password access set" , fiber.Map{ "user_id": user_id , "allowed": *body.Allowed } )
	err = c.JSON( fiber.Map{ "ok": true , "password_blocked": *body.Allowed == false } )
	return
}
