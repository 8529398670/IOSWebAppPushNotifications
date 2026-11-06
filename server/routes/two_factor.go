package routes

import (
	errors "errors"

	fiber "github.com/gofiber/fiber/v3"

	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

// Two-factor sign-in, from a person's point of view: finishing a sign-in with
// a code, and turning it on and off on their account (models/two_factor.go,
// models/sign_in.go).
//
// Setting it up needs a browser session, like every route that touches how an
// account signs in: a key that could change this could lock its owner out, or
// remove what protects them.

type finishSignInRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

type codeRequest struct {
	Code      string `json:"code"`
	CSRFToken string `json:"csrf_token"`
}

// RequireTwoFactor makes setting up 2FA answer 404 while auth.two_factor is
// off. Finishing a sign-in is not behind this: one already under way may as
// well end.
func ( handlers *Handlers ) RequireTwoFactor( c fiber.Ctx ) ( err error ) {
	if handlers.cfg().TwoFactorEnabled == false {
		err = notFound( c , "not found" )
		return
	}
	err = c.Next()
	return
}

func tooMany( c fiber.Ctx , code string ) ( err error ) {
	err = c.Status( fiber.StatusTooManyRequests ).JSON( fiber.Map{ "error": code } )
	return
}

// FinishSignIn is the second half of a sign-in. No CSRF token, for the same
// reason as /api/login: there is no session yet to hold one, and the JSON body
// rule guards it the same way.
func ( handlers *Handlers ) FinishSignIn( c fiber.Ctx ) ( err error ) {
	if sameOriginJSON( c ) == false {
		err = forbidden( c , "login must be submitted from this site's own login page" )
		return
	}
	var body finishSignInRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	user_id , ok := models.ChallengeUserID( handlers.Store , body.Challenge )
	if ok == false {
		err = badRequest( c , "challenge_invalid" )
		return
	}
	if handlers.Codes.Locked( user_id ) {
		err = tooMany( c , "two_factor_locked" )
		return
	}

	cfg := handlers.cfg()
	signed , method , finish_err := models.FinishChallenge( handlers.Store , body.Challenge , body.Code , cfg.SessionTTL , cfg.SecretKey )
	switch {
	case errors.Is( finish_err , models.ErrChallengeInvalid ):
		err = badRequest( c , "challenge_invalid" )
		return
	case errors.Is( finish_err , models.ErrWrongCode ):
		handlers.Codes.Record( user_id , false )
		handlers.auditAs( c , handlers.logUser( user_id , "anon" ) , logs.KindAuth , logs.LevelWarn , "wrong two-factor code" , nil )
		err = forbidden( c , "two_factor_wrong" )
		return
	case finish_err != nil:
		err = serverError( c , finish_err )
		return
	}
	handlers.Codes.Record( user_id , true )
	message := "signed in with a two-factor code"
	if method == models.CodeMethodRecovery { message = "signed in with a recovery code" }
	handlers.auditAs( c , handlers.logUser( user_id , security.MethodSession ) , logs.KindAuth , logs.LevelInfo , message , nil )
	err = handlers.signInResponse( c , signed , fiber.Map{ "ok": true } , fiber.StatusOK )
	return
}

// StartTwoFactor makes a new secret for the person's authenticator app. The
// page builds the QR code from it, so nothing about it is stored as anything
// but cipher text and it is shown only here.
func ( handlers *Handlers ) StartTwoFactor( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	secret , start_err := models.StartTwoFactorSetup( handlers.Store , security.UserFrom( c ).ID , handlers.cfg().SecretKey )
	if errors.Is( start_err , models.ErrTwoFactorOn ) {
		err = conflict( c , "two_factor_on" , nil )
		return
	}
	if start_err != nil {
		err = serverError( c , start_err )
		return
	}
	err = c.JSON( fiber.Map{ "secret": secret } )
	return
}

// ConfirmTwoFactor takes the code that proves the app has the secret, and
// answers with the recovery codes, which are never shown again.
func ( handlers *Handlers ) ConfirmTwoFactor( c fiber.Ctx ) ( err error ) {
	var body codeRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	user_id := security.UserFrom( c ).ID
	if handlers.Codes.Locked( user_id ) {
		err = tooMany( c , "two_factor_locked" )
		return
	}
	codes , confirm_err := models.ConfirmTwoFactorSetup( handlers.Store , user_id , body.Code , handlers.cfg().SecretKey )
	switch {
	case errors.Is( confirm_err , models.ErrTwoFactorOn ):
		err = conflict( c , "two_factor_on" , nil )
		return
	case errors.Is( confirm_err , models.ErrWrongCode ):
		handlers.Codes.Record( user_id , false )
		err = forbidden( c , "two_factor_wrong" )
		return
	case confirm_err != nil:
		err = serverError( c , confirm_err )
		return
	}
	handlers.Codes.Record( user_id , true )
	handlers.audit( c , logs.KindAuth , "two-factor sign-in turned on" , nil )
	err = c.JSON( fiber.Map{ "recovery_codes": codes } )
	return
}

func ( handlers *Handlers ) DisableTwoFactor( c fiber.Ctx ) ( err error ) {
	var body codeRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	user_id := security.UserFrom( c ).ID
	if handlers.Codes.Locked( user_id ) {
		err = tooMany( c , "two_factor_locked" )
		return
	}
	disable_err := models.DisableTwoFactor( handlers.Store , user_id , body.Code , handlers.cfg().SecretKey )
	switch {
	case errors.Is( disable_err , models.ErrTwoFactorOff ):
		err = conflict( c , "two_factor_off" , nil )
		return
	case errors.Is( disable_err , models.ErrWrongCode ):
		handlers.Codes.Record( user_id , false )
		err = forbidden( c , "two_factor_wrong" )
		return
	case disable_err != nil:
		err = serverError( c , disable_err )
		return
	}
	handlers.Codes.Record( user_id , true )
	handlers.audit( c , logs.KindAuth , "two-factor sign-in turned off" , nil )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}
