package routes

import (
	errors "errors"

	fiber "github.com/gofiber/fiber/v3"

	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

// Joining through an invite link (see models/invite_link.go; managing links
// is invite_links.go). Everything here is public -- holding the link is the
// permission -- so every POST is held to the same rule as /api/login: a JSON
// body from one of this site's own pages (sameOriginJSON). The credential
// travels in the body, never a query string, and the page that carries it in
// its path is served with no-referrer.
//
// A bad, expired, switched-off, or orphaned link always answers 404
// invite_link_invalid, whichever of those it was.

type joinRequest struct {
	Credential  string `json:"credential"`
	DisplayName string `json:"display_name"`
	UserID      uint64 `json:"user_id"`
	Pin         string `json:"pin"`
}

// ShowJoinPage answers a visit to an invite link with the ordinary app page,
// which sees the /join/ path and asks for a name. Nothing happens on the GET,
// so a chat app's link preview cannot use up a place.
func ( handlers *Handlers ) ShowJoinPage( c fiber.Ctx ) ( err error ) {
	c.Set( fiber.HeaderReferrerPolicy , "no-referrer" )
	// A person with an old link gets the styled page, not RequireInviteLinks's
	// JSON. The referrer rule above still applies: the path holds the secret.
	if handlers.inviteLinksOn() == false {
		err = handlers.Static.NotFound( c )
		return
	}
	err = handlers.Static.ServeIndex( c )
	return
}

// joinLink checks the request and decodes the body, then loads the link.
// link is nil whenever a response has already been written.
func ( handlers *Handlers ) joinLink( c fiber.Ctx , body *joinRequest ) ( link *models.InviteLink , err error ) {
	if sameOriginJSON( c ) == false {
		err = forbidden( c , "invite links must be used from this site's own page" )
		return
	}
	if c.Bind().JSON( body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	link , load_err := models.LoadInviteLink( handlers.Store , body.Credential )
	if load_err != nil {
		link = nil
		err = notFound( c , "invite_link_invalid" )
	}
	return
}

func ( handlers *Handlers ) JoinInfo( c fiber.Ctx ) ( err error ) {
	var body joinRequest
	link , err := handlers.joinLink( c , &body )
	if link == nil { return }
	err = c.JSON( fiber.Map{ "label": link.Label , "remaining": link.Remaining() } )
	return
}

// JoinMatch is the "did you mean...?": the accounts from this link whose
// names are close to what was typed. The page always shows this step before
// creating anyone, even with no matches, because a typo would otherwise use
// up a place.
func ( handlers *Handlers ) JoinMatch( c fiber.Ctx ) ( err error ) {
	var body joinRequest
	link , err := handlers.joinLink( c , &body )
	if link == nil { return }
	if models.ValidDisplayName( body.DisplayName ) == false {
		err = badRequest( c , "display name must be 1-80 characters" )
		return
	}
	matches , match_err := models.InviteMatches( handlers.Store , link , body.DisplayName )
	if match_err != nil {
		err = serverError( c , match_err )
		return
	}
	rows := []fiber.Map{}
	for _ , user := range matches {
		rows = append( rows , fiber.Map{ "id": user.ID , "display_name": user.DisplayName , "has_pin": user.HasPin() } )
	}
	err = c.JSON( fiber.Map{ "matches": rows , "can_create": link.Remaining() > 0 } )
	return
}

// JoinClaim signs in as an account this link created -- the same person on
// another device -- asking for the PIN if that person set one.
//
// An account with a password and no PIN is refused: anyone holding the link
// can pick any name on it, and that must not walk around the password. The
// person signs in with it instead. An account with two-factor on still has to
// give its code after this, PIN or not.
func ( handlers *Handlers ) JoinClaim( c fiber.Ctx ) ( err error ) {
	var body joinRequest
	link , err := handlers.joinLink( c , &body )
	if link == nil { return }
	user , account_err := models.InviteAccount( handlers.Store , link , body.UserID )
	if account_err != nil {
		err = notFound( c , "no_such_account" )
		return
	}
	if user.HasPin() {
		if handlers.Pins.Locked( user.ID ) {
			err = c.Status( fiber.StatusTooManyRequests ).JSON( fiber.Map{ "error": "pin_locked" } )
			return
		}
		ok := user.CheckPin( body.Pin )
		handlers.Pins.Record( user.ID , ok )
		if ok == false {
			handlers.auditAs( c , handlers.logUser( user.ID , "anon" ) , logs.KindAuth , logs.LevelWarn , "wrong pin on an invite link" , fiber.Map{ "link_id": link.ID } )
			code := "pin_wrong"
			if body.Pin == "" { code = "pin_needed" }
			err = forbidden( c , code )
			return
		}
	} else if user.PasswordUsable( handlers.cfg().PasswordsEnabled ) {
		err = forbidden( c , "use_password" )
		return
	}

	signed , _ , claim_err := models.ClaimInviteAccount( handlers.Store , body.Credential , user.ID , handlers.signInRules() )
	switch {
	case errors.Is( claim_err , models.ErrInviteLinkInvalid ):
		err = notFound( c , "invite_link_invalid" )
		return
	case errors.Is( claim_err , models.ErrNotInviteAccount ):
		err = notFound( c , "no_such_account" )
		return
	case claim_err != nil:
		err = serverError( c , claim_err )
		return
	}
	message := "signed back in through an invite link"
	if signed.Challenge != "" { message = "invite link accepted, waiting for a code" }
	handlers.auditAs( c , handlers.logUser( user.ID , security.MethodSession ) , logs.KindAuth , logs.LevelInfo , message , fiber.Map{ "link_id": link.ID } )
	err = handlers.signInResponse( c , signed , fiber.Map{ "ok": true , "display_name": user.DisplayName } , fiber.StatusOK )
	return
}

// JoinCreate makes a new account through the link, if it has places left,
// and signs it in.
func ( handlers *Handlers ) JoinCreate( c fiber.Ctx ) ( err error ) {
	var body joinRequest
	link , err := handlers.joinLink( c , &body )
	if link == nil { return }
	if models.ValidDisplayName( body.DisplayName ) == false {
		err = badRequest( c , "display name must be 1-80 characters" )
		return
	}

	session_credential , user , join_err := models.JoinInviteLink( handlers.Store , body.Credential , body.DisplayName , handlers.cfg().SessionTTL )
	switch {
	case errors.Is( join_err , models.ErrInviteLinkInvalid ):
		err = notFound( c , "invite_link_invalid" )
		return
	case errors.Is( join_err , models.ErrInviteLinkFull ):
		err = c.Status( fiber.StatusConflict ).JSON( fiber.Map{ "error": "invite_link_full" } )
		return
	case join_err != nil:
		err = serverError( c , join_err )
		return
	}
	handlers.auditAs( c , handlers.logUser( user.ID , security.MethodSession ) , logs.KindAuth , logs.LevelInfo , "joined through an invite link" , fiber.Map{ "link_id": link.ID } )
	handlers.Webhooks.Emit( models.EventUserCreated , map[string]any{ "user_id": user.ID , "display_name": user.DisplayName , "role": user.Role , "invite_link_id": link.ID } )
	signed := &models.SignIn{ UserID: user.ID , SessionCredential: session_credential }
	err = handlers.signInResponse( c , signed , fiber.Map{ "ok": true , "display_name": user.DisplayName } , fiber.StatusCreated )
	return
}
