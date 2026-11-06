package routes

import (
	errors "errors"

	fiber "github.com/gofiber/fiber/v3"

	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

type pinRequest struct {
	Pin       string `json:"pin"`
	CSRFToken string `json:"csrf_token"`
}

type renameRequest struct {
	DisplayName string `json:"display_name"`
	// Expect is optional: the name the caller expects to replace. The
	// frontend always sends it, so its undo cannot overwrite a rename made
	// elsewhere.
	Expect    *string `json:"expect"`
	CSRFToken string  `json:"csrf_token"`
}

// GetMe is the frontend's first call on every page load: it answers "who am
// I, what may I do, and what CSRF token do I echo back". Handing the token
// out here means no page needs a hidden form field or a template variable.
//
// "role" is the *effective* role, not the account's: a request made with a
// user-scoped API key belonging to an admin reports "user", because that is
// what it may actually do. account_role reports the account itself, for the
// rare caller that needs to tell the two apart. Reporting the account's role
// as "role" would have a client believe it has permissions the server will
// refuse to act on.
func ( handlers *Handlers ) GetMe( c fiber.Ctx ) ( err error ) {
	payload , row_err := handlers.meRow( security.ActorFrom( c ) )
	if row_err != nil {
		err = serverError( c , row_err )
		return
	}
	err = c.JSON( payload )
	return
}

// meRow is GetMe's answer, shared with the MCP whoami tool so the two cannot
// describe the same caller differently.
func ( handlers *Handlers ) meRow( actor *security.Actor ) ( payload fiber.Map , err error ) {
	user := actor.User

	// is_owner tells the UI which account-management buttons to offer; the
	// server checks ownership again on every request that depends on it.
	owner_id , err := models.OwnerID( handlers.Store )
	if err != nil { return }

	payload = fiber.Map{
		"authenticated":    true,
		"id":               user.ID,
		"display_name":     user.DisplayName,
		"role":             actor.Role,
		"account_role":     user.Role,
		"is_owner":         user.ID == owner_id,
		"maintenance":      handlers.cfg().MaintenanceMode(),
		"version":          handlers.Version,
		"announcement":     handlers.cfg().Announcement,
		"has_pin":          user.HasPin(),
		"username":           user.Username,
		"has_password":       user.HasPassword(),
		"password_blocked":   user.PasswordBlocked,
		"two_factor":         user.TwoFactorOn(),
		"passwords_enabled":  handlers.cfg().PasswordsEnabled,
		"two_factor_enabled": handlers.cfg().TwoFactorEnabled,
		"auth":             actor.Method(),
		"api_keys_enabled": handlers.cfg().APIKeysEnabled,
		"files_enabled": handlers.cfg().Files.Enabled,
		"invite_links_enabled": handlers.inviteLinksOn(),
		"webhooks_enabled": handlers.cfg().Webhooks.Enabled,
		// Whether track.js sends anything, and whether it sends clicks.
		"logs_enabled":   handlers.Logs.Enabled(),
		"logs_ui_clicks": handlers.Logs.Enabled() && handlers.cfg().Logs.UIClicks,
	}
	// Only a session has a CSRF token. A key-authenticated request has no
	// ambient credential to protect, so there is nothing to hand back -- see
	// Guard.CheckCSRF.
	if actor.Session != nil {
		payload[ "csrf_token" ] = actor.Session.CSRFToken
	}
	if actor.APIKey != nil {
		payload[ "api_key_id" ] = actor.APIKey.ID
		payload[ "api_key_name" ] = actor.APIKey.Name
	}
	return
}

func ( handlers *Handlers ) RenameAccount( c fiber.Ctx ) ( err error ) {
	var body renameRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if models.ValidDisplayName( body.DisplayName ) == false {
		err = badRequest( c , "display name must be 1-80 characters" )
		return
	}

	user := security.UserFrom( c )
	rename_err := models.RenameUser( handlers.Store , user.ID , body.DisplayName , body.Expect )
	var refusal *models.RenameConflictError
	if errors.As( rename_err , &refusal ) {
		err = conflict( c , refusal.Error() , fiber.Map{ "display_name": refusal.Current } )
		return
	}
	if rename_err != nil {
		err = serverError( c , rename_err )
		return
	}
	handlers.audit( c , logs.KindAuth , "renamed own account" , fiber.Map{ "name": body.DisplayName } )
	err = c.JSON( fiber.Map{ "ok": true , "display_name": body.DisplayName } )
	return
}

// SetPin sets, or with an empty pin clears, the PIN asked for when this
// account signs back in through an invite link (see models/pin.go).
func ( handlers *Handlers ) SetPin( c fiber.Ctx ) ( err error ) {
	var body pinRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	set_err := models.SetUserPin( handlers.Store , security.UserFrom( c ).ID , body.Pin )
	if errors.Is( set_err , models.ErrBadPin ) {
		err = badRequest( c , "bad_pin" )
		return
	}
	if set_err != nil {
		err = serverError( c , set_err )
		return
	}
	handlers.audit( c , logs.KindAuth , "pin changed" , fiber.Map{ "has_pin": body.Pin != "" } )
	err = c.JSON( fiber.Map{ "ok": true , "has_pin": body.Pin != "" } )
	return
}

// CreateMyLoginLink mints a one-time login link for the caller's own
// account: the way to sign in on another device without asking an admin.
// It is ReissueLogin pointed at yourself, so it has the same effect: any
// unused link the account had stops working, and existing sessions stay
// signed in.
//
// Session only (see routes.go): a login link becomes a session, so an API
// key that could call this could turn itself into one.
func ( handlers *Handlers ) CreateMyLoginLink( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	credential , token_err := models.IssueLoginToken( handlers.Store , security.UserFrom( c ).ID , handlers.cfg().LoginTokenTTL )
	if token_err != nil {
		err = serverError( c , token_err )
		return
	}
	handlers.audit( c , logs.KindAuth , "own login link created" , nil )
	err = c.JSON( fiber.Map{
		"login_path":         "/login/" + credential,
		"expires_in_seconds": int( handlers.cfg().LoginTokenTTL.Seconds() ),
	} )
	return
}

// Logout deletes the session server-side as well as clearing the cookie, so
// a copy of the cookie captured earlier is dead too.
//
// It is held to the CSRF token like every other state change. SameSite=Strict
// already stops another site from sending the cookie here, but not a page on
// a sibling subdomain, and being signed out by someone else's page is the
// first step of tricking a person into signing in to the wrong account.
//
// Called with an API key it does nothing and says so by succeeding: there is
// no session to destroy. A key is ended by revoking it, not by logging out.
func ( handlers *Handlers ) Logout( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	handlers.audit( c , logs.KindAuth , "signed out" , nil )
	handlers.destroyCookieSession( c )
	handlers.Guard.ClearSessionCookie( c )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}
