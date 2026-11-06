package routes

import (
	errors "errors"
	strconv "strconv"
	strings "strings"

	fiber "github.com/gofiber/fiber/v3"

	db "ipb/server/db"
	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

type createUserRequest struct {
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	CSRFToken   string `json:"csrf_token"`
}

type csrfOnlyRequest struct {
	CSRFToken string `json:"csrf_token"`
}

type renameUserRequest struct {
	DisplayName string  `json:"display_name"`
	Expect      *string `json:"expect"`
	CSRFToken   string  `json:"csrf_token"`
}

type setRoleRequest struct {
	Role      string `json:"role"`
	CSRFToken string `json:"csrf_token"`
}

type setDisabledRequest struct {
	Disabled  bool   `json:"disabled"`
	CSRFToken string `json:"csrf_token"`
}

// ListUsers marks the owner on its row, so the UI can tell which delete,
// disable, and revoke buttons the server would refuse -- see models/owner.go.
//
// ?q= keeps the accounts whose name or username contains it, in any case. Here
// and not in the browser, which only ever holds one page of them.
func ( handlers *Handlers ) ListUsers( c fiber.Ctx ) ( err error ) {
	rows , list_err := handlers.userRowsMatching( c.Query( "q" ) )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	err = sendPage( c , "users" , rows )
	return
}

// userRows is shared with the MCP admin_list_users tool.
func ( handlers *Handlers ) userRows() ( rows []fiber.Map , err error ) {
	rows , err = handlers.userRowsMatching( "" )
	return
}

func ( handlers *Handlers ) userRowsMatching( query string ) ( rows []fiber.Map , err error ) {
	users , err := models.ListUsers( handlers.Store )
	if err != nil { return }
	owner_id , err := models.OwnerID( handlers.Store )
	if err != nil { return }
	query = strings.ToLower( strings.TrimSpace( query ) )
	rows = []fiber.Map{}
	for _ , user := range users {
		if strings.Contains( strings.ToLower( user.DisplayName ) , query ) == false &&
			strings.Contains( strings.ToLower( user.Username ) , query ) == false { continue }
		rows = append( rows , fiber.Map{
			"id":           user.ID,
			"display_name": user.DisplayName,
			"role":         user.Role,
			"disabled":     user.Disabled(),
			"owner":        user.ID == owner_id,
			"has_password":     user.HasPassword(),
			"password_blocked": user.PasswordBlocked,
			"two_factor":       user.TwoFactorOn(),
		} )
	}
	return
}

// CreateUser is the signup process: an admin names someone, and gets back a
// one-time link to hand them. The link is returned as a path, not a full URL
// -- the browser knows the origin it is talking to, whereas the server behind
// a reverse proxy often does not, and a login link with the wrong host is
// worse than useless.
func ( handlers *Handlers ) CreateUser( c fiber.Ctx ) ( err error ) {
	var body createUserRequest
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
	if models.ValidRole( body.Role ) == false {
		err = badRequest( c , "role must be admin or user" )
		return
	}

	user , create_err := models.CreateUser( handlers.Store , body.DisplayName , body.Role )
	if create_err != nil {
		err = serverError( c , create_err )
		return
	}
	credential , token_err := models.IssueLoginToken( handlers.Store , user.ID , handlers.cfg().LoginTokenTTL )
	if token_err != nil {
		err = serverError( c , token_err )
		return
	}

	handlers.audit( c , logs.KindAdmin , "user created" , fiber.Map{ "user_id": user.ID , "name": user.DisplayName , "role": user.Role } )
	handlers.Webhooks.Emit( models.EventUserCreated , map[string]any{ "user_id": user.ID , "display_name": user.DisplayName , "role": user.Role } )
	err = c.Status( fiber.StatusCreated ).JSON( fiber.Map{
		"user_id":            user.ID,
		"login_path":         "/login/" + credential,
		"expires_in_seconds": int( handlers.cfg().LoginTokenTTL.Seconds() ),
	} )
	return
}

// ReissueLogin covers the only real failure mode of this auth model: someone
// lost their cookie or their device, and there is no password reset to fall
// back on. An admin mints a fresh link instead. Any link the account had not
// used yet stops working (see models.IssueLoginToken).
//
// It is not a reset: sessions the account already has stay signed in. When
// the worry is that someone else holds the account's credentials, use
// RevokeAccess first, then reissue.
func ( handlers *Handlers ) ReissueLogin( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
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
	if _ , get_err := models.GetUser( handlers.Store , user_id ); get_err != nil {
		err = notFound( c , "no such user" )
		return
	}

	credential , token_err := models.IssueLoginToken( handlers.Store , user_id , handlers.cfg().LoginTokenTTL )
	if token_err != nil {
		err = serverError( c , token_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "login link reissued" , fiber.Map{ "user_id": user_id } )
	err = c.JSON( fiber.Map{
		"login_path":         "/login/" + credential,
		"expires_in_seconds": int( handlers.cfg().LoginTokenTTL.Seconds() ),
	} )
	return
}

// RenameUser is an admin renaming someone else. Who may rename whom lives in
// models.RenameUserAs. It needs a browser session, like making an account: a
// name is how people tell who they are dealing with.
func ( handlers *Handlers ) RenameUser( c fiber.Ctx ) ( err error ) {
	var body renameUserRequest
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
	if models.ValidDisplayName( body.DisplayName ) == false {
		err = badRequest( c , "display name must be 1-80 characters" )
		return
	}
	rename_err := models.RenameUserAs( handlers.Store , user_id , security.UserFrom( c ).ID , body.DisplayName , body.Expect )
	var stale *models.RenameConflictError
	switch {
	case errors.As( rename_err , &stale ):
		err = conflict( c , stale.Error() , fiber.Map{ "display_name": stale.Current } )
		return
	case errors.Is( rename_err , db.ErrNotFound ):
		err = notFound( c , "no such user" )
		return
	case errors.Is( rename_err , models.ErrOwnerRequired ):
		err = forbidden( c , "only the owner can rename an admin" )
		return
	case rename_err != nil:
		err = serverError( c , rename_err )
		return
	}
	name := strings.TrimSpace( body.DisplayName )
	handlers.audit( c , logs.KindAdmin , "user renamed" , fiber.Map{ "user_id": user_id , "name": name } )
	err = c.JSON( fiber.Map{ "ok": true , "display_name": name } )
	return
}

// SetUserRole makes an account an admin or an ordinary user. Who may do what
// lives in models.SetUserRole. It needs a browser session, like making an
// account, so a leaked admin key cannot hand out admin rights.
func ( handlers *Handlers ) SetUserRole( c fiber.Ctx ) ( err error ) {
	var body setRoleRequest
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
	if models.ValidRole( body.Role ) == false {
		err = badRequest( c , "role must be admin or user" )
		return
	}
	changed , role_err := models.SetUserRole( handlers.Store , user_id , security.UserFrom( c ).ID , body.Role )
	switch {
	case errors.Is( role_err , db.ErrNotFound ):
		err = notFound( c , "no such user" )
		return
	case errors.Is( role_err , models.ErrRoleSelf ):
		err = badRequest( c , role_err.Error() )
		return
	case errors.Is( role_err , models.ErrOwnerProtected ):
		err = forbidden( c , "the owner is always an admin" )
		return
	case errors.Is( role_err , models.ErrOwnerRequired ):
		err = forbidden( c , "only the owner can take away an admin's rights" )
		return
	case role_err != nil:
		err = serverError( c , role_err )
		return
	}
	if changed {
		handlers.audit( c , logs.KindAdmin , "user role changed" , fiber.Map{ "user_id": user_id , "role": body.Role } )
	}
	err = c.JSON( fiber.Map{ "ok": true , "role": body.Role } )
	return
}

func ( handlers *Handlers ) SetUserDisabled( c fiber.Ctx ) ( err error ) {
	var body setDisabledRequest
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
	if refused := handlers.setUserDisabled( security.UserFrom( c ).ID , user_id , body.Disabled ); refused != nil {
		err = refused.send( c )
		return
	}
	handlers.audit( c , logs.KindAdmin , "user disabled set" , fiber.Map{ "user_id": user_id , "disabled": body.Disabled } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// RevokeAccess is the response to "this account may be compromised": every
// session, unused login link, and live API key it holds stops working at
// once. The account itself stays enabled; reissue a login link to let its
// owner back in. See models.RevokeAllCredentials for why this is separate
// from both disabling and reissuing.
func ( handlers *Handlers ) RevokeAccess( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
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
	revoked , refused := handlers.revokeAccess( security.UserFrom( c ).ID , user_id )
	if refused != nil {
		err = refused.send( c )
		return
	}
	handlers.audit( c , logs.KindAdmin , "access revoked" , fiber.Map{ "user_id": user_id } )
	err = c.JSON( fiber.Map{ "ok": true , "revoked": revoked } )
	return
}

// ResetTwoFactor is for someone who lost both the phone and the recovery codes.
// Who may reset whom lives in models.ResetTwoFactor; it needs a browser
// session, because it removes what stands between a login link and the
// account.
func ( handlers *Handlers ) ResetTwoFactor( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
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
	reset_err := models.ResetTwoFactor( handlers.Store , user_id , security.UserFrom( c ).ID )
	switch {
	case errors.Is( reset_err , db.ErrNotFound ):
		err = notFound( c , "no such user" )
		return
	case errors.Is( reset_err , models.ErrResetSelf ):
		err = badRequest( c , "you cannot reset your own two-factor sign-in" )
		return
	case errors.Is( reset_err , models.ErrOwnerProtected ):
		err = forbidden( c , "the owner's two-factor sign-in can only be reset from a shell" )
		return
	case errors.Is( reset_err , models.ErrOwnerRequired ):
		err = forbidden( c , "only the owner can reset an admin's two-factor sign-in" )
		return
	case reset_err != nil:
		err = serverError( c , reset_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "two-factor reset" , fiber.Map{ "user_id": user_id } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// DeleteUser removes an account for good, together with every session, login
// link, and API key it held. Disabling is the reversible version; this is for
// an account that should not exist at all.
//
// Any admin may delete an ordinary user. Deleting an admin takes the owner,
// and nobody deletes the owner or themselves -- those rules live in
// models.DeleteUser, checked inside its transaction. The route also requires
// a browser session (see routes.go): this cannot be undone, so a leaked
// admin-scoped API key must not be able to do it.
func ( handlers *Handlers ) DeleteUser( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
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

	removed , delete_err := models.DeleteUser( handlers.Store , user_id , security.UserFrom( c ).ID )
	switch {
	case delete_err == nil:
		handlers.audit( c , logs.KindAdmin , "user deleted" , fiber.Map{ "user_id": user_id } )
		handlers.Webhooks.Emit( models.EventUserDeleted , map[string]any{ "user_id": user_id } )
		err = c.JSON( fiber.Map{ "ok": true , "removed": removed } )
	case errors.Is( delete_err , db.ErrNotFound ):
		err = notFound( c , "no such user" )
	case errors.Is( delete_err , models.ErrDeleteSelf ):
		err = badRequest( c , "you cannot delete your own account" )
	case errors.Is( delete_err , models.ErrOwnerProtected ):
		err = forbidden( c , "the owner account cannot be deleted" )
	case errors.Is( delete_err , models.ErrOwnerRequired ):
		err = forbidden( c , "only the owner can delete an admin account" )
	default:
		err = serverError( c , delete_err )
	}
	return
}

// refusal is a rule saying no, kept apart from how it is delivered: the HTTP
// handlers send it as a status and an error body, the MCP tools as a tool
// error with the same words. Writing the rule once is what keeps the two
// doors from drifting apart.
type refusal struct {
	status  int
	message string
	// cause is why a 5xx happened. It goes to the log, never to the caller.
	cause error
}

func ( refused *refusal ) send( c fiber.Ctx ) ( err error ) {
	if refused.status >= 500 {
		err = serverError( c , refused.cause )
		return
	}
	err = c.Status( refused.status ).JSON( fiber.Map{ "error": refused.message } )
	return
}

// setUserDisabled carries every rule for switching an account off or on, for
// SetUserDisabled and the MCP admin_set_user_disabled tool.
func ( handlers *Handlers ) setUserDisabled( self_id uint64 , user_id uint64 , disabled bool ) ( refused *refusal ) {
	if _ , get_err := models.GetUser( handlers.Store , user_id ); get_err != nil {
		refused = &refusal{ status: fiber.StatusNotFound , message: "no such user" }
		return
	}

	// Locking yourself out is unrecoverable without shell access, so it is
	// worth one guard rail even though an admin could still disable a peer.
	if disabled && user_id == self_id {
		refused = &refusal{ status: fiber.StatusBadRequest , message: "you cannot disable your own account" }
		return
	}

	// Disabling also deletes the account's sessions and unused login links,
	// in the same transaction -- see models.SetUserDisabled. The owner cannot
	// be disabled; that check is in the model so every route gets it.
	if disable_err := models.SetUserDisabled( handlers.Store , user_id , disabled ); disable_err != nil {
		if errors.Is( disable_err , models.ErrOwnerProtected ) {
			refused = &refusal{ status: fiber.StatusForbidden , message: "the owner account cannot be disabled" }
			return
		}
		refused = &refusal{ status: fiber.StatusInternalServerError , message: "internal error" , cause: disable_err }
		return
	}
	handlers.Webhooks.Emit( models.EventUserDisabled , map[string]any{ "user_id": user_id , "disabled": disabled } )
	return
}

// revokeAccess carries every rule for cutting an account's credentials off,
// for RevokeAccess and the MCP admin_revoke_access tool.
func ( handlers *Handlers ) revokeAccess( self_id uint64 , user_id uint64 ) ( revoked models.Revoked , refused *refusal ) {
	if _ , get_err := models.GetUser( handlers.Store , user_id ); get_err != nil {
		refused = &refusal{ status: fiber.StatusNotFound , message: "no such user" }
		return
	}
	// Same guard rail as disabling: revoking your own access signs you out
	// with no link to get back in.
	if user_id == self_id {
		refused = &refusal{ status: fiber.StatusBadRequest , message: "you cannot revoke your own access" }
		return
	}

	// The owner is refused here (allow_owner false). Only an operator with
	// shell access may cut the owner off -- see models.RevokeAllCredentials.
	revoked , revoke_err := models.RevokeAllCredentials( handlers.Store , user_id , false )
	if revoke_err != nil {
		if errors.Is( revoke_err , models.ErrOwnerProtected ) {
			refused = &refusal{ status: fiber.StatusForbidden , message: "the owner account's access cannot be revoked" }
			return
		}
		refused = &refusal{ status: fiber.StatusInternalServerError , message: "internal error" , cause: revoke_err }
	}
	return
}
