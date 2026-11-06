package routes

import (
	errors "errors"
	strings "strings"


	fiber "github.com/gofiber/fiber/v3"

	db "ipb/server/db"
	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

// API keys are how anything that is not a browser calls this API: a script, a
// cron job, a CI pipeline, another service. A key carries a role from the same
// set users do, so there is one permission model rather than two -- see
// server/models/api_key.go and references/architecture.md.
//
// Every signed-in user can mint their own keys, and revoke or delete them. An
// admin can additionally see, revoke, and delete everyone's, which is what
// makes "who has standing access to this app" an answerable question, and can
// mint one that acts as someone else (CreateAPIKeyForUser).
//
// Revoking keeps the row, marked dead, so the listing still shows the key
// existed and when it stopped working; the `purge` job drops it later.
// Deleting removes the row now. Either one stops the key immediately.
//
// Minting, revoking, and deleting require a browser session (the group in routes.go adds
// Guard.RequireSession), so a leaked key cannot quietly mint its replacement.
// The admin routes that hand out login links require one too, for the same
// reason -- see Guard.RequireSession.

type createAPIKeyRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
	// ExpiresInDays is a pointer so that three cases stay distinguishable:
	// absent means "use the configured default", 0 means "never expires", and
	// a number means that many days. With a plain int, "never" and "unset"
	// would be the same request.
	ExpiresInDays *int   `json:"expires_in_days"`
	CSRFToken     string `json:"csrf_token"`
}

// renameAPIKeyRequest's Expect is the name the caller thinks it is replacing. The
// frontend sends it, so an undo cannot overwrite a rename made elsewhere.
type renameAPIKeyRequest struct {
	Name      string  `json:"name"`
	Expect    *string `json:"expect"`
	CSRFToken string  `json:"csrf_token"`
}

// apiKeyExpiryRequest's ExpiresInDays counts from now, and 0 means never, as when
// minting. Here it is required: there is no default to fall back on.
type apiKeyExpiryRequest struct {
	ExpiresInDays *int   `json:"expires_in_days"`
	CSRFToken     string `json:"csrf_token"`
}

// createUserAPIKeyRequest is createAPIKeyRequest plus whose key it is.
type createUserAPIKeyRequest struct {
	createAPIKeyRequest
	UserID uint64 `json:"user_id"`
}

// RequireAPIKeys hides the key-management endpoints when the feature is
// switched off, so an app with no programmatic callers can close the surface
// entirely. The Authorization header is ignored in that state too -- that part
// is enforced in server/security, not here, because it has to hold for every
// route rather than only these.
func ( handlers *Handlers ) RequireAPIKeys( c fiber.Ctx ) ( err error ) {
	if handlers.cfg().APIKeysEnabled == false {
		err = notFound( c , "api keys are disabled on this server" )
		return
	}
	err = c.Next()
	return
}

// apiKeyRow is the only shape a key is ever returned in. The secret hash is
// not in it, and nor is the credential -- that exists in one response, from
// CreateAPIKey, and is never recoverable afterwards.
func apiKeyRow( key *models.APIKey , display_name string ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":         key.ID,
		"user_id":    key.UserID,
		"name":       key.Name,
		"role":       key.Role,
		"created_at": key.CreatedAt,
		"revoked":    key.Revoked(),
		"expired":    key.Expired(),
		"live":       key.Live(),
	}
	if key.ExpiresAt != nil {
		row[ "expires_at" ] = key.ExpiresAt
	}
	if key.LastUsedAt != nil {
		row[ "last_used_at" ] = key.LastUsedAt
	}
	if key.RevokedAt != nil {
		row[ "revoked_at" ] = key.RevokedAt
	}
	if key.CreatedBy != 0 {
		row[ "created_by" ] = key.CreatedBy
	}
	if display_name != "" {
		row[ "display_name" ] = display_name
	}
	return
}

// ListMyAPIKeys answers "what has standing access as me". Revoked and expired
// keys are included, marked as such, because a key that used to exist is part
// of that answer.
func ( handlers *Handlers ) ListMyAPIKeys( c fiber.Ctx ) ( err error ) {
	user := security.UserFrom( c )
	keys , list_err := models.ListAPIKeysForUser( handlers.Store , user.ID )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	// Most people have no key someone else made, so the names are only loaded
	// when one is there to be named.
	names := map[ uint64 ]string{}
	for _ , key := range keys {
		if key.CreatedBy == 0 { continue }
		if names , list_err = handlers.displayNames(); list_err != nil {
			err = serverError( c , list_err )
			return
		}
		break
	}
	rows := []fiber.Map{}
	for _ , key := range keys {
		row := apiKeyRow( key , "" )
		nameCreator( row , key , names )
		rows = append( rows , row )
	}
	err = sendPage( c , "keys" , rows )
	return
}

// displayNames is every account's name by id: one pass rather than a GetUser
// per key, since a bucket read per row is the shape that quietly becomes slow.
func ( handlers *Handlers ) displayNames() ( names map[ uint64 ]string , err error ) {
	users , err := models.ListUsers( handlers.Store )
	if err != nil { return }
	names = map[ uint64 ]string{}
	for _ , user := range users {
		names[ user.ID ] = user.DisplayName
	}
	return
}

// nameCreator says who made a key on its owner's behalf. An admin deleted
// since has no name, and the page shows their id instead.
func nameCreator( row fiber.Map , key *models.APIKey , names map[ uint64 ]string ) {
	if name := names[ key.CreatedBy ]; key.CreatedBy != 0 && name != "" {
		row[ "created_by_name" ] = name
	}
}

// CreateMyAPIKey mints a key for the signed-in user and returns the credential
// once. The default role is "user" even for an admin: an admin-scoped key can
// list and disable accounts and revoke anyone's access, so it should be asked
// for rather than handed out by omission.
//
// The ceiling that a key cannot outrank its owner lives in
// models.IssueAPIKey, not here, so the control socket and the CLI get it too.
func ( handlers *Handlers ) CreateMyAPIKey( c fiber.Ctx ) ( err error ) {
	var body createAPIKeyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if models.ValidAPIKeyName( body.Name ) == false {
		err = badRequest( c , "name must be 1-80 characters" )
		return
	}

	role := body.Role
	if role == "" {
		role = models.RoleUser
	}
	if models.ValidRole( role ) == false {
		err = badRequest( c , "role must be admin or user" )
		return
	}

	ttl , ok := models.APIKeyTTLFromDays( body.ExpiresInDays , handlers.cfg().APIKeyTTL )
	if ok == false {
		err = badRequest( c , "expires_in_days must be 0 (never) or up to 3650" )
		return
	}

	user := security.UserFrom( c )
	credential , key , issue_err := models.IssueAPIKey( handlers.Store , user.ID , body.Name , role , ttl )
	if issue_err != nil {
		switch {
		case errors.Is( issue_err , models.ErrAPIKeyRole ):
			err = forbidden( c , "you cannot create an API key with more permission than your own account" )
		case errors.Is( issue_err , models.ErrAPIKeyLimit ):
			err = badRequest( c , "you already have the maximum number of live API keys -- revoke one first" )
		case errors.Is( issue_err , models.ErrAPIKeyDisabled ):
			// Not reachable through a live session today, since a disabled
			// account cannot hold one. Mapped anyway so that a future path
			// into this handler fails as a refusal rather than a 500.
			err = forbidden( c , "this account is disabled" )
		default:
			err = serverError( c , issue_err )
		}
		return
	}

	// The credential appears here and nowhere else, ever.
	row := apiKeyRow( key , "" )
	row[ "credential" ] = credential
	handlers.audit( c , logs.KindAdmin , "api key created" , fiber.Map{ "key_id": key.ID , "name": key.Name , "role": key.Role } )
	handlers.Webhooks.Emit( models.EventAPIKeyCreated , map[string]any{ "key_id": key.ID , "user_id": key.UserID , "name": key.Name , "role": key.Role } )
	err = c.Status( fiber.StatusCreated ).JSON( row )
	return
}

// CreateAPIKeyForUser mints a key that acts as another account, for setting up
// someone's integration for them. It needs a browser session, like every route
// that makes a credential: the admin_keys group in routes.go adds it, so a
// leaked admin key cannot mint itself a way in as somebody else.
//
// Who may mint for whom is models.IssueAPIKeyFor's to say. The key records who
// made it, and shows that to the person it acts as.
func ( handlers *Handlers ) CreateAPIKeyForUser( c fiber.Ctx ) ( err error ) {
	var body createUserAPIKeyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if body.UserID == 0 {
		err = badRequest( c , "user_id is required" )
		return
	}
	if models.ValidAPIKeyName( body.Name ) == false {
		err = badRequest( c , "name must be 1-80 characters" )
		return
	}
	role := body.Role
	if role == "" {
		role = models.RoleUser
	}
	if models.ValidRole( role ) == false {
		err = badRequest( c , "role must be admin or user" )
		return
	}
	ttl , ok := models.APIKeyTTLFromDays( body.ExpiresInDays , handlers.cfg().APIKeyTTL )
	if ok == false {
		err = badRequest( c , "expires_in_days must be 0 (never) or up to 3650" )
		return
	}

	actor := security.UserFrom( c )
	credential , key , issue_err := models.IssueAPIKeyFor( handlers.Store , actor.ID , body.UserID , body.Name , role , ttl )
	if issue_err != nil {
		switch {
		case errors.Is( issue_err , db.ErrNotFound ):
			err = notFound( c , "no such user" )
		case errors.Is( issue_err , models.ErrOwnerProtected ):
			err = forbidden( c , "a key for the owner can only be made by the owner, or from a shell" )
		case errors.Is( issue_err , models.ErrOwnerRequired ):
			err = forbidden( c , "only the owner can create a key for an admin" )
		case errors.Is( issue_err , models.ErrAPIKeyRole ):
			err = forbidden( c , "a key cannot have more permission than the account it belongs to" )
		case errors.Is( issue_err , models.ErrAPIKeyLimit ):
			err = badRequest( c , "that account already has the maximum number of live API keys" )
		case errors.Is( issue_err , models.ErrAPIKeyDisabled ):
			err = forbidden( c , "that account is disabled" )
		default:
			err = serverError( c , issue_err )
		}
		return
	}

	// The credential appears here and nowhere else, ever.
	row := apiKeyRow( key , "" )
	row[ "credential" ] = credential
	handlers.audit( c , logs.KindAdmin , "api key created" , fiber.Map{ "key_id": key.ID , "name": key.Name , "role": key.Role , "user_id": key.UserID , "created_by": actor.ID } )
	handlers.Webhooks.Emit( models.EventAPIKeyCreated , map[string]any{ "key_id": key.ID , "user_id": key.UserID , "name": key.Name , "role": key.Role , "created_by": actor.ID } )
	err = c.Status( fiber.StatusCreated ).JSON( row )
	return
}

// RenameMyAPIKey renames one of your own keys. Someone else's is "no such api
// key", for the same reason as in RevokeMyAPIKey.
func ( handlers *Handlers ) RenameMyAPIKey( c fiber.Ctx ) ( err error ) {
	err = handlers.renameKey( c , true )
	return
}

// RenameAnyAPIKey is an admin renaming anyone's key. A name changes nothing about
// what a key can do, so unlike its expiry this needs no ladder.
func ( handlers *Handlers ) RenameAnyAPIKey( c fiber.Ctx ) ( err error ) {
	err = handlers.renameKey( c , false )
	return
}

func ( handlers *Handlers ) renameKey( c fiber.Ctx , own_only bool ) ( err error ) {
	var body renameAPIKeyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if models.ValidAPIKeyName( body.Name ) == false {
		err = badRequest( c , "name must be 1-80 characters" )
		return
	}

	key , get_err := models.GetAPIKey( handlers.Store , c.Params( "key_id" ) )
	if get_err != nil || ( own_only && key.UserID != security.UserFrom( c ).ID ) {
		err = notFound( c , "no such api key" )
		return
	}
	rename_err := models.RenameAPIKey( handlers.Store , key.ID , body.Name , body.Expect )
	var refusal *models.RenameConflictError
	switch {
	case errors.As( rename_err , &refusal ):
		err = conflict( c , refusal.Error() , fiber.Map{ "name": refusal.Current } )
		return
	case errors.Is( rename_err , db.ErrNotFound ):
		err = notFound( c , "no such api key" )
		return
	case rename_err != nil:
		err = serverError( c , rename_err )
		return
	}
	name := strings.TrimSpace( body.Name )
	handlers.audit( c , logs.KindAdmin , "api key renamed" , fiber.Map{ "key_id": key.ID , "name": name } )
	err = c.JSON( fiber.Map{ "ok": true , "name": name } )
	return
}

// SetMyAPIKeyExpiry changes when one of your own keys expires. The session this
// group requires is what stops a leaked key from extending itself.
func ( handlers *Handlers ) SetMyAPIKeyExpiry( c fiber.Ctx ) ( err error ) {
	err = handlers.setKeyExpiry( c , true )
	return
}

// SetAnyAPIKeyExpiry is the same for an admin. Whose keys they may change is
// models.SetAPIKeyExpiry's to say.
func ( handlers *Handlers ) SetAnyAPIKeyExpiry( c fiber.Ctx ) ( err error ) {
	err = handlers.setKeyExpiry( c , false )
	return
}

func ( handlers *Handlers ) setKeyExpiry( c fiber.Ctx , own_only bool ) ( err error ) {
	var body apiKeyExpiryRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	ttl , ok := models.APIKeyTTLFromDays( body.ExpiresInDays , 0 )
	if body.ExpiresInDays == nil || ok == false {
		err = badRequest( c , "expires_in_days must be 0 (never) or up to 3650" )
		return
	}

	actor := security.UserFrom( c )
	found , get_err := models.GetAPIKey( handlers.Store , c.Params( "key_id" ) )
	if get_err != nil || ( own_only && found.UserID != actor.ID ) {
		err = notFound( c , "no such api key" )
		return
	}
	key , set_err := models.SetAPIKeyExpiry( handlers.Store , found.ID , actor.ID , ttl )
	if set_err != nil {
		switch {
		case errors.Is( set_err , db.ErrNotFound ):
			err = notFound( c , "no such api key" )
		case errors.Is( set_err , models.ErrAPIKeyDead ):
			err = badRequest( c , "only a live key can have its expiry changed -- create a new one instead" )
		case errors.Is( set_err , models.ErrOwnerProtected ):
			err = forbidden( c , "only the owner can change when the owner's keys expire" )
		case errors.Is( set_err , models.ErrOwnerRequired ):
			err = forbidden( c , "only the owner can change when an admin's keys expire" )
		default:
			err = serverError( c , set_err )
		}
		return
	}
	handlers.audit( c , logs.KindAdmin , "api key expiry changed" , fiber.Map{ "key_id": key.ID , "expires_in_days": *body.ExpiresInDays } )
	err = c.JSON( apiKeyRow( key , "" ) )
	return
}

// RevokeMyAPIKey takes effect immediately -- the next request carrying that
// key fails. Someone else's key is reported as "no such api key" rather than
// "forbidden", so the endpoint does not confirm which key ids exist.
func ( handlers *Handlers ) RevokeMyAPIKey( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}

	user := security.UserFrom( c )
	key , get_err := models.GetAPIKey( handlers.Store , c.Params( "key_id" ) )
	if get_err != nil || key.Deleted() || key.UserID != user.ID {
		err = notFound( c , "no such api key" )
		return
	}
	if revoke_err := models.RevokeAPIKey( handlers.Store , key.ID ); revoke_err != nil {
		err = serverError( c , revoke_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "api key revoked" , fiber.Map{ "key_id": c.Params( "key_id" ) } )
	handlers.Webhooks.Emit( models.EventAPIKeyRevoked , map[string]any{ "key_id": key.ID , "user_id": key.UserID } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// DeleteMyAPIKey deletes one of your own keys -- live or already dead. It
// stops working at once, and RestoreMyAPIKey can bring it back for a few
// minutes. Someone else's key is "no such api key", for the same reason as in
// RevokeMyAPIKey.
func ( handlers *Handlers ) DeleteMyAPIKey( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}

	user := security.UserFrom( c )
	key , get_err := models.GetAPIKey( handlers.Store , c.Params( "key_id" ) )
	if get_err != nil || key.UserID != user.ID {
		err = notFound( c , "no such api key" )
		return
	}
	if delete_err := models.DeleteAPIKey( handlers.Store , key.ID , user.ID ); delete_err != nil {
		err = deleteKeyError( c , delete_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "api key deleted" , fiber.Map{ "key_id": c.Params( "key_id" ) } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// RestoreMyAPIKey undoes DeleteMyAPIKey, within models.RestoreWindow. A key
// an admin deleted is the admin's to restore, not its owner's.
func ( handlers *Handlers ) RestoreMyAPIKey( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}

	user := security.UserFrom( c )
	key , get_err := models.GetAPIKey( handlers.Store , c.Params( "key_id" ) )
	if get_err != nil || key.UserID != user.ID {
		err = notFound( c , "no such api key" )
		return
	}
	err = handlers.restoreKey( c , key.ID , user )
	return
}

// RestoreAnyAPIKey undoes a delete, any key's, within models.RestoreWindow.
func ( handlers *Handlers ) RestoreAnyAPIKey( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	err = handlers.restoreKey( c , c.Params( "key_id" ) , security.UserFrom( c ) )
	return
}

func ( handlers *Handlers ) restoreKey( c fiber.Ctx , key_id string , actor *models.User ) ( err error ) {
	key , restore_err := models.RestoreAPIKey( handlers.Store , key_id , actor.ID , actor.IsAdmin() )
	if restore_err != nil {
		err = restoreRefused( c , restore_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "api key restored" , fiber.Map{ "key_id": key_id } )
	err = c.JSON( apiKeyRow( key , "" ) )
	return
}

// deleteKeyError maps a DeleteAPIKey failure. A key that is already deleted,
// or vanished between the lookup and the delete -- deleted by its owner and
// an admin at once -- is reported as missing, not as a server fault.
func deleteKeyError( c fiber.Ctx , delete_err error ) ( err error ) {
	if errors.Is( delete_err , db.ErrNotFound ) {
		err = notFound( c , "no such api key" )
		return
	}
	err = serverError( c , delete_err )
	return
}

// ListAllAPIKeys is the admin view: every key in the app, with whose it is.
// This is the "who and what has standing access" question, and it is the
// reason admins can see keys they did not create.
func ( handlers *Handlers ) ListAllAPIKeys( c fiber.Ctx ) ( err error ) {
	keys , list_err := models.ListAPIKeys( handlers.Store )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	names , names_err := handlers.displayNames()
	if names_err != nil {
		err = serverError( c , names_err )
		return
	}

	rows := []fiber.Map{}
	for _ , key := range keys {
		row := apiKeyRow( key , names[ key.UserID ] )
		nameCreator( row , key , names )
		rows = append( rows , row )
	}
	err = sendPage( c , "keys" , rows )
	return
}

// RevokeAnyAPIKey is how an admin kills a credential belonging to someone
// else -- a laptop that went missing, a CI system being decommissioned, a
// contractor who has finished.
func ( handlers *Handlers ) RevokeAnyAPIKey( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}

	key , get_err := models.GetAPIKey( handlers.Store , c.Params( "key_id" ) )
	if get_err != nil {
		err = notFound( c , "no such api key" )
		return
	}
	if revoke_err := models.RevokeAPIKey( handlers.Store , key.ID ); revoke_err != nil {
		err = serverError( c , revoke_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "api key revoked" , fiber.Map{ "key_id": c.Params( "key_id" ) } )
	handlers.Webhooks.Emit( models.EventAPIKeyRevoked , map[string]any{ "key_id": key.ID , "user_id": key.UserID } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// DeleteAnyAPIKey stops the key working and takes it off every listing, its
// owner's included. Unlike RevokeAnyAPIKey it can be undone, by
// RestoreAnyAPIKey.
func ( handlers *Handlers ) DeleteAnyAPIKey( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}

	if delete_err := models.DeleteAPIKey( handlers.Store , c.Params( "key_id" ) , security.UserFrom( c ).ID ); delete_err != nil {
		err = deleteKeyError( c , delete_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "api key deleted" , fiber.Map{ "key_id": c.Params( "key_id" ) } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}
