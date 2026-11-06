package routes

import (
	errors "errors"
	strconv "strconv"
	strings "strings"

	fiber "github.com/gofiber/fiber/v3"

	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

// sessionRow picks out what the devices list shows. It names each field,
// rather than returning the record, so the secret's hash and the CSRF token
// cannot reach a response by way of a change to the model.
func sessionRow( session *models.Session , current_id string ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":         session.ID,
		"current":    session.ID == current_id,
		"created_at": session.CreatedAt,
		"expires_at": session.ExpiresAt,
	}
	if session.LastSeenAt != nil {
		row[ "last_seen_at" ] = session.LastSeenAt
	}
	if session.IP != "" {
		row[ "ip" ] = session.IP
	}
	if session.UserAgent != "" {
		row[ "user_agent" ] = session.UserAgent
	}
	return
}

// ListMySessions answers "where am I signed in". Only ever the caller's own:
// an admin looks at someone else's through ListUserSessions.
func ( handlers *Handlers ) ListMySessions( c fiber.Ctx ) ( err error ) {
	actor := security.ActorFrom( c )
	sessions , list_err := models.ListSessionsForUser( handlers.Store , actor.User.ID )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	rows := []fiber.Map{}
	for _ , session := range sessions {
		rows = append( rows , sessionRow( session , actor.Session.ID ) )
	}
	err = sendPage( c , "sessions" , rows )
	return
}

// sessionsTarget reads whose sessions an admin route is asking about. Nobody but
// the owner reaches the owner's, the same rule as revoking the owner's access.
func ( handlers *Handlers ) sessionsTarget( c fiber.Ctx ) ( user_id uint64 , by_owner bool , refused *refusal ) {
	user_id , parse_err := strconv.ParseUint( c.Params( "user_id" ) , 10 , 64 )
	if parse_err != nil {
		refused = &refusal{ status: fiber.StatusBadRequest , message: "invalid user id" }
		return
	}
	if _ , get_err := models.GetUser( handlers.Store , user_id ); get_err != nil {
		refused = &refusal{ status: fiber.StatusNotFound , message: "no such user" }
		return
	}
	owner_id , owner_err := models.OwnerID( handlers.Store )
	if owner_err != nil {
		refused = &refusal{ status: fiber.StatusInternalServerError , message: "internal error" , cause: owner_err }
		return
	}
	by_owner = security.UserFrom( c ).ID == owner_id
	if user_id == owner_id && by_owner == false {
		refused = &refusal{ status: fiber.StatusForbidden , message: "the owner account's sessions are the owner's own" }
	}
	return
}

// ListUserSessions shows an admin where an account is signed in, for ending one
// device rather than everything with revoke-access. Addresses are for the owner
// only, as in the activity log, which keeps them from other admins too.
func ( handlers *Handlers ) ListUserSessions( c fiber.Ctx ) ( err error ) {
	user_id , by_owner , refused := handlers.sessionsTarget( c )
	if refused != nil {
		err = refused.send( c )
		return
	}
	sessions , list_err := models.ListSessionsForUser( handlers.Store , user_id )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	rows := []fiber.Map{}
	for _ , session := range sessions {
		row := sessionRow( session , security.ActorFrom( c ).Session.ID )
		if by_owner == false { delete( row , "ip" ) }
		rows = append( rows , row )
	}
	err = sendPage( c , "sessions" , rows )
	return
}

// RevokeUserSession signs one of an account's devices out, and only that.
func ( handlers *Handlers ) RevokeUserSession( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	user_id , _ , refused := handlers.sessionsTarget( c )
	if refused != nil {
		err = refused.send( c )
		return
	}
	// Clone: the log entry outlives this request, and fiber reuses the buffer.
	session_id := strings.Clone( c.Params( "session_id" ) )
	if session_id == security.ActorFrom( c ).Session.ID {
		err = badRequest( c , "use sign out for this device" )
		return
	}
	revoke_err := models.RevokeSession( handlers.Store , user_id , session_id )
	switch {
	case errors.Is( revoke_err , models.ErrSessionNotFound ):
		err = notFound( c , "not found" )
	case revoke_err != nil:
		err = serverError( c , revoke_err )
	default:
		handlers.audit( c , logs.KindAdmin , "session revoked" , fiber.Map{ "user_id": user_id } )
		err = c.JSON( fiber.Map{ "ok": true } )
	}
	return
}

// RevokeMySession signs out one other device. This device is refused: ending
// it here would leave the browser holding a dead cookie, and signing out is
// what the sign-out button is for.
func ( handlers *Handlers ) RevokeMySession( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	actor := security.ActorFrom( c )
	// Clone: the log entry outlives this request, and fiber reuses the buffer.
	session_id := strings.Clone( c.Params( "session_id" ) )
	if session_id == actor.Session.ID {
		err = badRequest( c , "use sign out for this device" )
		return
	}
	revoke_err := models.RevokeSession( handlers.Store , actor.User.ID , session_id )
	switch {
	case errors.Is( revoke_err , models.ErrSessionNotFound ):
		err = notFound( c , "not found" )
	case revoke_err != nil:
		err = serverError( c , revoke_err )
	default:
		handlers.audit( c , logs.KindAuth , "session_revoked" , nil )
		err = c.JSON( fiber.Map{ "ok": true } )
	}
	return
}

// RevokeMyOtherSessions is the button for a lost phone or a shared computer:
// everything but this device.
func ( handlers *Handlers ) RevokeMyOtherSessions( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	actor := security.ActorFrom( c )
	removed , revoke_err := models.RevokeOtherSessions( handlers.Store , actor.User.ID , actor.Session.ID )
	if revoke_err != nil {
		err = serverError( c , revoke_err )
		return
	}
	handlers.audit( c , logs.KindAuth , "sessions_revoked" , fiber.Map{ "removed": removed } )
	err = c.JSON( fiber.Map{ "ok": true , "removed": removed } )
	return
}
