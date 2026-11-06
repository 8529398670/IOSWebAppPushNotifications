package routes

import (
	strconv "strconv"

	fiber "github.com/gofiber/fiber/v3"

	middleware "ipb/server/middleware"
	models "ipb/server/models"
	security "ipb/server/security"
)

// maintenanceRetrySeconds is the Retry-After on a refusal: long enough not to
// invite hammering, short enough that a script comes back soon after the end.
const maintenanceRetrySeconds = 300

// Maintenance is server.maintenance, read per request so switching it applies
// at once. It runs after Guard.LoadUser because it has to know who is asking,
// and that also leaves `manage` and the control socket out of it.
//
// What is open in each mode is middleware.MaintenanceAllows. Past that, only
// the owner's browser session gets through, which is what lets them check the
// work and turn the mode off. Their API keys are refused like anyone's, as on
// every owner route: see Guard.RequireOwner.
func ( handlers *Handlers ) Maintenance( c fiber.Ctx ) ( err error ) {
	mode := handlers.cfg().MaintenanceMode()
	if middleware.MaintenanceAllows( mode , c.Method() , c.Path() ) || handlers.ownerSession( c ) {
		err = c.Next()
		return
	}
	c.Set( fiber.HeaderRetryAfter , strconv.Itoa( maintenanceRetrySeconds ) )
	if handlers.ErrorPages.Wanted( c ) {
		err = handlers.ErrorPages.Send( c , fiber.StatusServiceUnavailable , "" )
		return
	}
	err = c.Status( fiber.StatusServiceUnavailable ).JSON( fiber.Map{ "error": "this app is in maintenance mode" , "maintenance": mode } )
	return
}

// ownerSession fails closed: if the owner cannot be read, nobody is exempt.
func ( handlers *Handlers ) ownerSession( c fiber.Ctx ) ( result bool ) {
	actor := security.ActorFrom( c )
	if actor == nil || actor.Session == nil { return }
	owner_id , err := models.OwnerID( handlers.Store )
	result = err == nil && actor.User.ID == owner_id
	return
}
