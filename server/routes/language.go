package routes

import (
	fiber "github.com/gofiber/fiber/v3"
)

// GetLanguage hands the browser the whole language.yaml tree as JSON. It is
// deliberately public: the signed-out page has text too, and none of it is
// secret. Do not put anything sensitive in language.yaml -- it is, by design,
// readable by anyone who can reach the server.
func ( handlers *Handlers ) GetLanguage( c fiber.Ctx ) ( err error ) {
	c.Set( fiber.HeaderContentType , fiber.MIMEApplicationJSON )
	c.Set( fiber.HeaderCacheControl , "no-store" )
	err = c.Send( handlers.Language.JSON() )
	return
}

// GetHealth is what the Dockerfile HEALTHCHECK hits. It stays trivial on
// purpose -- if it touched the database, a slow query would get the container
// killed and restarted, turning a small problem into an outage.
func ( handlers *Handlers ) GetHealth( c fiber.Ctx ) ( err error ) {
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}
