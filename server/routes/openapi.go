package routes

import (
	fiber "github.com/gofiber/fiber/v3"
)

// GetOpenAPI hands out config/openapi.json. It is written by hand, so it can
// say what a route takes and returns; openapi_test.go fails when it and the
// route table disagree. Signed-in callers only: it maps the admin surface, and
// nobody who cannot sign in has a use for it.
func ( handlers *Handlers ) GetOpenAPI( c fiber.Ctx ) ( err error ) {
	if len( handlers.OpenAPI ) == 0 {
		err = notFound( c , "not found" )
		return
	}
	c.Set( fiber.HeaderContentType , fiber.MIMEApplicationJSON )
	err = c.Send( handlers.OpenAPI )
	return
}
