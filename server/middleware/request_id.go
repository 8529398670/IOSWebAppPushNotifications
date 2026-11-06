package middleware

import (
	fiber "github.com/gofiber/fiber/v3"

	encryption "ipb/server/encryption"
)

const (
	requestIDHeader = "X-Request-ID"
	requestIDLocal  = "request_id"
	// Hex rather than a URL token: a token can start with "-", which the Logs
	// screen's search reads as "leave this out".
	requestIDLength = 16
)

// RequestID gives every request a reference, sent back in X-Request-ID, written
// on its log entries, and shown on an error page, so that what someone reads
// out can be matched to what happened.
//
// One sent by the caller is ignored. It would let anyone choose what appears
// in the log, and collide on purpose with a real one; a proxy that wants to
// follow a request keeps its own id.
func RequestID() ( handler fiber.Handler ) {
	handler = func( c fiber.Ctx ) ( err error ) {
		id := encryption.GenerateRandomString( requestIDLength )
		c.Locals( requestIDLocal , id )
		c.Set( requestIDHeader , id )
		err = c.Next()
		return
	}
	return
}

// RequestIDFrom is this request's reference, or "" before RequestID has run: a
// body too large for the server to read fails before any middleware.
func RequestIDFrom( c fiber.Ctx ) ( id string ) {
	id , _ = c.Locals( requestIDLocal ).( string )
	return
}
