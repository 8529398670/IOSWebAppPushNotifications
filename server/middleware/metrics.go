package middleware

import (
	strings "strings"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	metrics "ipb/server/metrics"
)

// Metrics counts every request for /metrics. It is separate from RequestLog
// because that one stands down when the activity log is off, and these numbers
// are wanted regardless.
//
// A stream is left out of the timing: its handler returns as streaming starts,
// so what it would record is not how long it ran.
func Metrics( recorder *metrics.Recorder ) ( handler fiber.Handler ) {
	handler = func( c fiber.Ctx ) ( err error ) {
		recorder.Begin()
		defer recorder.End()
		started := time.Now()
		err = c.Next()
		status := c.Response().StatusCode()
		if err != nil {
			status = errorStatus( err )
		}
		content_type := string( c.Response().Header.ContentType() )
		timed := strings.HasPrefix( content_type , "text/event-stream" ) == false
		recorder.Observe( c.Method() , status , time.Since( started ).Seconds() , timed )
		return
	}
	return
}
