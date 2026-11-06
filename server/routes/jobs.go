package routes

import (
	errors "errors"
	strings "strings"

	fiber "github.com/gofiber/fiber/v3"

	jobs "ipb/server/jobs"
	logs "ipb/server/logs"
)

// ListJobs is the owner's Jobs screen: what runs in the background and how the
// last run of each went.
func ( handlers *Handlers ) ListJobs( c fiber.Ctx ) ( err error ) {
	err = c.JSON( fiber.Map{ "jobs": handlers.Jobs.Status() } )
	return
}

// RunJob starts a job now, ahead of its schedule. The answer is 202 because
// only the start is waited for: a backup can outlast a request, and the screen
// polls for how it ended.
func ( handlers *Handlers ) RunJob( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	// Clone: the log entry outlives this request, and fiber reuses the buffer.
	name := strings.Clone( c.Params( "name" ) )
	run_err := handlers.Jobs.RunNow( name )
	switch {
	case errors.Is( run_err , jobs.ErrUnknown ):
		err = notFound( c , "not found" )
	case run_err != nil:
		err = conflict( c , "job already running" , nil )
	default:
		handlers.audit( c , logs.KindAdmin , "job_run" , fiber.Map{ "name": name } )
		err = c.Status( fiber.StatusAccepted ).JSON( fiber.Map{ "ok": true } )
	}
	return
}
