package routes

import (
	bytes "bytes"

	fiber "github.com/gofiber/fiber/v3"

	metrics "ipb/server/metrics"
)

// RequireMetrics makes /metrics answer 404 while metrics.enabled or
// auth.api_keys is off, like RequireMCP.
func ( handlers *Handlers ) RequireMetrics( c fiber.Ctx ) ( err error ) {
	cfg := handlers.cfg()
	if cfg.MetricsEnabled == false || cfg.APIKeysEnabled == false {
		err = notFound( c , "not found" )
		return
	}
	err = c.Next()
	return
}

// GetMetrics is what a Prometheus scrape reads. See server/metrics.
func ( handlers *Handlers ) GetMetrics( c fiber.Ctx ) ( err error ) {
	extra := metrics.Extra{}
	if handlers.Logs.Enabled() {
		extra.LogsDropped = handlers.Logs.Dropped()
	}
	if handlers.Jobs != nil {
		for _ , job := range handlers.Jobs.Status() {
			extra.Jobs = append( extra.Jobs , metrics.Job{ Name: job.Name , LastSuccess: job.LastSuccess , LastFailure: job.LastFailure } )
		}
	}
	var out bytes.Buffer
	handlers.Metrics.Write( &out , extra )
	c.Set( fiber.HeaderContentType , "text/plain; version=0.0.4; charset=utf-8" )
	err = c.Send( out.Bytes() )
	return
}
