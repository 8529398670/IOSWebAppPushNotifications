package routes

import (
	sync "sync"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	db "ipb/server/db"
	models "ipb/server/models"
)

// readyWait is how long /api/ready waits for the database before saying no.
const readyWait = 2 * time.Second

// readiness is the probe in progress, if there is one. Anyone can call
// /api/ready, and a database slow enough to time out is the worst moment to
// pile more reads onto it, so callers share one probe. A stuck one holds a
// single goroutine, not one per caller.
type readiness struct {
	lock    sync.Mutex
	current *readyProbe
	// check replaces the real one in a test.
	check func() bool
}

type readyProbe struct {
	done chan struct{}
	ok   bool
}

// GetReady says whether this server can do real work: the database answers,
// is at the schema this build expects, and can be read with this key, which
// reading the owner record proves.
//
// It is apart from /api/health on purpose. The container's healthcheck restarts
// what fails it, so that one touches nothing; this is for a load balancer, or a
// person, deciding whether to send traffic. The body says no more than yes or
// no, because the route is public.
func ( handlers *Handlers ) GetReady( c fiber.Ctx ) ( err error ) {
	probe := handlers.readyProbe()
	ok := false
	select {
	case <-probe.done:
		ok = probe.ok
	case <-time.After( readyWait ):
	}
	status := fiber.StatusOK
	if ok == false {
		status = fiber.StatusServiceUnavailable
	}
	err = c.Status( status ).JSON( fiber.Map{ "ok": ok } )
	return
}

func ( handlers *Handlers ) readyProbe() ( probe *readyProbe ) {
	state := &handlers.readiness
	state.lock.Lock()
	defer state.lock.Unlock()
	if state.current != nil {
		probe = state.current
		return
	}
	probe = &readyProbe{ done: make( chan struct{} ) }
	state.current = probe
	go func() {
		defer func() {
			// A panic on this goroutine would otherwise take the server with it.
			if recover() != nil {
				probe.ok = false
			}
			state.lock.Lock()
			state.current = nil
			state.lock.Unlock()
			close( probe.done )
		}()
		check := state.check
		if check == nil {
			check = handlers.databaseReady
		}
		probe.ok = check()
	}()
	return
}

func ( handlers *Handlers ) databaseReady() ( ok bool ) {
	version , err := handlers.Store.SchemaVersion()
	if err != nil || version != db.LatestSchemaVersion() { return }
	_ , err = models.OwnerID( handlers.Store )
	ok = err == nil
	return
}
