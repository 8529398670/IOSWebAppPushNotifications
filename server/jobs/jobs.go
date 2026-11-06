// Package jobs is the one place background work runs. A job is a name, an
// interval and a function: Register it from main.go and it runs on schedule,
// never overlaps itself, survives a panic, and reports how it went to the
// owner's Jobs screen. See references/architecture.md.
//
// Due times come from the record of the last start, not from a timer that
// began when the process did. A server restarted more often than a job's
// interval therefore still runs the job, and a job that ran a minute before a
// restart does not run again just because the process is new.
package jobs

import (
	errors "errors"
	fmt "fmt"
	log "log"
	sort "sort"
	sync "sync"
	time "time"

	db "ipb/server/db"
	logs "ipb/server/logs"
	models "ipb/server/models"
)

// tick is how often the registry looks for due jobs. It bounds how late a job
// can start, so it only needs to be small against the intervals in use.
const tick = 30 * time.Second

var (
	ErrUnknown = errors.New( "no such job" )
	ErrRunning = errors.New( "job already running" )
)

// Func is one run of a job. note is a short line for the owner saying what the
// run did, which matters for a job that often has nothing to do: "not due" and
// "wrote a backup" both end without an error. A job that did part of its work
// should return both a note and an error.
type Func func() ( note string , err error )

// Status is one row of the Jobs screen.
type Status struct {
	Name            string     `json:"name"`
	IntervalSeconds int        `json:"interval_seconds"`
	Running         bool       `json:"running"`
	Interrupted     bool       `json:"interrupted"`
	Runs            int        `json:"runs"`
	NextDue         time.Time  `json:"next_due"`
	LastStarted     *time.Time `json:"last_started,omitempty"`
	LastFinished    *time.Time `json:"last_finished,omitempty"`
	LastOK          *bool      `json:"last_ok,omitempty"`
	LastNote        string     `json:"last_note,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	// For /metrics, not the screen.
	LastSuccess *time.Time `json:"-"`
	LastFailure *time.Time `json:"-"`
}

type job struct {
	name     string
	interval time.Duration
	run      Func
	running  bool
	record   models.JobRecord
}

// Registry holds the jobs. Register them before Start.
type Registry struct {
	// OnFailure, when set, hears the name of a job whose run failed.
	OnFailure func( name string )

	store  *db.Store
	logger *logs.Logger

	lock    sync.Mutex
	jobs    map[ string ]*job
	stopped bool
	running sync.WaitGroup

	stop chan struct{}
	done chan struct{}
}

func New( store *db.Store , logger *logs.Logger ) ( registry *Registry ) {
	registry = &Registry{
		store:  store,
		logger: logger,
		jobs:   map[ string ]*job{},
		stop:   make( chan struct{} ),
		done:   make( chan struct{} ),
	}
	return
}

// Register adds a job. A record that cannot be read is reported and treated as
// never run, since running a job early is the safer mistake.
func ( registry *Registry ) Register( name string , interval time.Duration , run Func ) {
	record , err := models.LoadJobRecord( registry.store , name )
	if err != nil {
		log.Printf( "[jobs] %s: could not read its record: %v" , name , err )
		record = &models.JobRecord{ Name: name }
	}
	registry.lock.Lock()
	defer registry.lock.Unlock()
	registry.jobs[ name ] = &job{ name: name , interval: interval , run: run , record: *record }
}

// Start runs anything already due, then keeps checking until Stop.
func ( registry *Registry ) Start() {
	go func() {
		defer close( registry.done )
		ticker := time.NewTicker( tick )
		defer ticker.Stop()
		registry.RunDue( time.Now().UTC() )
		for {
			select {
			case <-registry.stop:
				return
			case <-ticker.C:
				registry.RunDue( time.Now().UTC() )
			}
		}
	}()
}

// Stop ends the schedule and waits up to wait for runs in progress. Nothing is
// cancelled: every job has to be safe to lose at any moment anyway, because
// the process can always be killed, so a run still going when the wait ends is
// simply abandoned.
func ( registry *Registry ) Stop( wait time.Duration ) ( finished bool ) {
	registry.lock.Lock()
	already := registry.stopped
	registry.stopped = true
	registry.lock.Unlock()
	if already == false {
		close( registry.stop )
	}
	finished = registry.Wait( wait )
	return
}

// Wait blocks until no job is running, or wait has passed.
func ( registry *Registry ) Wait( wait time.Duration ) ( finished bool ) {
	idle := make( chan struct{} )
	go func() {
		registry.running.Wait()
		close( idle )
	}()
	select {
	case <-idle:
		finished = true
	case <-time.After( wait ):
	}
	return
}

// RunDue starts every job that is due at now, each on its own goroutine, so a
// long backup does not hold the purge up. It returns how many it started.
func ( registry *Registry ) RunDue( now time.Time ) ( started int ) {
	registry.lock.Lock()
	due := []*job{}
	for _ , entry := range registry.jobs {
		if entry.running == false && entry.dueAt( now ) {
			due = append( due , entry )
		}
	}
	registry.lock.Unlock()
	for _ , entry := range due {
		if registry.begin( entry , now ) == nil {
			started += 1
		}
	}
	return
}

// RunNow starts a job whatever its schedule says. It returns as soon as the
// run has begun: a backup can take longer than a request is allowed to.
func ( registry *Registry ) RunNow( name string ) ( err error ) {
	registry.lock.Lock()
	entry , found := registry.jobs[ name ]
	registry.lock.Unlock()
	if found == false {
		err = ErrUnknown
		return
	}
	err = registry.begin( entry , time.Now().UTC() )
	return
}

// Status lists the jobs by name.
func ( registry *Registry ) Status() ( rows []Status ) {
	registry.lock.Lock()
	defer registry.lock.Unlock()
	rows = make( []Status , 0 , len( registry.jobs ) )
	for _ , entry := range registry.jobs {
		rows = append( rows , entry.status() )
	}
	sort.Slice( rows , func( a int , b int ) ( less bool ) {
		less = rows[ a ].Name < rows[ b ].Name
		return
	} )
	return
}

// dueAt says whether the job should run at now. A last start in the future
// means the clock was wrong when it was written, and a job must not sit idle
// until the clock catches up. The caller holds the lock.
func ( entry *job ) dueAt( now time.Time ) ( due bool ) {
	last := entry.record.LastStarted
	due = last == nil || last.After( now ) || now.Sub( *last ) >= entry.interval
	return
}

func ( entry *job ) status() ( row Status ) {
	record := entry.record
	row = Status{
		Name:            entry.name,
		IntervalSeconds: int( entry.interval.Seconds() ),
		Running:         entry.running,
		Runs:            record.Runs,
		NextDue:         time.Now().UTC(),
		LastStarted:     record.LastStarted,
		LastFinished:    record.LastFinished,
		LastOK:          record.LastOK,
		LastNote:        record.LastNote,
		LastError:       record.LastError,
		LastSuccess:     record.LastSuccess,
		LastFailure:     record.LastFailure,
	}
	if record.LastStarted != nil {
		row.NextDue = record.LastStarted.Add( entry.interval )
		unfinished := record.LastFinished == nil || record.LastFinished.Before( *record.LastStarted )
		row.Interrupted = unfinished && entry.running == false
	}
	return
}

// begin claims the job and starts its goroutine. The claim is what stops two
// runs overlapping, whichever of the schedule and the owner asked first.
func ( registry *Registry ) begin( entry *job , started time.Time ) ( err error ) {
	registry.lock.Lock()
	defer registry.lock.Unlock()
	if entry.running || registry.stopped {
		err = ErrRunning
		return
	}
	entry.running = true
	entry.record.LastStarted = &started
	entry.record.Runs += 1
	snapshot := entry.record
	registry.running.Add( 1 )
	go registry.execute( entry , snapshot )
	return
}

func ( registry *Registry ) execute( entry *job , started models.JobRecord ) {
	defer registry.running.Done()
	registry.save( &started )

	note , run_err := call( entry.run )
	finished := time.Now().UTC()
	ok := run_err == nil

	registry.lock.Lock()
	entry.running = false
	entry.record.LastFinished = &finished
	entry.record.LastOK = &ok
	entry.record.LastNote = note
	entry.record.LastError = ""
	if ok {
		entry.record.LastSuccess = &finished
	} else {
		entry.record.LastError = run_err.Error()
		entry.record.LastFailure = &finished
	}
	snapshot := entry.record
	registry.lock.Unlock()

	registry.save( &snapshot )
	if run_err != nil {
		log.Printf( "[jobs] %s failed: %v" , entry.name , run_err )
		registry.logger.System( logs.LevelError , "background job failed" , map[string]any{ "job": entry.name , "error": run_err.Error() } )
		if registry.OnFailure != nil { registry.OnFailure( entry.name ) }
	}
}

// save failing is reported and otherwise ignored. The job's own work matters
// more than its bookkeeping, and the database being gone is about to be
// everyone's problem anyway.
func ( registry *Registry ) save( record *models.JobRecord ) {
	if err := models.SaveJobRecord( registry.store , record ); err != nil {
		log.Printf( "[jobs] %s: could not save its record: %v" , record.Name , err )
	}
}

// call turns a panic into an error, so one bad run costs that run and not the
// whole server.
func call( run Func ) ( note string , err error ) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf( "panic: %v" , recovered )
		}
	}()
	note , err = run()
	return
}
