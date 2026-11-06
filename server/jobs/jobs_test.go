package jobs

import (
	errors "errors"
	filepath "path/filepath"
	sync "sync"
	atomic "sync/atomic"
	testing "testing"
	time "time"

	config "ipb/server/config"
	db "ipb/server/db"
	models "ipb/server/models"
)

const hour = time.Hour

func openStore( t *testing.T , path string ) ( store *db.Store ) {
	t.Helper()
	store , err := db.Open( &config.Config{ DatabasePath: path , SecretKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" } )
	if err != nil { t.Fatal( err ) }
	return
}

func testRegistry( t *testing.T ) ( registry *Registry , store *db.Store ) {
	t.Helper()
	store = openStore( t , filepath.Join( t.TempDir() , "jobs.db" ) )
	t.Cleanup( func() { store.Close() } )
	registry = New( store , nil )
	return
}

func settle( t *testing.T , registry *Registry ) {
	t.Helper()
	if registry.Wait( 5 * time.Second ) == false {
		t.Fatal( "jobs did not finish" )
	}
}

func row( t *testing.T , registry *Registry , name string ) ( found Status ) {
	t.Helper()
	for _ , candidate := range registry.Status() {
		if candidate.Name == name {
			found = candidate
			return
		}
	}
	t.Fatalf( "no status for %s" , name )
	return
}

func TestNeverRunJobIsDueAtOnce( t *testing.T ) {
	registry , _ := testRegistry( t )
	var runs atomic.Int32
	registry.Register( "a" , hour , func() ( note string , err error ) {
		runs.Add( 1 )
		note = "did it"
		return
	} )
	if started := registry.RunDue( time.Now().UTC() ); started != 1 {
		t.Fatalf( "started %d" , started )
	}
	settle( t , registry )
	status := row( t , registry , "a" )
	if runs.Load() != 1 || status.Runs != 1 || status.LastNote != "did it" || status.LastOK == nil || *status.LastOK == false {
		t.Fatalf( "runs %d status %+v" , runs.Load() , status )
	}
	if status.LastSuccess == nil || status.LastFailure != nil {
		t.Fatalf( "success and failure stamps: %+v" , status )
	}
}

func TestNotDueUntilTheIntervalHasPassed( t *testing.T ) {
	registry , _ := testRegistry( t )
	registry.Register( "a" , hour , func() ( note string , err error ) { return } )
	now := time.Now().UTC()
	registry.RunDue( now )
	settle( t , registry )
	if started := registry.RunDue( now.Add( 59 * time.Minute ) ); started != 0 {
		t.Fatal( "ran before it was due" )
	}
	if started := registry.RunDue( now.Add( hour ) ); started != 1 {
		t.Fatal( "did not run when due" )
	}
	settle( t , registry )
}

func TestDueTimeSurvivesARestart( t *testing.T ) {
	path := filepath.Join( t.TempDir() , "jobs.db" )
	store := openStore( t , path )
	first := New( store , nil )
	first.Register( "a" , hour , func() ( note string , err error ) { return } )
	now := time.Now().UTC()
	first.RunDue( now )
	settle( t , first )
	store.Close()

	store = openStore( t , path )
	defer store.Close()
	second := New( store , nil )
	second.Register( "a" , hour , func() ( note string , err error ) {
		t.Error( "ran again after a restart" )
		return
	} )
	if started := second.RunDue( now.Add( time.Minute ) ); started != 0 {
		t.Fatal( "a restart made the job due" )
	}
	if row( t , second , "a" ).Runs != 1 {
		t.Fatal( "the run count did not survive" )
	}
}

func TestClockGoneBackwardsDoesNotStrandAJob( t *testing.T ) {
	registry , _ := testRegistry( t )
	registry.Register( "a" , hour , func() ( note string , err error ) { return } )
	now := time.Now().UTC()
	registry.RunDue( now )
	settle( t , registry )
	if started := registry.RunDue( now.Add( -24 * hour ) ); started != 1 {
		t.Fatal( "a start in the future stranded the job" )
	}
	settle( t , registry )
}

func TestNoOverlap( t *testing.T ) {
	registry , _ := testRegistry( t )
	release := make( chan struct{} )
	var runs atomic.Int32
	registry.Register( "a" , hour , func() ( note string , err error ) {
		runs.Add( 1 )
		<-release
		return
	} )
	now := time.Now().UTC()
	registry.RunDue( now )
	if err := registry.RunNow( "a" ); errors.Is( err , ErrRunning ) == false {
		t.Fatalf( "manual run during a scheduled one: %v" , err )
	}
	if started := registry.RunDue( now.Add( 2 * hour ) ); started != 0 {
		t.Fatal( "the schedule overlapped a run" )
	}
	if row( t , registry , "a" ).Running == false {
		t.Fatal( "not shown as running" )
	}
	close( release )
	settle( t , registry )
	if runs.Load() != 1 {
		t.Fatalf( "ran %d times" , runs.Load() )
	}
}

func TestRunNowUnknown( t *testing.T ) {
	registry , _ := testRegistry( t )
	if err := registry.RunNow( "nope" ); errors.Is( err , ErrUnknown ) == false {
		t.Fatalf( "got %v" , err )
	}
}

func TestPanicIsCapturedAndTheJobRunsAgain( t *testing.T ) {
	registry , _ := testRegistry( t )
	var runs atomic.Int32
	registry.Register( "a" , hour , func() ( note string , err error ) {
		if runs.Add( 1 ) == 1 {
			panic( "boom" )
		}
		return
	} )
	now := time.Now().UTC()
	registry.RunDue( now )
	settle( t , registry )
	status := row( t , registry , "a" )
	if status.LastOK == nil || *status.LastOK || status.LastError != "panic: boom" || status.LastFailure == nil {
		t.Fatalf( "status %+v" , status )
	}
	registry.RunDue( now.Add( hour ) )
	settle( t , registry )
	status = row( t , registry , "a" )
	if status.LastOK == nil || *status.LastOK == false || status.LastError != "" {
		t.Fatalf( "a good run did not clear the failure: %+v" , status )
	}
}

func TestRunDiedPartWayShowsAsInterrupted( t *testing.T ) {
	path := filepath.Join( t.TempDir() , "jobs.db" )
	store := openStore( t , path )
	defer store.Close()
	started := time.Now().UTC()
	// What a run leaves behind if the process dies during it.
	if err := models.SaveJobRecord( store , &models.JobRecord{ Name: "a" , Runs: 1 , LastStarted: &started } ); err != nil {
		t.Fatal( err )
	}
	registry := New( store , nil )
	registry.Register( "a" , hour , func() ( note string , err error ) { return } )
	if row( t , registry , "a" ).Interrupted == false {
		t.Fatal( "not shown as interrupted" )
	}
	if started_now := registry.RunDue( started.Add( time.Minute ) ); started_now != 0 {
		t.Fatal( "a run that died ran again on boot" )
	}
}

func TestStopWaitsForARunAndGivesUpOnAStuckOne( t *testing.T ) {
	registry , _ := testRegistry( t )
	release := make( chan struct{} )
	var once sync.Once
	registry.Register( "a" , hour , func() ( note string , err error ) {
		<-release
		return
	} )
	registry.RunDue( time.Now().UTC() )
	if registry.Stop( 20 * time.Millisecond ) {
		t.Fatal( "Stop claimed a stuck run finished" )
	}
	once.Do( func() { close( release ) } )
	if registry.Stop( 5 * time.Second ) == false {
		t.Fatal( "Stop did not see the run finish" )
	}
	if err := registry.RunNow( "a" ); err == nil {
		t.Fatal( "a stopped registry started a run" )
	}
}
