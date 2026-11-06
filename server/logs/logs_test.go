package logs

import (
	bytes "bytes"
	os "os"
	filepath "path/filepath"
	strings "strings"
	testing "testing"
	time "time"
	unsafe "unsafe"

	config "ipb/server/config"
	encryption "ipb/server/encryption"
)

// What these pin down: nothing secret reaches a line, an encrypted line reads
// back, a day rotates into parts and pages back newest first across them,
// retention and recycling delete the right days and never today, a gzipped
// day still reads, and the search grammar means what the Logs screen says.

func testLogger( t *testing.T , encrypt bool ) ( logger *Logger ) {
	t.Helper()
	logger = New( config.LogsConfig{
		Enabled:           true,
		Dir:               t.TempDir(),
		RetentionDays:     30,
		MaxTotalBytes:     500 * 1024 * 1024,
		MaxFileBytes:      50 * 1024 * 1024,
		CompressAfterDays: 1,
	} , encryption.GenerateKeyHex() , encrypt )
	return
}

// writeNow writes straight through the writer, skipping the queue, so a test
// can read what it wrote at once.
func writeNow( logger *Logger , entries ...Entry ) {
	for _ , entry := range entries {
		if entry.TS.IsZero() { entry.TS = logger.now().UTC() }
		if entry.Level == "" { entry.Level = LevelInfo }
		logger.write( entry )
	}
	logger.flush()
}

func request( path string , status int ) ( entry Entry ) {
	entry = Entry{ Kind: KindRequest , Request: &Request{ Method: "GET" , Path: path , Status: status } }
	return
}

func TestRedact( t *testing.T ) {
	cases := map[string][2]string{
		"/login/abc.def":     { "" , "/login/…" },
		"/join/xyz":          { "" , "/join/…" },
		"/api/me":            { "" , "/api/me" },
		"/api/thing":         { "token=s3cret&page=2" , "/api/thing?page=2&token=%E2%80%A6" },
		"/login/":            { "" , "/login/" },
		"/i/abc.def/":                     { "" , "/i/…" },
		"/i/abc.def/manifest.webmanifest": { "" , "/i/…" },
		"/":                               { "credential=abc.def" , "/?credential=%E2%80%A6" },
	}
	for path , want := range cases {
		if got := Redact( path , want[ 0 ] ); got != want[ 1 ] {
			t.Errorf( "Redact(%q, %q) = %q, want %q" , path , want[ 0 ] , got , want[ 1 ] )
		}
	}
	if got := Redact( "/"+strings.Repeat( "a" , 1000 ) , "" ); len( got ) > maxPathLength + 4 {
		t.Errorf( "a long path was not capped: %d bytes" , len( got ) )
	}
}

// A line is written after its request has ended. Fiber hands out strings that
// view the request's buffer and reuses it for the next request, so an entry that
// kept them could log another request's bytes, headers and all.
func TestAnEntryOwnsItsStrings( t *testing.T ) {
	logger := testLogger( t , false )
	buffer := []byte( "request" )
	view := unsafe.String( &buffer[ 0 ] , len( buffer ) )
	logger.Log( Entry{
		Kind: KindAdmin , RequestID: view , IP: view , UA: view , Msg: view ,
		Request: &Request{ Method: view , Path: view , Referer: view },
		Detail: map[string]any{ "link_id": view , "count": 1 },
	} )
	copy( buffer , "another" )

	entry := <-logger.queue
	got := []any{ entry.RequestID , entry.IP , entry.UA , entry.Msg ,
		entry.Request.Method , entry.Request.Path , entry.Request.Referer , entry.Detail[ "link_id" ] }
	for index , value := range got {
		if value != "request" { t.Errorf( "field %d reads %q" , index , value ) }
	}
	if entry.Detail[ "count" ] != 1 { t.Errorf( "%v" , entry.Detail ) }
}

func TestEncryptedLinesReadBack( t *testing.T ) {
	logger := testLogger( t , true )
	writeNow( logger , request( "/api/secret-looking-path" , 200 ) )

	raw , err := os.ReadFile( filepath.Join( logger.Settings().Dir , partName( logger.today() , 0 , false ) ) )
	if err != nil { t.Fatal( err ) }
	if bytes.Contains( raw , []byte( "secret-looking-path" ) ) {
		t.Fatal( "an encrypted log line has its path in plain text" )
	}
	records , _ , err := logger.ReadDay( logger.today() , Query{} , -1 , 10 )
	if err != nil { t.Fatal( err ) }
	if len( records ) != 1 || records[ 0 ].Request.Path != "/api/secret-looking-path" {
		t.Fatalf( "read back %+v" , records )
	}

	// The same files read under another key give nothing, not garbage.
	other := testLogger( t , true )
	other.settings.Store( ptr( logger.Settings() ) )
	if records , _ , _ := other.ReadDay( logger.today() , Query{} , -1 , 10 ); len( records ) != 0 {
		t.Fatal( "a different key read the log" )
	}
}

func TestRotationAndPaging( t *testing.T ) {
	logger := testLogger( t , false )
	change( logger , func( settings *config.LogsConfig ) { settings.MaxFileBytes = 400 } )
	for index := 0; index < 30; index += 1 {
		writeNow( logger , request( "/api/item/"+strings.Repeat( "x" , index % 3 ) , 200 + index ) )
	}
	parts , _ := logger.dayFiles( logger.today() )
	if len( parts ) < 3 {
		t.Fatalf( "expected the day to rotate into several parts, got %d" , len( parts ) )
	}
	for _ , part := range parts {
		if part.size > 400 { t.Errorf( "part %d is %d bytes, over the cap" , part.part , part.size ) }
	}

	seen := []int{}
	before := -1
	for {
		records , next , err := logger.ReadDay( logger.today() , Query{} , before , 7 )
		if err != nil { t.Fatal( err ) }
		for _ , record := range records {
			seen = append( seen , record.Request.Status )
		}
		if next == nil { break }
		before = *next
	}
	if len( seen ) != 30 {
		t.Fatalf( "paged through %d entries, want 30" , len( seen ) )
	}
	for index , status := range seen {
		if status != 229 - index {
			t.Fatalf( "entry %d is status %d: not newest first" , index , status )
		}
	}
}

func TestPrune( t *testing.T ) {
	logger := testLogger( t , false )
	fixed := time.Date( 2026 , 11 , 2 , 12 , 0 , 0 , 0 , time.UTC )
	logger.now = func() time.Time { return fixed }
	change( logger , func( settings *config.LogsConfig ) { settings.RetentionDays = 5 } )
	change( logger , func( settings *config.LogsConfig ) { settings.CompressAfterDays = 2 } )

	for _ , days_ago := range []int{ 0 , 1 , 2 , 3 , 9 } {
		entry := request( "/api/day" , 200 )
		entry.TS = fixed.AddDate( 0 , 0 , -days_ago )
		writeNow( logger , entry )
	}
	result , err := logger.Prune()
	if err != nil { t.Fatal( err ) }
	if result.Deleted != 1 || result.Compressed != 2 {
		t.Fatalf( "prune: %+v, want 1 deleted (9 days old) and 2 compressed (2 and 3 days old)" , result )
	}
	by_day , _ := logger.files()
	if _ , found := by_day[ "2026-10-24" ]; found {
		t.Fatal( "a day past retention survived" )
	}
	compressed := by_day[ "2026-10-31" ]
	if len( compressed ) != 1 || compressed[ 0 ].compressed == false {
		t.Fatalf( "2 days old should be gzipped: %+v" , compressed )
	}
	if records , _ , _ := logger.ReadDay( "2026-10-31" , Query{} , -1 , 10 ); len( records ) != 1 {
		t.Fatal( "a gzipped day does not read back" )
	}

	// Recycling: a cap below what is there removes the oldest days, never
	// today.
	change( logger , func( settings *config.LogsConfig ) { settings.MaxTotalBytes = 1 } )
	result , err = logger.Prune()
	if err != nil { t.Fatal( err ) }
	by_day , _ = logger.files()
	if len( by_day ) != 1 || by_day[ "2026-11-02" ] == nil {
		t.Fatalf( "recycling should leave only today, left %v" , by_day )
	}
	if err := logger.DeleteDay( "2026-11-02" ); err != ErrToday {
		t.Fatalf( "deleting today: %v, want ErrToday" , err )
	}
}

func TestQuery( t *testing.T ) {
	failing := request( "/api/admin/users" , 503 )
	failing.Actor = &Actor{ UserID: 7 , Name: "Ana Lopez" , Method: "session" }
	failing.IP = "10.0.0.5"
	click := Entry{ Kind: KindUI , UI: &UI{ Action: "click" , Screen: "users" , Target: "admin.create_button" } }

	cases := []struct {
		query string
		entry Entry
		want  bool
	}{
		{ "status:5xx" , failing , true },
		{ "status:4xx" , failing , false },
		{ "status:503" , failing , true },
		{ "user:ana" , failing , true },
		{ "user:7" , failing , true },
		{ "user:bob" , failing , false },
		{ "path:/api/admin" , failing , true },
		{ "ip:10.0." , failing , true },
		{ "kind:ui,auth" , failing , false },
		{ "kind:ui,auth" , click , true },
		{ "-kind:request" , failing , false },
		{ "-kind:request" , click , true },
		{ "action:click screen:users" , click , true },
		{ "create_button" , click , true },
		{ "\"ana lopez\"" , failing , true },
		{ "users -status:5xx" , failing , false },
		{ "nonsense:thing" , click , false },
	}
	logger := testLogger( t , false )
	for _ , item := range cases {
		line , _ := logger.encode( item.entry )
		if got := ParseQuery( item.query ).Match( &item.entry , bytes.ToLower( line ) ); got != item.want {
			t.Errorf( "%q on %s: got %v, want %v" , item.query , line , got , item.want )
		}
	}
}

func TestQueueNeverBlocks( t *testing.T ) {
	logger := testLogger( t , false )
	// Not started: nothing drains the queue, so it fills and then drops.
	for index := 0; index < queueSize + 5; index += 1 {
		logger.Log( request( "/" , 200 ) )
	}
	if logger.Dropped() != 5 {
		t.Fatalf( "dropped %d, want 5" , logger.Dropped() )
	}
}

func ptr( settings config.LogsConfig ) ( result *config.LogsConfig ) {
	result = &settings
	return
}

// change edits a logger's settings in place, for a test.
func change( logger *Logger , edit func( settings *config.LogsConfig ) ) {
	settings := logger.Settings()
	edit( &settings )
	logger.settings.Store( &settings )
}
