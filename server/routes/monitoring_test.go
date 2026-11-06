package routes

import (
	errors "errors"
	fmt "fmt"
	io "io"
	http "net/http"
	os "os"
	filepath "path/filepath"
	regexp "regexp"
	strings "strings"
	atomic "sync/atomic"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
	logs "ipb/server/logs"
	metrics "ipb/server/metrics"
	middleware "ipb/server/middleware"
	models "ipb/server/models"
)

// monitored is the app the way main.go builds it, with the middleware and
// error handler the plain fixtures leave out, plus routes that fail on demand.
type monitored struct {
	*authFixture
	app      *fiber.App
	logDir   string
	logger   *logs.Logger
	adminKey string
	userKey  string
}

func newMonitored( t *testing.T , logging bool ) ( fixture *monitored ) {
	t.Helper()
	base := newAuthFixture( t )
	base.cfg.MetricsEnabled = true
	dir := t.TempDir()
	logger := logs.New( config.LogsConfig{ Enabled: logging , Dir: dir , RetentionDays: 7 , MaxTotalBytes: 1 << 20 , MaxFileBytes: 1 << 20 } , base.cfg.SecretKey , false )
	logger.Start()
	settings := config.NewStaticHolder( base.cfg )
	handlers := base.handlers
	handlers.Logs = logger
	handlers.Metrics = metrics.New()

	app := fiber.New( fiber.Config{ ErrorHandler: middleware.NewErrorHandler( nil ) } )
	app.Use( middleware.RequestID() )
	app.Use( middleware.Metrics( handlers.Metrics ) )
	app.Use( middleware.Recover( settings ) )
	app.Use( middleware.RequestLog( logger ) )
	app.Get( "/fail" , func( c fiber.Ctx ) ( err error ) {
		err = serverError( c , errors.New( "the disk is on fire" ) )
		return
	} )
	app.Get( "/panic" , func( c fiber.Ctx ) ( err error ) {
		panic( "the wheels came off" )
	} )
	handlers.Register( app )

	admin_key , _ , err := models.IssueAPIKey( base.store , base.owner.ID , "scraper" , models.RoleAdmin , time.Hour )
	if err != nil { t.Fatal( err ) }
	user_key , _ , err := models.IssueAPIKey( base.store , base.alice.ID , "script" , models.RoleUser , time.Hour )
	if err != nil { t.Fatal( err ) }
	fixture = &monitored{ authFixture: base , app: app , logDir: dir , logger: logger , adminKey: admin_key , userKey: user_key }
	base.app = app
	return
}

func ( fixture *monitored ) get( t *testing.T , path string , headers map[ string ]string ) ( response *http.Response , body string ) {
	t.Helper()
	request , _ := http.NewRequest( http.MethodGet , path , nil )
	for name , value := range headers {
		request.Header.Set( name , value )
	}
	response , err := fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
	if err != nil { t.Fatal( err ) }
	raw , _ := io.ReadAll( response.Body )
	body = string( raw )
	return
}

func bearer( key string ) ( headers map[ string ]string ) {
	headers = map[ string ]string{ "Authorization": "Bearer " + key }
	return
}

var requestIDShape = regexp.MustCompile( `^[0-9a-f]{16}$` )

func TestEveryResponseCarriesAFreshRequestID( t *testing.T ) {
	fixture := newMonitored( t , false )
	first , _ := fixture.get( t , "/api/health" , map[ string ]string{ "X-Request-ID": "chosen-by-caller" } )
	second , _ := fixture.get( t , "/api/health" , nil )
	one , two := first.Header.Get( "X-Request-ID" ) , second.Header.Get( "X-Request-ID" )
	if requestIDShape.MatchString( one ) == false || requestIDShape.MatchString( two ) == false || one == two {
		t.Fatalf( "%q %q" , one , two )
	}
}

func TestAFailureCanBeMatchedToItsLogLine( t *testing.T ) {
	for path , cause := range map[ string ]string{ "/fail": "the disk is on fire" , "/panic": "the wheels came off" } {
		fixture := newMonitored( t , true )
		response , body := fixture.get( t , path , nil )
		id := response.Header.Get( "X-Request-ID" )
		if response.StatusCode != http.StatusInternalServerError {
			t.Fatalf( "%s: status %d" , path , response.StatusCode )
		}
		if strings.Contains( body , cause ) {
			t.Fatalf( "%s: the cause reached the client: %s" , path , body )
		}
		if strings.Contains( body , fmt.Sprintf( `"request_id":"%s"` , id ) ) == false {
			t.Fatalf( "%s: no reference in the body: %s" , path , body )
		}
		fixture.logger.Close()
		files , _ := filepath.Glob( filepath.Join( fixture.logDir , "*.jsonl" ) )
		matched := false
		for _ , file := range files {
			raw , _ := os.ReadFile( file )
			for _ , line := range strings.Split( string( raw ) , "\n" ) {
				if strings.Contains( line , id ) && strings.Contains( line , cause ) {
					matched = true
				}
			}
		}
		if matched == false {
			t.Fatalf( "%s: no log line has both %s and the cause" , path , id )
		}
	}
}

func TestLogsOffStillGivesIDsAndMetrics( t *testing.T ) {
	fixture := newMonitored( t , false )
	response , body := fixture.get( t , "/fail" , nil )
	if requestIDShape.MatchString( response.Header.Get( "X-Request-ID" ) ) == false || strings.Contains( body , "request_id" ) == false {
		t.Fatalf( "%v %s" , response.Header , body )
	}
	_ , scrape := fixture.get( t , "/metrics" , bearer( fixture.adminKey ) )
	if strings.Contains( scrape , `app_http_requests_total{method="GET",status_class="5xx"} 1` ) == false {
		t.Fatalf( "the failure was not counted:\n%s" , scrape )
	}
}

func TestReadyAnswersOnlyYesOrNo( t *testing.T ) {
	fixture := newMonitored( t , false )
	response , body := fixture.get( t , "/api/ready" , nil )
	if response.StatusCode != http.StatusOK || body != `{"ok":true}` {
		t.Fatalf( "%d %s" , response.StatusCode , body )
	}
	fixture.handlers.readiness.check = func() bool { return false }
	response , body = fixture.get( t , "/api/ready" , nil )
	if response.StatusCode != http.StatusServiceUnavailable || body != `{"ok":false}` {
		t.Fatalf( "%d %s" , response.StatusCode , body )
	}
}

func TestReadySaysNoOnABrokenDatabaseAndShrugsOffAPanic( t *testing.T ) {
	fixture := newMonitored( t , false )
	fixture.store.Close()
	if response , _ := fixture.get( t , "/api/ready" , nil ); response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf( "closed database: %d" , response.StatusCode )
	}
	fixture.handlers.readiness.check = func() bool { panic( "boom" ) }
	if response , _ := fixture.get( t , "/api/ready" , nil ); response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf( "panic: %d" , response.StatusCode )
	}
}

func TestReadyGivesUpOnAStuckDatabaseAndSharesTheProbe( t *testing.T ) {
	fixture := newMonitored( t , false )
	release := make( chan struct{} )
	var calls atomic.Int32
	fixture.handlers.readiness.check = func() bool {
		calls.Add( 1 )
		<-release
		return true
	}
	started := time.Now()
	response , body := fixture.get( t , "/api/ready" , nil )
	if response.StatusCode != http.StatusServiceUnavailable || body != `{"ok":false}` {
		t.Fatalf( "%d %s" , response.StatusCode , body )
	}
	if elapsed := time.Since( started ); elapsed < readyWait || elapsed > readyWait + 2 * time.Second {
		t.Fatalf( "took %v" , elapsed )
	}
	fixture.get( t , "/api/ready" , nil )
	close( release )
	if calls.Load() != 1 {
		t.Fatalf( "%d probes ran at once" , calls.Load() )
	}
}

func TestMetricsAccess( t *testing.T ) {
	fixture := newMonitored( t , false )
	owner := fixture.signIn( t , fixture.owner.ID )

	if response , _ := fixture.get( t , "/metrics" , nil ); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf( "anonymous: %d" , response.StatusCode )
	}
	if response , _ := fixture.get( t , "/metrics" , map[ string ]string{ "Cookie": owner.cookie } ); response.StatusCode != http.StatusForbidden {
		t.Fatalf( "a browser session: %d" , response.StatusCode )
	}
	if response , _ := fixture.get( t , "/metrics" , bearer( fixture.userKey ) ); response.StatusCode != http.StatusForbidden {
		t.Fatalf( "a user key: %d" , response.StatusCode )
	}
	response , _ := fixture.get( t , "/metrics" , bearer( fixture.adminKey ) )
	if response.StatusCode != http.StatusOK || response.Header.Get( "Content-Type" ) != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf( "an admin key: %d %s" , response.StatusCode , response.Header.Get( "Content-Type" ) )
	}

	fixture.cfg.APIKeysEnabled = false
	if response , _ = fixture.get( t , "/metrics" , bearer( fixture.adminKey ) ); response.StatusCode != http.StatusNotFound {
		t.Fatalf( "keys off: %d" , response.StatusCode )
	}
	fixture.cfg.APIKeysEnabled = true
	fixture.cfg.MetricsEnabled = false
	if response , _ = fixture.get( t , "/metrics" , bearer( fixture.adminKey ) ); response.StatusCode != http.StatusNotFound {
		t.Fatalf( "metrics off: %d" , response.StatusCode )
	}
}

var sampleLine = regexp.MustCompile( `^[a-z_]+(\{[a-z_]+="[^"]*"(,[a-z_]+="[^"]*")*\})? [0-9.e+-]+$` )

func TestMetricsFormatAndNoPathLabels( t *testing.T ) {
	fixture := newMonitored( t , false )
	fixture.get( t , "/api/health" , nil )
	fixture.get( t , "/some/secret/looking/path" , nil )
	request , _ := http.NewRequest( http.MethodTrace , "/api/health" , nil )
	fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
	_ , scrape := fixture.get( t , "/metrics" , bearer( fixture.adminKey ) )

	for _ , family := range []string{
		"app_http_requests_total" , "app_http_request_duration_seconds" , "app_http_requests_in_flight" , "app_uptime_seconds" ,
		"app_logs_dropped_total" , "app_job_last_success_timestamp_seconds" , "app_job_last_failure_timestamp_seconds" ,
	} {
		if strings.Contains( scrape , "# TYPE "+family+" " ) == false || strings.Contains( scrape , "# HELP "+family+" " ) == false {
			t.Fatalf( "%s has no HELP or TYPE:\n%s" , family , scrape )
		}
	}
	for _ , line := range strings.Split( strings.TrimSpace( scrape ) , "\n" ) {
		if strings.HasPrefix( line , "#" ) { continue }
		if sampleLine.MatchString( line ) == false && strings.Contains( line , `le="+Inf"` ) == false {
			t.Fatalf( "not a valid sample: %q" , line )
		}
	}
	if strings.Contains( scrape , "secret" ) || strings.Contains( scrape , "TRACE" ) {
		t.Fatalf( "a path or an unlisted method became a label:\n%s" , scrape )
	}
	if strings.Contains( scrape , `method="OTHER"` ) == false {
		t.Fatalf( "an unknown method was not folded into OTHER:\n%s" , scrape )
	}
}
