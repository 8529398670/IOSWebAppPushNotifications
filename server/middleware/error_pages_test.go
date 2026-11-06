package middleware

import (
	errors "errors"
	io "io"
	http "net/http"
	strings "strings"
	testing "testing"
	fstest "testing/fstest"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
	errorpage "ipb/server/errorpage"
	language "ipb/server/language"
	static "ipb/server/static"
)

const testLanguage = `
error_page:
  home: "Home"
  not_found_title: "Page <not> found"
  not_found_message: "Gone."
  rate_limited_title: "Slow down"
  rate_limited_message: "Wait."
  server_error_title: "Broken"
  server_error_message: "Sorry."
  reference: "Reference: {reference}"
`

func errorPageApp( t *testing.T , rate_limit int ) ( app *fiber.App ) {
	t.Helper()
	lang , err := language.Parse( []byte( testLanguage ) )
	if err != nil { t.Fatal( err ) }
	pages := errorpage.New( lang )
	server , err := static.New( fstest.MapFS{
		"index.html":  { Data: []byte( "the index" ) },
		"css/app.css": { Data: []byte( "body{}" ) },
	} )
	if err != nil { t.Fatal( err ) }
	server.NotFound = pages.NotFound( server.NotFound )

	settings := config.NewStaticHolder( &config.Config{ RateLimitMax: rate_limit , RateLimitSignInMax: rate_limit , RateLimitWindow: time.Minute } )
	app = fiber.New( fiber.Config{ ErrorHandler: NewErrorHandler( pages ) } )
	app.Use( RequestID() )
	app.Use( Recover( settings ) )
	app.Use( SecurityHeaders( settings ) )
	app.Use( RateLimit( settings ) )
	app.Get( "/boom" , func( fiber.Ctx ) error { return errors.New( "the disk is on fire" ) } )
	app.Get( "/login/*" , server.ServeIndex )
	app.Get( "/*" , server.Handler )
	return
}

func fetch( t *testing.T , app *fiber.App , target string , accept string ) ( response *http.Response , body string ) {
	t.Helper()
	request , _ := http.NewRequest( http.MethodGet , target , nil )
	if accept != "" {
		request.Header.Set( "Accept" , accept )
	}
	response , err := app.Test( request , fiber.TestConfig{ Timeout: 5 * time.Second } )
	if err != nil { t.Fatal( err ) }
	raw , _ := io.ReadAll( response.Body )
	body = string( raw )
	return
}

const browserAccept = "text/html,application/xhtml+xml,*/*;q=0.8"

func TestABrowserGetsTheNotFoundPage( t *testing.T ) {
	app := errorPageApp( t , 100 )
	for _ , target := range []string{ "/settings" , "/nope.css" , "/a/b/" } {
		response , body := fetch( t , app , target , browserAccept )
		if response.StatusCode != 404 || strings.HasPrefix( response.Header.Get( "Content-Type" ) , "text/html" ) == false {
			t.Fatalf( "%s: %d %s" , target , response.StatusCode , response.Header.Get( "Content-Type" ) )
		}
		if strings.Contains( body , "Page &lt;not&gt; found" ) == false {
			t.Fatalf( "%s: text missing or unescaped: %s" , target , body )
		}
		if response.Header.Get( "Content-Security-Policy" ) == "" || response.Header.Get( "Cache-Control" ) != "no-store" {
			t.Fatalf( "%s: headers: %v" , target , response.Header )
		}
	}
}

func TestAScriptKeepsThePlainNotFound( t *testing.T ) {
	app := errorPageApp( t , 100 )
	for _ , accept := range []string{ "" , "*/*" , "text/css" } {
		response , body := fetch( t , app , "/nope.css" , accept )
		if response.StatusCode != 404 || body != "Not found" {
			t.Fatalf( "accept %q: %d %q" , accept , response.StatusCode , body )
		}
	}
}

func TestTheAppPagesStillServe( t *testing.T ) {
	app := errorPageApp( t , 100 )
	for _ , target := range []string{ "/" , "/login/some-credential" , "/index.html" } {
		response , body := fetch( t , app , target , browserAccept )
		if response.StatusCode != 200 || body != "the index" {
			t.Fatalf( "%s: %d %q" , target , response.StatusCode , body )
		}
	}
	if response , body := fetch( t , app , "/css/app.css" , "text/css" ); response.StatusCode != 200 || body != "body{}" {
		t.Fatalf( "%d %q" , response.StatusCode , body )
	}
}

func TestACrashShowsAReferenceAndNoDetail( t *testing.T ) {
	app := errorPageApp( t , 100 )
	response , body := fetch( t , app , "/boom" , browserAccept )
	id := response.Header.Get( "X-Request-ID" )
	if response.StatusCode != 500 || id == "" || strings.Contains( body , "Reference: "+id ) == false {
		t.Fatalf( "%d %s: %s" , response.StatusCode , id , body )
	}
	if strings.Contains( body , "fire" ) {
		t.Fatal( "the cause reached the client" )
	}
	if response , body = fetch( t , app , "/boom" , "application/json" ); strings.Contains( body , `"request_id"` ) == false {
		t.Fatalf( "%d %s" , response.StatusCode , body )
	}
}

func TestRateLimitedAnswers( t *testing.T ) {
	app := errorPageApp( t , 1 )
	fetch( t , app , "/" , browserAccept )
	response , body := fetch( t , app , "/" , browserAccept )
	if response.StatusCode != 429 || strings.Contains( body , "Slow down" ) == false {
		t.Fatalf( "a browser: %d %s" , response.StatusCode , body )
	}
	if response.Header.Get( "Retry-After" ) == "" {
		t.Fatal( "no Retry-After" )
	}
	response , body = fetch( t , app , "/api/me" , browserAccept )
	if response.StatusCode != 429 || strings.Contains( body , `"too many requests"` ) == false {
		t.Fatalf( "the API stays JSON: %d %s" , response.StatusCode , body )
	}
}

func TestSearchEnginesAreToldToStayOut( t *testing.T ) {
	app := errorPageApp( t , 100 )
	for _ , target := range []string{ "/" , "/nope" , "/boom" } {
		response , _ := fetch( t , app , target , browserAccept )
		if got := response.Header.Get( "X-Robots-Tag" ); got != robotsPolicy {
			t.Fatalf( "%s: X-Robots-Tag %q" , target , got )
		}
	}
}
