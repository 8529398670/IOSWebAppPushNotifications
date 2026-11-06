package routes

import (
	json "encoding/json"
	http "net/http"
	os "os"
	regexp "regexp"
	sort "sort"
	strings "strings"
	testing "testing"

	fiber "github.com/gofiber/fiber/v3"
)

// notInTheSpec is what the route table has that is not an API: the pages a
// link opens, and the catch-alls.
var notInTheSpec = map[string]bool{
	"GET /login/*": true,
	"GET /i/{credential}": true,
	"GET /manifest.webmanifest": true,
	"GET /login/manifest.webmanifest": true,
	"GET /join/manifest.webmanifest": true,
	"GET /i/{credential}/manifest.webmanifest": true,
	"GET /join/*":  true,
	"GET /api/*":   true,
	"GET /*":       true,
}

func specFile( t *testing.T ) ( raw []byte ) {
	t.Helper()
	raw , err := os.ReadFile( "../../config/openapi.json" )
	if err != nil { t.Fatal( err ) }
	return
}

// specRoutes is every "METHOD /path" the spec lists.
func specRoutes( t *testing.T ) ( routes map[string]bool ) {
	t.Helper()
	var document struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal( specFile( t ) , &document ); err != nil { t.Fatal( err ) }
	routes = map[string]bool{}
	for path , methods := range document.Paths {
		for method := range methods {
			routes[ strings.ToUpper( method ) + " " + path ] = true
		}
	}
	return
}

// A new route that is not in config/openapi.json fails here, and so does an
// entry for a route that has gone. Logging is on because the log routes are
// only registered then.
func TestTheSpecAndTheRouteTableAgree( t *testing.T ) {
	fixture := newMonitored( t , true )
	parameter := regexp.MustCompile( `:(\w+)` )
	registered := map[string]bool{}
	for _ , route := range fixture.app.GetRoutes( true ) {
		if route.Method != http.MethodGet && route.Method != http.MethodPost && route.Method != http.MethodDelete { continue }
		if route.Path == "/fail" || route.Path == "/panic" { continue } // newMonitored's own
		name := route.Method + " " + parameter.ReplaceAllString( route.Path , "{$1}" )
		if notInTheSpec[ name ] == false {
			registered[ name ] = true
		}
	}
	spec := specRoutes( t )
	problems := []string{}
	for name := range registered {
		if spec[ name ] == false { problems = append( problems , "not in config/openapi.json: " + name ) }
	}
	for name := range spec {
		if registered[ name ] == false { problems = append( problems , "in config/openapi.json but not a route: " + name ) }
	}
	sort.Strings( problems )
	if len( problems ) > 0 {
		t.Fatal( strings.Join( problems , "\n" ) )
	}
}

func TestTheSpecIsForSignedInCallers( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.handlers.OpenAPI = specFile( t )
	stranger := fixture.browser()
	if status , _ := stranger.do( t , http.MethodGet , "/api/openapi.json" , nil ); status != fiber.StatusUnauthorized {
		t.Fatalf( "status %d" , status )
	}
	alice := fixture.signIn( t , fixture.alice.ID )
	status , reply := alice.do( t , http.MethodGet , "/api/openapi.json" , nil )
	if status != fiber.StatusOK || reply[ "openapi" ] != "3.1.0" {
		t.Fatalf( "%d %v" , status , reply )
	}
}
