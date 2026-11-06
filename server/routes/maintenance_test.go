package routes

import (
	io "io"
	http "net/http"
	strings "strings"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
	errorpage "ipb/server/errorpage"
	language "ipb/server/language"
	models "ipb/server/models"
)

func testErrorPages( t *testing.T ) ( pages *errorpage.Pages ) {
	t.Helper()
	lang , err := language.Parse( []byte( "error_page:\n  home: \"Home\"\n  maintenance_title: \"Down for maintenance\"\n  maintenance_message: \"Soon.\"\n" ) )
	if err != nil { t.Fatal( err ) }
	pages = errorpage.New( lang )
	return
}

func keyGet( t *testing.T , fixture *authFixture , key string , path string ) ( response *http.Response ) {
	t.Helper()
	request , _ := http.NewRequest( http.MethodGet , path , nil )
	request.Header.Set( "Authorization" , "Bearer " + key )
	response , err := fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
	if err != nil { t.Fatal( err ) }
	return
}

func TestFullMaintenanceLeavesOnlyTheOwnersSession( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	owner_key , _ , err := models.IssueAPIKey( fixture.store , fixture.owner.ID , "script" , models.RoleAdmin , time.Hour )
	if err != nil { t.Fatal( err ) }
	fixture.cfg.Maintenance = config.MaintenanceFull

	if status , reply := owner.do( t , http.MethodGet , "/api/team" , nil ); status != fiber.StatusOK {
		t.Fatalf( "the owner was refused: %d %v" , status , reply )
	}
	status , reply := alice.do( t , http.MethodGet , "/api/team" , nil )
	if status != fiber.StatusServiceUnavailable || reply[ "maintenance" ] != "full" {
		t.Fatalf( "%d %v" , status , reply )
	}
	// The owner's key is not the owner's session.
	response := keyGet( t , fixture , owner_key , "/api/team" )
	if response.StatusCode != fiber.StatusServiceUnavailable {
		t.Fatalf( "status %d" , response.StatusCode )
	}
	if response.Header.Get( "Retry-After" ) == "" { t.Fatal( "no Retry-After" ) }

	// Still able to find out why.
	if status , reply = alice.do( t , http.MethodGet , "/api/me" , nil ); status != fiber.StatusOK || reply[ "maintenance" ] != "full" {
		t.Fatalf( "%d %v" , status , reply )
	}
}

func TestReadOnlyMaintenanceRefusesWritesButNotReads( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	fixture.cfg.Maintenance = config.MaintenanceReadOnly

	if status , reply := alice.do( t , http.MethodGet , "/api/team" , nil ); status != fiber.StatusOK {
		t.Fatalf( "%d %v" , status , reply )
	}
	if status , reply := send( t , alice , "/api/account/rename" , fiber.Map{ "display_name": "Al" } ); status != fiber.StatusServiceUnavailable {
		t.Fatalf( "%d %v" , status , reply )
	}
	if status , reply := send( t , owner , "/api/account/rename" , fiber.Map{ "display_name": "Boss" } ); status != fiber.StatusOK {
		t.Fatalf( "the owner was refused: %d %v" , status , reply )
	}
}

func TestMaintenanceAppliesWithoutARestart( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	for _ , step := range []struct {
		mode   string
		status int
	}{
		{ config.MaintenanceNone , fiber.StatusOK },
		{ config.MaintenanceFull , fiber.StatusServiceUnavailable },
		{ config.MaintenanceNone , fiber.StatusOK },
	} {
		fixture.cfg.Maintenance = step.mode
		if status , _ := alice.do( t , http.MethodGet , "/api/team" , nil ); status != step.status {
			t.Fatalf( "%s: status %d" , step.mode , status )
		}
	}
}

func TestSigningInStillWorksDuringMaintenance( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.cfg.Maintenance = config.MaintenanceFull
	owner := fixture.signIn( t , fixture.owner.ID )
	if status , reply := owner.do( t , http.MethodGet , "/api/team" , nil ); status != fiber.StatusOK {
		t.Fatalf( "%d %v" , status , reply )
	}
}

func TestABrowserGetsThePageNotJSON( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.cfg.Maintenance = config.MaintenanceFull
	fixture.handlers.ErrorPages = testErrorPages( t )
	request , _ := http.NewRequest( http.MethodGet , "/" , nil )
	request.Header.Set( "Accept" , "text/html" )
	response , err := fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
	if err != nil { t.Fatal( err ) }
	raw , _ := io.ReadAll( response.Body )
	if response.StatusCode != fiber.StatusServiceUnavailable || strings.Contains( string( raw ) , "Down for maintenance" ) == false {
		t.Fatalf( "%d %s" , response.StatusCode , raw )
	}
}
