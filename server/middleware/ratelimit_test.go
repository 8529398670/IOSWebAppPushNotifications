package middleware

import (
	http "net/http"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
)

// What these pin down: a page's files never spend the budget, the two budgets
// are separate, and no spelling of a path gets around either.

func limitedApp( general int , sign_in int ) ( app *fiber.App ) {
	settings := config.NewHolder( &config.Config{ RateLimitMax: general , RateLimitSignInMax: sign_in , RateLimitUploadMax: 3 , RateLimitWindow: time.Minute } )
	app = fiber.New()
	app.Use( RateLimit( settings ) )
	app.All( "/*" , func( c fiber.Ctx ) ( err error ) {
		err = c.SendString( "ok" )
		return
	} )
	return
}

func status( t *testing.T , app *fiber.App , method string , target string ) ( code int ) {
	t.Helper()
	request , err := http.NewRequest( method , target , nil )
	if err != nil { t.Fatal( err ) }
	response , err := app.Test( request )
	if err != nil { t.Fatal( err ) }
	response.Body.Close()
	code = response.StatusCode
	return
}

func TestStaticFilesNeverSpendTheBudget( t *testing.T ) {
	app := limitedApp( 2 , 2 )
	for count := 0; count < 50; count++ {
		for _ , target := range []string{ "/js/app.js" , "/css/style.css" , "/vendor/bootstrap/bootstrap.min.js" } {
			if code := status( t , app , http.MethodGet , target ); code != 200 {
				t.Fatalf( "%s, request %d: %d" , target , count , code )
			}
		}
	}
	// None of that counted, so the whole budget is still here.
	for count := 0; count < 2; count++ {
		if code := status( t , app , http.MethodGet , "/api/me" ); code != 200 { t.Fatalf( "api call %d: %d" , count , code ) }
	}
	if code := status( t , app , http.MethodGet , "/api/me" ); code != 429 { t.Fatalf( "past the budget: %d" , code ) }
}

func TestPiecesOfAnUploadHaveTheirOwnBudget( t *testing.T ) {
	app := limitedApp( 2 , 2 )
	for count := 0; count < 3; count++ {
		if code := status( t , app , http.MethodPost , "/api/files/abc/chunks/1" ); code != 200 { t.Fatalf( "piece %d: %d" , count , code ) }
	}
	if code := status( t , app , http.MethodPost , "/API/Files/abc/chunks/2/" ); code != 429 { t.Fatalf( "past the budget: %d" , code ) }
	// All of that left the page's budget alone, and only a piece is a piece.
	for _ , target := range []string{ "/api/files/abc/finish" , "/api/files/abc/chunks" } {
		if code := status( t , app , http.MethodPost , target ); code != 200 { t.Fatalf( "%s: %d" , target , code ) }
	}
	if code := status( t , app , http.MethodPost , "/api/files/abc/finish" ); code != 429 { t.Fatalf( "general budget: %d" , code ) }
}

func TestTheBudgetsAreSeparate( t *testing.T ) {
	app := limitedApp( 3 , 2 )
	for count := 0; count < 2; count++ {
		if code := status( t , app , http.MethodPost , "/api/login" ); code != 200 { t.Fatalf( "sign-in %d: %d" , count , code ) }
	}
	if code := status( t , app , http.MethodPost , "/api/login/password" ); code != 429 { t.Fatalf( "past the sign-in budget: %d" , code ) }
	if code := status( t , app , http.MethodPost , "/api/join/claim" ); code != 429 { t.Fatalf( "joining shares it: %d" , code ) }
	if code := status( t , app , http.MethodGet , "/api/me" ); code != 200 { t.Fatalf( "the general budget was spent by sign-in: %d" , code ) }
}

func TestNoSpellingGetsAroundTheBudgets( t *testing.T ) {
	for _ , target := range []string{ "/API/login" , "/Api/Login/" , "/api/login/" , "/api/LOGIN/two-factor" } {
		app := limitedApp( 100 , 1 )
		status( t , app , http.MethodPost , "/api/login" )
		if code := status( t , app , http.MethodPost , target ); code != 429 {
			t.Errorf( "%s got past the sign-in budget: %d" , target , code )
		}
	}
	// Spelled to look like a static file, but it reaches an API route.
	for _ , target := range []string{ "/API/owner/logs/days/2026.11" , "/Api/me.json" , "/MCP.json" , "/LOGIN/abc.def" , "/JOIN/abc.def" } {
		app := limitedApp( 1 , 100 )
		status( t , app , http.MethodGet , "/api/me" )
		if code := status( t , app , http.MethodGet , target ); code != 429 {
			t.Errorf( "%s counted as a static file: %d" , target , code )
		}
	}
	// Only a read of a file is exempt.
	app := limitedApp( 1 , 100 )
	status( t , app , http.MethodPost , "/js/app.js" )
	if code := status( t , app , http.MethodPost , "/js/app.js" ); code != 429 {
		t.Errorf( "a POST counted as a static file: %d" , code )
	}
}

func TestThePageItselfStillCounts( t *testing.T ) {
	app := limitedApp( 1 , 100 )
	status( t , app , http.MethodGet , "/" )
	if code := status( t , app , http.MethodGet , "/" ); code != 429 { t.Fatalf( "/ is exempt: %d" , code ) }
}
