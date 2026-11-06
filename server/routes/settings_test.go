package routes

import (
	json "encoding/json"
	io "io"
	http "net/http"
	os "os"
	filepath "path/filepath"
	strings "strings"
	testing "testing"
	fstest "testing/fstest"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
	db "ipb/server/db"
	encryption "ipb/server/encryption"
	models "ipb/server/models"
	security "ipb/server/security"
	static "ipb/server/static"
)

// The Settings screen's routes, wired the way main.go wires them, over a
// real config.yaml and secret.key in a temporary folder.

type settingsFixture struct {
	app      *fiber.App
	settings *config.Holder
	path     string
	owner    string // a session cookie
	csrf     string
	admin    string // another admin's session cookie
	key      string // the owner's admin API key
}

func useDefaults( t *testing.T ) {
	t.Helper()
	defaults , err := os.ReadFile( "../../config/defaults.yaml" )
	if err != nil { t.Fatal( err ) }
	header , err := os.ReadFile( "../../config/example_header.yaml" )
	if err != nil { t.Fatal( err ) }
	config.UseEmbedded( defaults , header )
	// A project's defaults.yaml says which features it chose. These tests are
	// about the features themselves, so they run on the template's choice
	// whatever that was.
	pinned , _ , err := config.EditChanges( defaults , map[string]any{
		"auth.api_keys": true , "auth.invite_links": true , "auth.two_factor": true , "auth.passwords": false ,
		"server.mcp": true , "files.enabled": true , "webhooks.enabled": true ,
		"metrics.enabled": false , "backups.enabled": false ,
	} , "defaults.yaml" , false )
	if err != nil { t.Fatal( err ) }
	config.UseEmbedded( pinned , header )
}

func newSettingsFixture( t *testing.T ) ( fixture *settingsFixture ) {
	t.Helper()
	useDefaults( t )
	dir := t.TempDir()
	path := filepath.Join( dir , "config.yaml" )
	if _ , err := config.WriteNew( path ); err != nil { t.Fatal( err ) }
	// Keep the app directory in the test's folder, not ~/.config.
	raw , _ := os.ReadFile( path )
	raw = []byte( strings.Replace( string( raw ) , `app_dir: ""` , `app_dir: "`+filepath.Join( dir , "data" )+`"` , 1 ) )
	os.WriteFile( path , raw , 0o600 )

	cfg , err := config.LoadPath( path , true )
	if err != nil { t.Fatal( err ) }
	store , err := db.Open( cfg )
	if err != nil { t.Fatal( err ) }
	t.Cleanup( func() { store.Close() } )

	owner , _ := models.CreateUser( store , "Owner" , models.RoleAdmin )
	if _ , err = models.EnsureOwner( store ); err != nil { t.Fatal( err ) }
	other , _ := models.CreateUser( store , "Other admin" , models.RoleAdmin )
	key , _ , err := models.IssueAPIKey( store , owner.ID , "admin" , models.RoleAdmin , time.Hour )
	if err != nil { t.Fatal( err ) }

	settings := config.NewHolder( cfg )
	static_server , _ := static.New( fstest.MapFS{ "index.html": { Data: []byte( "index" ) } } )
	handlers := New( store , settings , security.New( store , settings ) , nil , static_server , "test" )
	app := fiber.New()
	handlers.Register( app )

	fixture = &settingsFixture{ app: app , settings: settings , path: path , key: key }
	fixture.owner = sessionCookie( t , store , cfg , owner.ID )
	fixture.admin = sessionCookie( t , store , cfg , other.ID )
	_ , me := fixture.request( t , http.MethodGet , "/api/me" , fixture.owner , "" , "" )
	fixture.csrf , _ = me[ "csrf_token" ].( string )
	return
}

func sessionCookie( t *testing.T , store *db.Store , cfg *config.Config , user_id uint64 ) ( cookie string ) {
	t.Helper()
	login , err := models.IssueLoginToken( store , user_id , time.Hour )
	if err != nil { t.Fatal( err ) }
	signed , err := models.RedeemLoginToken( store , login , models.SignInRules{ SessionTTL: time.Hour } )
	if err != nil { t.Fatal( err ) }
	sealed , _ := encryption.ChaChaEncryptString( cfg.SecretKey , signed.SessionCredential )
	cookie = cfg.CookieName + "=" + sealed
	return
}

func ( fixture *settingsFixture ) request( t *testing.T , method string , path string , cookie string , key string , body string ) ( status int , reply map[string]any ) {
	t.Helper()
	request , _ := http.NewRequest( method , path , strings.NewReader( body ) )
	request.Header.Set( "Content-Type" , "application/json" )
	if cookie != "" {
		request.Header.Set( "Cookie" , cookie )
	}
	if key != "" {
		request.Header.Set( "Authorization" , "Bearer "+key )
	}
	response , err := fixture.app.Test( request )
	if err != nil { t.Fatal( err ) }
	raw , _ := io.ReadAll( response.Body )
	status = response.StatusCode
	json.Unmarshal( raw , &reply )
	if reply == nil {
		reply = map[string]any{ "raw": string( raw ) }
	}
	return
}

func TestSettingsAreTheOwnersAlone( t *testing.T ) {
	fixture := newSettingsFixture( t )
	if status , _ := fixture.request( t , http.MethodGet , "/api/owner/settings" , fixture.admin , "" , "" ); status != 404 {
		t.Errorf( "another admin: status %d, want 404" , status )
	}
	if status , _ := fixture.request( t , http.MethodGet , "/api/owner/settings" , "" , fixture.key , "" ); status != 404 {
		t.Errorf( "the owner's API key: status %d, want 404" , status )
	}
	status , reply := fixture.request( t , http.MethodGet , "/api/owner/settings" , fixture.owner , "" , "" )
	if status != 200 {
		t.Fatalf( "owner: status %d" , status )
	}
	encoded , _ := json.Marshal( reply )
	if strings.Contains( string( encoded ) , fixture.settings.Get().SecretKey ) {
		t.Fatal( "the settings response contains the secret key" )
	}
}

func TestSaveSettings( t *testing.T ) {
	fixture := newSettingsFixture( t )
	_ , snapshot := fixture.request( t , http.MethodGet , "/api/owner/settings" , fixture.owner , "" , "" )
	version , _ := snapshot[ "version" ].( string )

	body := `{"version":"` + version + `","changes":{"server.rate_limit_max":7}}`
	if status , _ := fixture.request( t , http.MethodPost , "/api/owner/settings" , fixture.owner , "" , body ); status != 403 {
		t.Errorf( "no csrf token: status %d, want 403" , status )
	}

	body = `{"csrf_token":"` + fixture.csrf + `","version":"` + version + `","changes":{"server.rate_limit_max":7}}`
	status , reply := fixture.request( t , http.MethodPost , "/api/owner/settings" , fixture.owner , "" , body )
	if status != 200 || fixture.settings.Get().RateLimitMax != 7 {
		t.Fatalf( "save: status %d %v, rate_limit_max %d" , status , reply , fixture.settings.Get().RateLimitMax )
	}

	// The same version again is now out of date.
	status , reply = fixture.request( t , http.MethodPost , "/api/owner/settings" , fixture.owner , "" , body )
	if status != 409 || reply[ "error" ] != "settings_changed" || reply[ "version" ] == version {
		t.Fatalf( "stale version: status %d %v" , status , reply )
	}

	body = `{"csrf_token":"` + fixture.csrf + `","version":"` + reply[ "version" ].( string ) + `","changes":{"server.port":0}}`
	status , reply = fixture.request( t , http.MethodPost , "/api/owner/settings" , fixture.owner , "" , body )
	if status != 400 || reply[ "error" ] != "invalid_settings" {
		t.Fatalf( "invalid value: status %d %v" , status , reply )
	}
}

func TestMCPFollowsTheSetting( t *testing.T ) {
	fixture := newSettingsFixture( t )
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}`
	if status , _ := fixture.request( t , http.MethodPost , "/mcp" , "" , fixture.key , ping ); status == 404 {
		t.Fatal( "/mcp should answer while server.mcp is on" )
	}
	raw , _ := os.ReadFile( fixture.path )
	if _ , err := fixture.settings.Save( config.Version( raw ) , map[string]any{ "server.mcp": false } ); err != nil {
		t.Fatal( err )
	}
	if status , _ := fixture.request( t , http.MethodPost , "/mcp" , "" , fixture.key , ping ); status != 404 {
		t.Fatalf( "/mcp should 404 once server.mcp is off, got %d" , status )
	}
}
