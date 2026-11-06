package routes

import (
	json "encoding/json"
	fmt "fmt"
	io "io"
	http "net/http"
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

// Password sign-in and two-factor, through the real routes: the toggles, the
// per-account block, every way of signing in being asked for a code, and the
// answers that must not say which part was wrong.

type authFixture struct {
	app   *fiber.App
	store *db.Store
	cfg   *config.Config
	owner *models.User
	alice *models.User
	handlers *Handlers
}

// browser is one cookie jar.
type browser struct {
	fixture *authFixture
	cookie  string
}

func newAuthFixture( t *testing.T ) ( fixture *authFixture ) {
	t.Helper()
	cfg := &config.Config{
		ProjectName:      "Test",
		DatabasePath:     filepath.Join( t.TempDir() , "test.db" ),
		SecretKey:        strings.Repeat( "ab" , 32 ),
		CookieName:       "session",
		APIKeysEnabled:   true,
		PasswordsEnabled: true,
		TwoFactorEnabled: true,
		InviteLinksEnabled: true,
		Webhooks:         config.WebhooksConfig{ Enabled: true },
		SessionTTL:       time.Hour,
	}
	store , err := db.Open( cfg )
	if err != nil { t.Fatal( err ) }
	t.Cleanup( func() { store.Close() } )
	owner , _ := models.CreateUser( store , "Owner" , models.RoleAdmin )
	if _ , err = models.EnsureOwner( store ); err != nil { t.Fatal( err ) }
	alice , _ := models.CreateUser( store , "Alice" , models.RoleUser )

	static_server , _ := static.New( fstest.MapFS{ "index.html": { Data: []byte( "index" ) } } )
	settings := config.NewStaticHolder( cfg )
	handlers := New( store , settings , security.New( store , settings ) , nil , static_server , "test" )
	app := fiber.New()
	handlers.Register( app )
	fixture = &authFixture{ app: app , store: store , cfg: cfg , owner: owner , alice: alice , handlers: handlers }
	return
}

func ( fixture *authFixture ) browser() ( result *browser ) {
	result = &browser{ fixture: fixture }
	return
}

func ( client *browser ) do( t *testing.T , method string , path string , body fiber.Map ) ( status int , reply map[ string ]any ) {
	t.Helper()
	raw , _ := json.Marshal( body )
	request , _ := http.NewRequest( method , path , strings.NewReader( string( raw ) ) )
	request.Header.Set( "Content-Type" , "application/json" )
	if client.cookie != "" {
		request.Header.Set( "Cookie" , client.cookie )
	}
	response , err := client.fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
	if err != nil { t.Fatal( err ) }
	for _ , cookie := range response.Cookies() {
		client.cookie = cookie.Name + "=" + cookie.Value
	}
	text , _ := io.ReadAll( response.Body )
	status = response.StatusCode
	json.Unmarshal( text , &reply )
	return
}

func ( client *browser ) post( t *testing.T , path string , body fiber.Map ) ( status int , reply map[ string ]any ) {
	t.Helper()
	status , reply = client.do( t , http.MethodPost , path , body )
	return
}

func ( client *browser ) csrf( t *testing.T ) ( token string ) {
	t.Helper()
	_ , reply := client.do( t , http.MethodGet , "/api/me" , nil )
	token , _ = reply[ "csrf_token" ].( string )
	return
}

func ( client *browser ) signedIn( t *testing.T ) ( result bool ) {
	t.Helper()
	status , _ := client.do( t , http.MethodGet , "/api/me" , nil )
	result = status == 200
	return
}

func ( fixture *authFixture ) link( t *testing.T , user_id uint64 ) ( credential string ) {
	t.Helper()
	credential , err := models.IssueLoginToken( fixture.store , user_id , time.Hour )
	if err != nil { t.Fatal( err ) }
	return
}

func ( fixture *authFixture ) signIn( t *testing.T , user_id uint64 ) ( client *browser ) {
	t.Helper()
	client = fixture.browser()
	if status , reply := client.post( t , "/api/login" , fiber.Map{ "credential": fixture.link( t , user_id ) } ); status != 200 {
		t.Fatalf( "login link: %d %v" , status , reply )
	}
	return
}

// digest stands in for what password.js derives: 43 base64url characters.
func digest( text string ) ( result string ) {
	result = encryption.Sha256Hex( text )[ :43 ]
	return
}

func codeFor( t *testing.T , secret string , offset int64 ) ( code string ) {
	t.Helper()
	code , err := encryption.TOTPCode( secret , uint64( time.Now().Unix()/encryption.TOTPPeriodSeconds+offset ) )
	if err != nil { t.Fatal( err ) }
	return
}

func ( client *browser ) setPassword( t *testing.T , username string , text string , code string ) ( status int , reply map[ string ]any ) {
	t.Helper()
	status , reply = client.post( t , "/api/account/password" , fiber.Map{
		"username": username , "password_digest": digest( text ) , "code": code , "csrf_token": client.csrf( t ) ,
	} )
	return
}

func ( client *browser ) login( t *testing.T , username string , text string ) ( status int , reply map[ string ]any ) {
	t.Helper()
	status , reply = client.post( t , "/api/login/password" , fiber.Map{ "username": username , "password_digest": digest( text ) } )
	return
}

func ( client *browser ) enrol( t *testing.T ) ( secret string , recovery []string ) {
	t.Helper()
	token := client.csrf( t )
	_ , started := client.post( t , "/api/account/two-factor/start" , fiber.Map{ "csrf_token": token } )
	secret = started[ "secret" ].( string )
	status , reply := client.post( t , "/api/account/two-factor/confirm" , fiber.Map{ "code": codeFor( t , secret , 0 ) , "csrf_token": token } )
	if status != 200 { t.Fatalf( "confirm: %d %v" , status , reply ) }
	for _ , code := range reply[ "recovery_codes" ].( []any ) {
		recovery = append( recovery , code.( string ) )
	}
	return
}

func ( fixture *authFixture ) challenge( t *testing.T , user_id uint64 ) ( challenge string ) {
	t.Helper()
	_ , reply := fixture.browser().post( t , "/api/login" , fiber.Map{ "credential": fixture.link( t , user_id ) } )
	challenge , ok := reply[ "challenge" ].( string )
	if ok == false { t.Fatalf( "a login link did not ask for a code: %v" , reply ) }
	return
}

func ( fixture *authFixture ) finish( t *testing.T , challenge string , code string ) ( status int , reply map[ string ]any ) {
	t.Helper()
	status , reply = fixture.browser().post( t , "/api/login/two-factor" , fiber.Map{ "challenge": challenge , "code": code } )
	return
}

func TestPasswordSetThenSignIn( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	if status , reply := alice.setPassword( t , "Alice" , "correct horse" , "" ); status != 200 {
		t.Fatalf( "set: %d %v" , status , reply )
	}
	stored , _ := models.GetUser( fixture.store , fixture.alice.ID )
	if stored.Username != "alice" || strings.HasPrefix( stored.PasswordHash , "$2" ) == false {
		t.Errorf( "stored: %q %q" , stored.Username , stored.PasswordHash )
	}
	fresh := fixture.browser()
	if status , reply := fresh.login( t , "ALICE" , "correct horse" ); status != 200 {
		t.Fatalf( "login: %d %v" , status , reply )
	}
	if fresh.signedIn( t ) == false { t.Errorf( "not signed in" ) }
}

func TestEveryPasswordFailureAnswersTheSame( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	alice.setPassword( t , "alice" , "correct horse" , "" )
	owner := fixture.signIn( t , fixture.owner.ID )
	owner.setPassword( t , "owner" , "correct horse" , "" )
	models.SetPasswordBlocked( fixture.store , fixture.owner.ID , true )
	dee_user , _ := models.CreateUser( fixture.store , "Dee" , models.RoleUser )
	dee := fixture.signIn( t , dee_user.ID )
	dee.setPassword( t , "dee" , "correct horse" , "" )
	models.SetUserDisabled( fixture.store , dee_user.ID , true )

	for name , attempt := range map[ string ][ 2 ]string{
		"wrong":    { "alice" , "wrong" },
		"unknown":  { "nobody" , "correct horse" },
		"blocked":  { "owner" , "correct horse" },
		"disabled": { "dee" , "correct horse" },
	} {
		status , reply := fixture.browser().login( t , attempt[ 0 ] , attempt[ 1 ] )
		if status != 400 || reply[ "error" ] != "invalid_login" {
			t.Errorf( "%s: %d %v" , name , status , reply )
		}
	}
}

func TestARawPasswordIsRefused( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	_ , reply := alice.post( t , "/api/account/password" , fiber.Map{
		"username": "alice" , "password_digest": "hunter2" , "csrf_token": alice.csrf( t ) ,
	} )
	if reply[ "error" ] != "bad_digest" { t.Errorf( "%v" , reply ) }
}

func TestPasswordLockoutTreatsUnknownNamesAlike( t *testing.T ) {
	fixture := newAuthFixture( t )
	for _ , name := range []string{ "alice" , "nobody" } {
		for range models.AttemptMaxFailures {
			fixture.browser().login( t , name , "wrong" )
		}
		if _ , reply := fixture.browser().login( t , name , "wrong" ); reply[ "error" ] != "login_locked" {
			t.Errorf( "%s: %v" , name , reply )
		}
	}
}

func TestUsernamesAreUnique( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.signIn( t , fixture.alice.ID ).setPassword( t , "same" , "correct horse" , "" )
	_ , reply := fixture.signIn( t , fixture.owner.ID ).setPassword( t , "Same" , "correct horse" , "" )
	if reply[ "error" ] != "username_taken" { t.Errorf( "%v" , reply ) }
}

func TestChangingAPasswordEndsOtherSessionsOnly( t *testing.T ) {
	fixture := newAuthFixture( t )
	first := fixture.signIn( t , fixture.alice.ID )
	second := fixture.signIn( t , fixture.alice.ID )
	first.setPassword( t , "alice" , "correct horse" , "" )
	if first.signedIn( t ) == false { t.Errorf( "this session ended" ) }
	if second.signedIn( t ) { t.Errorf( "the other session survived" ) }
}

func TestPasswordToggleClosesAndRestores( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	alice.setPassword( t , "alice" , "correct horse" , "" )

	fixture.cfg.PasswordsEnabled = false
	if status , _ := fixture.browser().login( t , "alice" , "correct horse" ); status != 404 {
		t.Errorf( "login while off: %d" , status )
	}
	if status , _ := alice.setPassword( t , "alice" , "another one" , "" ); status != 404 {
		t.Errorf( "set while off: %d" , status )
	}
	_ , options := fixture.browser().do( t , http.MethodGet , "/api/login/options" , nil )
	if options[ "passwords" ] != false || options[ "salt" ] != nil { t.Errorf( "options: %v" , options ) }

	fixture.cfg.PasswordsEnabled = true
	if status , _ := fixture.browser().login( t , "alice" , "correct horse" ); status != 200 {
		t.Errorf( "login after restoring: %d" , status )
	}
	_ , options = fixture.browser().do( t , http.MethodGet , "/api/login/options" , nil )
	if salt , _ := options[ "salt" ].( string ); salt == "" { t.Errorf( "no salt: %v" , options ) }
}

func TestOwnerBlocksOneAccount( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice.setPassword( t , "alice" , "correct horse" , "" )

	path := fmt.Sprintf( "/api/owner/users/%d/password-access" , fixture.alice.ID )
	if status , _ := alice.post( t , path , fiber.Map{ "allowed": false , "csrf_token": alice.csrf( t ) } ); status != 404 {
		t.Errorf( "a user: %d" , status )
	}
	if status , _ := owner.post( t , path , fiber.Map{ "allowed": false , "csrf_token": owner.csrf( t ) } ); status != 200 {
		t.Errorf( "the owner: %d" , status )
	}
	if status , _ := fixture.browser().login( t , "alice" , "correct horse" ); status != 400 {
		t.Errorf( "blocked login: %d" , status )
	}
	if _ , reply := alice.setPassword( t , "alice" , "another one" , "" ); reply[ "error" ] != "password_blocked" {
		t.Errorf( "blocked set: %v" , reply )
	}
	if alice.signedIn( t ) == false { t.Errorf( "a block is not a sign-out" ) }

	owner.post( t , path , fiber.Map{ "allowed": true , "csrf_token": owner.csrf( t ) } )
	if status , _ := fixture.browser().login( t , "alice" , "correct horse" ); status != 200 {
		t.Errorf( "after unblocking: %d" , status )
	}
}

func TestRevokingAccessRemovesThePassword( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.signIn( t , fixture.alice.ID ).setPassword( t , "alice" , "correct horse" , "" )
	revoked , err := models.RevokeAllCredentials( fixture.store , fixture.alice.ID , false )
	if err != nil || revoked.Passwords != 1 { t.Fatalf( "%v %v" , revoked , err ) }
	if status , _ := fixture.browser().login( t , "alice" , "correct horse" ); status != 400 {
		t.Errorf( "login after revoking: %d" , status )
	}
}

func TestInviteClaimAndPasswords( t *testing.T ) {
	fixture := newAuthFixture( t )
	credential , _ , err := models.IssueInviteLink( fixture.store , "Club" , 10 , 24*time.Hour , fixture.owner.ID )
	if err != nil { t.Fatal( err ) }
	bob := fixture.browser()
	if status , reply := bob.post( t , "/api/join/create" , fiber.Map{ "credential": credential , "display_name": "Bob" } ); status != 201 {
		t.Fatalf( "join: %d %v" , status , reply )
	}
	_ , me := bob.do( t , http.MethodGet , "/api/me" , nil )
	bob_id := me[ "id" ]
	claim := func( client *browser , pin string ) ( status int , reply map[ string ]any ) {
		status , reply = client.post( t , "/api/join/claim" , fiber.Map{ "credential": credential , "user_id": bob_id , "pin": pin } )
		return
	}

	if status , reply := claim( fixture.browser() , "" ); status != 200 { t.Fatalf( "claim: %d %v" , status , reply ) }
	bob.setPassword( t , "bob" , "correct horse" , "" )
	if _ , reply := claim( fixture.browser() , "" ); reply[ "error" ] != "use_password" {
		t.Errorf( "a password should close the claim: %v" , reply )
	}
	bob.post( t , "/api/account/pin" , fiber.Map{ "pin": "1234" , "csrf_token": bob.csrf( t ) } )
	if status , reply := claim( fixture.browser() , "1234" ); status != 200 {
		t.Errorf( "a PIN should keep it open: %d %v" , status , reply )
	}

	secret , _ := bob.enrol( t )
	fresh := fixture.browser()
	_ , reply := claim( fresh , "1234" )
	if reply[ "two_factor" ] != true { t.Fatalf( "a claim did not ask for a code: %v" , reply ) }
	if fresh.signedIn( t ) { t.Errorf( "signed in before the code" ) }
	if status , finished := fresh.post( t , "/api/login/two-factor" , fiber.Map{ "challenge": reply[ "challenge" ] , "code": codeFor( t , secret , 1 ) } ); status != 200 {
		t.Fatalf( "finish: %d %v" , status , finished )
	}
	if fresh.signedIn( t ) == false { t.Errorf( "not signed in after the code" ) }
}

func TestRFC6238Vector( t *testing.T ) {
	// Appendix B of the RFC, seed "12345678901234567890", t = 59. The RFC
	// shows eight digits, 94287082; six is the same value's tail.
	code , err := encryption.TOTPCode( "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" , 59/30 )
	if err != nil || code != "287082" { t.Errorf( "%q %v" , code , err ) }
}

func TestTwoFactorSecretIsEncryptedOnItsOwn( t *testing.T ) {
	fixture := newAuthFixture( t )
	secret , _ := fixture.signIn( t , fixture.alice.ID ).enrol( t )
	stored , _ := models.GetUser( fixture.store , fixture.alice.ID )
	if stored.TOTPSecret == secret { t.Fatalf( "stored in the clear" ) }
	opened , err := encryption.ChaChaDecryptBase64String( fixture.cfg.SecretKey , stored.TOTPSecret )
	if err != nil || opened != secret { t.Errorf( "%q %v" , opened , err ) }
}

func TestLoginLinkAsksForTheCode( t *testing.T ) {
	fixture := newAuthFixture( t )
	secret , _ := fixture.signIn( t , fixture.alice.ID ).enrol( t )
	fresh := fixture.browser()
	_ , reply := fresh.post( t , "/api/login" , fiber.Map{ "credential": fixture.link( t , fixture.alice.ID ) } )
	if reply[ "two_factor" ] != true { t.Fatalf( "%v" , reply ) }
	if fresh.signedIn( t ) { t.Errorf( "signed in before the code" ) }
	if _ , wrong := fresh.post( t , "/api/login/two-factor" , fiber.Map{ "challenge": reply[ "challenge" ] , "code": "000000" } ); wrong[ "error" ] != "two_factor_wrong" {
		t.Errorf( "%v" , wrong )
	}
	if status , _ := fresh.post( t , "/api/login/two-factor" , fiber.Map{ "challenge": reply[ "challenge" ] , "code": codeFor( t , secret , 1 ) } ); status != 200 {
		t.Errorf( "right code: %d" , status )
	}
	if fresh.signedIn( t ) == false { t.Errorf( "not signed in" ) }
}

func TestPasswordAsksForTheCode( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	alice.setPassword( t , "alice" , "correct horse" , "" )
	secret , _ := alice.enrol( t )
	fresh := fixture.browser()
	_ , reply := fresh.login( t , "alice" , "correct horse" )
	if reply[ "two_factor" ] != true { t.Fatalf( "%v" , reply ) }
	if fresh.signedIn( t ) { t.Errorf( "signed in before the code" ) }
	fresh.post( t , "/api/login/two-factor" , fiber.Map{ "challenge": reply[ "challenge" ] , "code": codeFor( t , secret , 1 ) } )
	if fresh.signedIn( t ) == false { t.Errorf( "not signed in" ) }
}

func TestCodesAndChallengesWorkOnce( t *testing.T ) {
	fixture := newAuthFixture( t )
	secret , recovery := fixture.signIn( t , fixture.alice.ID ).enrol( t )
	if len( recovery ) != models.RecoveryCodeCount { t.Fatalf( "%d recovery codes" , len( recovery ) ) }

	code := codeFor( t , secret , 1 )
	if status , _ := fixture.finish( t , fixture.challenge( t , fixture.alice.ID ) , code ); status != 200 {
		t.Errorf( "first use: %d" , status )
	}
	if status , _ := fixture.finish( t , fixture.challenge( t , fixture.alice.ID ) , code ); status != 403 {
		t.Errorf( "replay: %d" , status )
	}

	challenge := fixture.challenge( t , fixture.alice.ID )
	if status , _ := fixture.finish( t , challenge , strings.ToLower( recovery[ 0 ] ) ); status != 200 {
		t.Errorf( "recovery code: %d" , status )
	}
	if _ , reply := fixture.finish( t , challenge , recovery[ 1 ] ); reply[ "error" ] != "challenge_invalid" {
		t.Errorf( "spent challenge: %v" , reply )
	}
	if status , _ := fixture.finish( t , fixture.challenge( t , fixture.alice.ID ) , recovery[ 0 ] ); status != 403 {
		t.Errorf( "spent recovery code: %d" , status )
	}
}

func TestWrongCodesLock( t *testing.T ) {
	fixture := newAuthFixture( t )
	secret , _ := fixture.signIn( t , fixture.alice.ID ).enrol( t )
	challenge := fixture.challenge( t , fixture.alice.ID )
	for range models.AttemptMaxFailures {
		fixture.finish( t , challenge , "000000" )
	}
	if _ , reply := fixture.finish( t , challenge , codeFor( t , secret , 1 ) ); reply[ "error" ] != "two_factor_locked" {
		t.Errorf( "%v" , reply )
	}
}

func TestTurningTwoFactorOffNeedsACode( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	secret , _ := alice.enrol( t )
	token := alice.csrf( t )
	if status , _ := alice.post( t , "/api/account/two-factor/disable" , fiber.Map{ "code": "" , "csrf_token": token } ); status != 403 {
		t.Errorf( "no code: %d" , status )
	}
	if status , _ := alice.post( t , "/api/account/two-factor/disable" , fiber.Map{ "code": codeFor( t , secret , 1 ) , "csrf_token": token } ); status != 200 {
		t.Errorf( "right code: %d" , status )
	}
	fixture.signIn( t , fixture.alice.ID )
}

func TestChangingAPasswordNeedsACode( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	secret , _ := alice.enrol( t )
	if _ , reply := alice.setPassword( t , "alice" , "correct horse" , "" ); reply[ "error" ] != "two_factor_wrong" {
		t.Errorf( "%v" , reply )
	}
	if status , _ := alice.setPassword( t , "alice" , "correct horse" , codeFor( t , secret , 1 ) ); status != 200 {
		t.Errorf( "with a code: %d" , status )
	}
}

func TestTwoFactorToggleStopsAskingAndRestores( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	alice.enrol( t )
	fixture.cfg.TwoFactorEnabled = false
	fixture.signIn( t , fixture.alice.ID )
	if status , _ := alice.post( t , "/api/account/two-factor/start" , fiber.Map{ "csrf_token": alice.csrf( t ) } ); status != 404 {
		t.Errorf( "setup while off: %d" , status )
	}
	fixture.cfg.TwoFactorEnabled = true
	fixture.challenge( t , fixture.alice.ID )
}

func TestDisablingEndsASignInInProgress( t *testing.T ) {
	fixture := newAuthFixture( t )
	secret , _ := fixture.signIn( t , fixture.alice.ID ).enrol( t )
	challenge := fixture.challenge( t , fixture.alice.ID )
	models.SetUserDisabled( fixture.store , fixture.alice.ID , true )
	if _ , reply := fixture.finish( t , challenge , codeFor( t , secret , 1 ) ); reply[ "error" ] != "challenge_invalid" {
		t.Errorf( "%v" , reply )
	}
}

func TestResetTwoFactorRules( t *testing.T ) {
	fixture := newAuthFixture( t )
	second , _ := models.CreateUser( fixture.store , "Second" , models.RoleAdmin )
	admin := fixture.signIn( t , second.ID )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	alice.enrol( t )
	owner.enrol( t )
	admin.enrol( t )

	reset := func( client *browser , user_id uint64 ) ( status int ) {
		status , _ = client.post( t , fmt.Sprintf( "/api/admin/users/%d/reset-two-factor" , user_id ) , fiber.Map{ "csrf_token": client.csrf( t ) } )
		return
	}
	for _ , check := range []struct {
		name   string
		client *browser
		target uint64
		want   int
	}{
		{ "an admin on the owner" , admin , fixture.owner.ID , 403 },
		{ "an admin on themselves" , admin , second.ID , 400 },
		{ "the owner on themselves" , owner , fixture.owner.ID , 400 },
		{ "an admin on a user" , admin , fixture.alice.ID , 200 },
		{ "the owner on an admin" , owner , second.ID , 200 },
	} {
		if status := reset( check.client , check.target ); status != check.want {
			t.Errorf( "%s: %d, want %d" , check.name , status , check.want )
		}
	}
	// The CLI may do what the web may not.
	if err := models.ResetTwoFactor( fixture.store , fixture.owner.ID , 0 ); err != nil { t.Fatal( err ) }
	stored , _ := models.GetUser( fixture.store , fixture.owner.ID )
	if stored.TwoFactorOn() { t.Errorf( "still on" ) }
}
