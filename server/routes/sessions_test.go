package routes

import (
	encoding_json "encoding/json"
	fmt "fmt"
	io "io"
	http "net/http"
	strings "strings"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	db "ipb/server/db"
	jobs "ipb/server/jobs"
	models "ipb/server/models"
)

// devices is a browser's GET /api/account/sessions: the rows of its first page.
func ( client *browser ) devices( t *testing.T ) ( rows []map[ string ]any ) {
	t.Helper()
	request , _ := http.NewRequest( http.MethodGet , "/api/account/sessions" , nil )
	request.Header.Set( "Cookie" , client.cookie )
	request.Header.Set( "User-Agent" , "test-agent" )
	response , err := client.fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
	if err != nil { t.Fatal( err ) }
	raw , _ := io.ReadAll( response.Body )
	if response.StatusCode != http.StatusOK {
		t.Fatalf( "status %d: %s" , response.StatusCode , raw )
	}
	if strings.Contains( string( raw ) , "secret_hash" ) || strings.Contains( string( raw ) , "csrf" ) {
		t.Fatalf( "the list leaks a credential: %s" , raw )
	}
	var page struct {
		Sessions []map[ string ]any `json:"sessions"`
	}
	if err = encoding_json.Unmarshal( raw , &page ); err != nil { t.Fatal( err ) }
	rows = page.Sessions
	return
}

func other( t *testing.T , rows []map[ string ]any ) ( id string ) {
	t.Helper()
	for _ , row := range rows {
		if row[ "current" ] == false {
			id , _ = row[ "id" ].( string )
			return
		}
	}
	t.Fatal( "no other session listed" )
	return
}

func TestDevicesListMarksThisOneAndRecordsTheSignIn( t *testing.T ) {
	fixture := newAuthFixture( t )
	first := fixture.signIn( t , fixture.alice.ID )
	second := fixture.signIn( t , fixture.alice.ID )
	fixture.signIn( t , fixture.owner.ID )

	rows := first.devices( t )
	if len( rows ) != 2 {
		t.Fatalf( "someone else's session is listed, or one is missing: %v" , rows )
	}
	current := 0
	for _ , row := range rows {
		if row[ "current" ] == true { current += 1 }
		if row[ "last_seen_at" ] == nil || row[ "ip" ] == nil {
			t.Fatalf( "sign-in details were not recorded: %v" , row )
		}
	}
	if current != 1 {
		t.Fatalf( "%d sessions marked current" , current )
	}
	if second.signedIn( t ) == false {
		t.Fatal( "listing ended a session" )
	}
}

func TestTwoFactorSignInRecordsTheDevice( t *testing.T ) {
	fixture := newAuthFixture( t )
	client := fixture.signIn( t , fixture.alice.ID )
	secret , _ := client.enrol( t )
	challenge := fixture.challenge( t , fixture.alice.ID )
	status , _ := fixture.finish( t , challenge , codeFor( t , secret , 1 ) )
	if status != http.StatusOK {
		t.Fatalf( "status %d" , status )
	}
	sessions , err := models.ListSessionsForUser( fixture.store , fixture.alice.ID )
	if err != nil { t.Fatal( err ) }
	recorded := 0
	for _ , session := range sessions {
		if session.LastSeenAt != nil { recorded += 1 }
	}
	if recorded != len( sessions ) || recorded == 0 {
		t.Fatalf( "%d of %d sessions were recorded" , recorded , len( sessions ) )
	}
}

func TestRevokeOneDevice( t *testing.T ) {
	fixture := newAuthFixture( t )
	here := fixture.signIn( t , fixture.alice.ID )
	there := fixture.signIn( t , fixture.alice.ID )
	id := other( t , here.devices( t ) )

	if status , _ := here.post( t , "/api/account/sessions/"+id+"/revoke" , fiber.Map{} ); status != http.StatusForbidden {
		t.Fatalf( "no CSRF token: status %d" , status )
	}
	status , _ := here.post( t , "/api/account/sessions/"+id+"/revoke" , fiber.Map{ "csrf_token": here.csrf( t ) } )
	if status != http.StatusOK {
		t.Fatalf( "status %d" , status )
	}
	if there.signedIn( t ) {
		t.Fatal( "the revoked device is still signed in" )
	}
	if here.signedIn( t ) == false {
		t.Fatal( "revoking the other device ended this one" )
	}
}

func TestSomeoneElsesSessionLooksLikeNoSession( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice_second := fixture.signIn( t , fixture.alice.ID )
	id := other( t , alice.devices( t ) )

	csrf := owner.csrf( t )
	theirs , foreign := owner.post( t , "/api/account/sessions/"+id+"/revoke" , fiber.Map{ "csrf_token": csrf } )
	unknown_status , unknown := owner.post( t , "/api/account/sessions/nothing-here/revoke" , fiber.Map{ "csrf_token": csrf } )
	if theirs != http.StatusNotFound || unknown_status != http.StatusNotFound || foreign[ "error" ] != unknown[ "error" ] {
		t.Fatalf( "%d %v vs %d %v" , theirs , foreign , unknown_status , unknown )
	}
	if alice_second.signedIn( t ) == false {
		t.Fatal( "another account's session was ended" )
	}
}

func TestThisDeviceIsNotRevokedHere( t *testing.T ) {
	fixture := newAuthFixture( t )
	client := fixture.signIn( t , fixture.alice.ID )
	id , _ := client.devices( t )[ 0 ][ "id" ].( string )
	status , reply := client.post( t , "/api/account/sessions/"+id+"/revoke" , fiber.Map{ "csrf_token": client.csrf( t ) } )
	if status != http.StatusBadRequest || reply[ "error" ] != "use sign out for this device" {
		t.Fatalf( "%d %v" , status , reply )
	}
	if client.signedIn( t ) == false {
		t.Fatal( "this session was ended" )
	}
}

func TestRevokeOthersKeepsThisOne( t *testing.T ) {
	fixture := newAuthFixture( t )
	here := fixture.signIn( t , fixture.alice.ID )
	there := fixture.signIn( t , fixture.alice.ID )
	third := fixture.signIn( t , fixture.alice.ID )
	owner := fixture.signIn( t , fixture.owner.ID )

	status , reply := here.post( t , "/api/account/sessions/revoke-others" , fiber.Map{ "csrf_token": here.csrf( t ) } )
	if status != http.StatusOK || reply[ "removed" ] != float64( 2 ) {
		t.Fatalf( "%d %v" , status , reply )
	}
	if there.signedIn( t ) || third.signedIn( t ) {
		t.Fatal( "another device is still signed in" )
	}
	if here.signedIn( t ) == false || owner.signedIn( t ) == false {
		t.Fatal( "the wrong session ended" )
	}
}

func TestAnAPIKeyCannotManageDevices( t *testing.T ) {
	fixture := newAuthFixture( t )
	key , _ , err := models.IssueAPIKey( fixture.store , fixture.alice.ID , "script" , models.RoleUser , time.Hour )
	if err != nil { t.Fatal( err ) }
	request , _ := http.NewRequest( http.MethodGet , "/api/account/sessions" , nil )
	request.Header.Set( "Authorization" , "Bearer "+key )
	response , err := fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
	if err != nil { t.Fatal( err ) }
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf( "status %d" , response.StatusCode )
	}
}

func TestTouchIsThrottledAndCannotBringASessionBack( t *testing.T ) {
	fixture := newAuthFixture( t )
	client := fixture.signIn( t , fixture.alice.ID )
	sessions , _ := models.ListSessionsForUser( fixture.store , fixture.alice.ID )
	session := sessions[ 0 ]
	stamp := *session.LastSeenAt

	models.TouchSession( fixture.store , session , time.Hour , time.Hour )
	if session.LastSeenAt.Equal( stamp ) == false {
		t.Fatal( "touched inside the interval" )
	}
	stale := stamp.Add( -time.Hour )
	session.LastSeenAt = &stale
	models.TouchSession( fixture.store , session , time.Hour , time.Hour )
	if session.LastSeenAt.Before( stamp ) {
		t.Fatal( "not touched after the interval" )
	}

	if err := models.RevokeSession( fixture.store , fixture.alice.ID , session.ID ); err != nil { t.Fatal( err ) }
	session.LastSeenAt = &stale
	models.TouchSession( fixture.store , session , time.Hour , time.Hour )
	if client.signedIn( t ) {
		t.Fatal( "a touch brought back a revoked session" )
	}
}

// age backdates a browser's only session: signed in signed_in ago, ending in
// remaining, and last used long enough ago for the next request to count.
func ( fixture *authFixture ) age( t *testing.T , user_id uint64 , signed_in time.Duration , remaining time.Duration ) ( session_id string ) {
	t.Helper()
	sessions , err := models.ListSessionsForUser( fixture.store , user_id )
	if err != nil || len( sessions ) != 1 { t.Fatalf( "%d sessions, %v" , len( sessions ) , err ) }
	session_id = sessions[ 0 ].ID
	now := time.Now().UTC()
	stale := now.Add( -time.Hour )
	err = fixture.store.UpdateValue( db.BucketSessions , []byte( session_id ) ,
		func() any { return &models.Session{} } ,
		func( item any ) ( mutate_err error ) {
			stored := item.( *models.Session )
			stored.CreatedAt = now.Add( -signed_in )
			stored.ExpiresAt = now.Add( remaining )
			stored.LastSeenAt = &stale
			return
		} )
	if err != nil { t.Fatal( err ) }
	return
}

func ( fixture *authFixture ) sessionEnd( t *testing.T , session_id string ) ( expires time.Time ) {
	t.Helper()
	stored := &models.Session{}
	if err := fixture.store.Get( db.BucketSessions , []byte( session_id ) , stored ); err != nil { t.Fatal( err ) }
	expires = stored.ExpiresAt
	return
}

// cookieOn sends one request and answers the session cookie it set, if any.
func ( client *browser ) cookieOn( t *testing.T , method string , path string , body string ) ( found *http.Cookie ) {
	t.Helper()
	request , _ := http.NewRequest( method , path , strings.NewReader( body ) )
	request.Header.Set( "Content-Type" , "application/json" )
	request.Header.Set( "Cookie" , client.cookie )
	response , err := client.fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
	if err != nil { t.Fatal( err ) }
	for _ , cookie := range response.Cookies() {
		if cookie.Name == client.fixture.cfg.CookieName { found = cookie }
	}
	return
}

func TestUsingASessionExtendsTheRecordAndTheCookie( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.cfg.SessionMaxAge = 24 * time.Hour
	client := fixture.signIn( t , fixture.alice.ID )
	session_id := fixture.age( t , fixture.alice.ID , 2 * time.Hour , 10 * time.Minute )

	cookie := client.cookieOn( t , http.MethodGet , "/api/me" , "" )
	if cookie == nil {
		t.Fatal( "the record moved but the browser would still drop the cookie" )
	}
	if cookie.MaxAge < 3500 || cookie.MaxAge > 3600 || cookie.HttpOnly == false {
		t.Fatalf( "cookie: %+v" , cookie )
	}
	if left := time.Until( fixture.sessionEnd( t , session_id ) ); left < 59 * time.Minute {
		t.Fatalf( "%s left" , left )
	}
	if again := client.cookieOn( t , http.MethodGet , "/api/me" , "" ); again != nil {
		t.Fatal( "a second request inside the interval sent the cookie again" )
	}
}

func TestASessionStopsExtendingAtItsLimit( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.cfg.SessionMaxAge = 24 * time.Hour
	client := fixture.signIn( t , fixture.alice.ID )
	session_id := fixture.age( t , fixture.alice.ID , 23 * time.Hour + 50 * time.Minute , 5 * time.Minute )

	cookie := client.cookieOn( t , http.MethodGet , "/api/me" , "" )
	if cookie == nil || cookie.MaxAge > 600 {
		t.Fatalf( "cookie: %+v" , cookie )
	}
	if left := time.Until( fixture.sessionEnd( t , session_id ) ); left > 10 * time.Minute {
		t.Fatalf( "ran past the limit: %s left" , left )
	}

	fixture.age( t , fixture.alice.ID , 25 * time.Hour , 5 * time.Minute )
	if cookie = client.cookieOn( t , http.MethodGet , "/api/me" , "" ); cookie != nil {
		t.Fatal( "a session past its limit was extended" )
	}
}

func TestALiveStreamCheckIsNotUse( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.cfg.SessionMaxAge = 24 * time.Hour
	client := fixture.signIn( t , fixture.owner.ID )
	session_id := fixture.age( t , fixture.owner.ID , 2 * time.Hour , 10 * time.Minute )
	before := fixture.sessionEnd( t , session_id )
	credential , err := fixture.handlers.Guard.DecryptCookie( strings.TrimPrefix( client.cookie , fixture.cfg.CookieName + "=" ) )
	if err != nil { t.Fatal( err ) }

	if fixture.handlers.Guard.StillOwner( credential ) == false {
		t.Fatal( "the session should be alive" )
	}
	if fixture.sessionEnd( t , session_id ).Equal( before ) == false {
		t.Fatal( "a stream re-checking its session kept it alive" )
	}
}

func TestLoggingOutOnARequestThatExtendsStillClearsTheCookie( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.cfg.SessionMaxAge = 24 * time.Hour
	client := fixture.signIn( t , fixture.alice.ID )
	csrf := client.csrf( t )
	fixture.age( t , fixture.alice.ID , 2 * time.Hour , 10 * time.Minute )

	cookie := client.cookieOn( t , http.MethodPost , "/api/logout" , `{"csrf_token":"`+csrf+`"}` )
	if cookie == nil || cookie.Value != "" {
		t.Fatalf( "cookie: %+v" , cookie )
	}
}

func TestAnAdminEndsOneOfSomeonesDevices( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	first := fixture.signIn( t , fixture.alice.ID )
	second := fixture.signIn( t , fixture.alice.ID )
	path := fmt.Sprintf( "/api/admin/users/%d/sessions" , fixture.alice.ID )

	status , page := owner.do( t , http.MethodGet , path , nil )
	rows , _ := page[ "sessions" ].( []any )
	if status != http.StatusOK || len( rows ) != 2 { t.Fatalf( "%d %v" , status , page ) }
	raw , _ := encoding_json.Marshal( page )
	if strings.Contains( string( raw ) , "secret_hash" ) || strings.Contains( string( raw ) , "csrf" ) {
		t.Fatalf( "the list leaks a credential: %s" , raw )
	}
	row , _ := rows[ 0 ].( map[ string ]any )
	if row[ "ip" ] == nil { t.Fatalf( "the owner should see the address: %v" , row ) }

	id , _ := row[ "id" ].( string )
	status , _ = owner.post( t , path + "/" + id + "/revoke" , fiber.Map{ "csrf_token": owner.csrf( t ) } )
	if status != http.StatusOK { t.Fatalf( "%d" , status ) }
	if first.signedIn( t ) == second.signedIn( t ) {
		t.Fatal( "one device should have ended and the other not" )
	}
}

func TestOnlyTheOwnerReachesTheOwnersSessionsAndAddresses( t *testing.T ) {
	fixture := newAuthFixture( t )
	peer , err := models.CreateUser( fixture.store , "Peer" , models.RoleAdmin )
	if err != nil { t.Fatal( err ) }
	admin := fixture.signIn( t , peer.ID )
	fixture.signIn( t , fixture.owner.ID )
	fixture.signIn( t , fixture.alice.ID )

	status , _ := admin.do( t , http.MethodGet , fmt.Sprintf( "/api/admin/users/%d/sessions" , fixture.owner.ID ) , nil )
	if status != http.StatusForbidden { t.Fatalf( "the owner's list: %d" , status ) }

	status , page := admin.do( t , http.MethodGet , fmt.Sprintf( "/api/admin/users/%d/sessions" , fixture.alice.ID ) , nil )
	rows , _ := page[ "sessions" ].( []any )
	if status != http.StatusOK || len( rows ) != 1 { t.Fatalf( "%d %v" , status , page ) }
	if _ , shown := rows[ 0 ].( map[ string ]any )[ "ip" ]; shown {
		t.Fatal( "an admin who is not the owner sees an address" )
	}
}

func TestSessionAdminRoutesRefuse( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	path := fmt.Sprintf( "/api/admin/users/%d/sessions" , fixture.alice.ID )

	if status , _ := alice.do( t , http.MethodGet , path , nil ); status != http.StatusForbidden {
		t.Fatalf( "a user: %d" , status )
	}
	if status , _ := owner.do( t , http.MethodGet , "/api/admin/users/9999/sessions" , nil ); status != http.StatusNotFound {
		t.Fatalf( "no such user: %d" , status )
	}
	csrf := owner.csrf( t )
	if status , _ := owner.post( t , path + "/nothing/revoke" , fiber.Map{ "csrf_token": csrf } ); status != http.StatusNotFound {
		t.Fatalf( "no such session: %d" , status )
	}
	mine := owner.devices( t )[ 0 ][ "id" ].( string )
	self := fmt.Sprintf( "/api/admin/users/%d/sessions/%s/revoke" , fixture.owner.ID , mine )
	if status , _ := owner.post( t , self , fiber.Map{ "csrf_token": csrf } ); status != http.StatusBadRequest {
		t.Fatalf( "this device: %d" , status )
	}
	theirs := alice.devices( t )[ 0 ][ "id" ].( string )
	if status , _ := owner.post( t , path + "/" + theirs + "/revoke" , fiber.Map{} ); status != http.StatusForbidden {
		t.Fatalf( "no CSRF token: %d" , status )
	}
}

func TestSearchingUsersKeepsPagingHonest( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	for _ , name := range []string{ "Zed One" , "zed two" , "Zed Three" } {
		if _ , err := models.CreateUser( fixture.store , name , models.RoleUser ); err != nil { t.Fatal( err ) }
	}
	_ , page := owner.do( t , http.MethodGet , "/api/admin/users?q=ZED&limit=2" , nil )
	rows , _ := page[ "users" ].( []any )
	if len( rows ) != 2 || page[ "total" ] != float64( 3 ) || page[ "next" ] != float64( 2 ) {
		t.Fatalf( "%v" , page )
	}
	if _ , page = owner.do( t , http.MethodGet , "/api/admin/users?q=nobody" , nil ); page[ "total" ] != float64( 0 ) {
		t.Fatalf( "%v" , page )
	}
}

func TestMeSaysTheVersionAndTheAnnouncement( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.cfg.Announcement = "Down at noon"
	client := fixture.signIn( t , fixture.alice.ID )
	_ , me := client.do( t , http.MethodGet , "/api/me" , nil )
	if me[ "version" ] != "test" || me[ "announcement" ] != "Down at noon" {
		t.Fatalf( "%v" , me )
	}
}

func TestSessionFromBeforeTheseFieldsStillLoads( t *testing.T ) {
	fixture := newAuthFixture( t )
	client := fixture.signIn( t , fixture.alice.ID )
	sessions , _ := models.ListSessionsForUser( fixture.store , fixture.alice.ID )
	old := *sessions[ 0 ]
	old.IP , old.UserAgent , old.LastSeenAt = "" , "" , nil
	if err := fixture.store.Put( db.BucketSessions , []byte( old.ID ) , &old ); err != nil { t.Fatal( err ) }
	rows := client.devices( t )
	if len( rows ) != 1 || rows[ 0 ][ "ip" ] != nil {
		t.Fatalf( "rows %v" , rows )
	}
}

func TestJobsAreTheOwnersAlone( t *testing.T ) {
	fixture := newAuthFixture( t )
	handlers_jobs := jobs.New( fixture.store , nil )
	release := make( chan struct{} )
	handlers_jobs.Register( "slow" , time.Hour , func() ( note string , err error ) {
		<-release
		return
	} )
	fixture.handlers.Jobs = handlers_jobs
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )

	if status , _ := alice.do( t , http.MethodGet , "/api/owner/jobs" , nil ); status != http.StatusNotFound {
		t.Fatalf( "a user reached the jobs: %d" , status )
	}
	status , reply := owner.do( t , http.MethodGet , "/api/owner/jobs" , nil )
	listed , _ := reply[ "jobs" ].( []any )
	if status != http.StatusOK || len( listed ) != 1 {
		t.Fatalf( "%d %v" , status , reply )
	}
	if status , _ = owner.post( t , "/api/owner/jobs/slow/run" , fiber.Map{} ); status != http.StatusForbidden {
		t.Fatalf( "no CSRF token: %d" , status )
	}
	csrf := owner.csrf( t )
	if status , _ = owner.post( t , "/api/owner/jobs/nope/run" , fiber.Map{ "csrf_token": csrf } ); status != http.StatusNotFound {
		t.Fatalf( "unknown job: %d" , status )
	}
	if status , _ = owner.post( t , "/api/owner/jobs/slow/run" , fiber.Map{ "csrf_token": csrf } ); status != http.StatusAccepted {
		t.Fatalf( "run: %d" , status )
	}
	status , reply = owner.post( t , "/api/owner/jobs/slow/run" , fiber.Map{ "csrf_token": csrf } )
	close( release )
	if status != http.StatusConflict || reply[ "error" ] != "job already running" {
		t.Fatalf( "%d %v" , status , reply )
	}
	if handlers_jobs.Wait( 5 * time.Second ) == false {
		t.Fatal( "the job did not finish" )
	}
}
