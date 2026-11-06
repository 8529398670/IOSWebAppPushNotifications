package routes

import (
	http "net/http"
	url "net/url"
	strings "strings"
	testing "testing"

	fiber "github.com/gofiber/fiber/v3"

	models "ipb/server/models"
)

type sendFixture struct {
	*authFixture
	owner_browser *browser
	token         string
	app_id        string
	alice_key     string
}

func newSendFixture( t *testing.T ) ( fixture *sendFixture ) {
	t.Helper()
	auth := newAuthFixture( t )
	owner := auth.signIn( t , auth.owner.ID )
	status , reply := send( t , owner , "/api/apps" , fiber.Map{ "name": "Doorbell" } )
	if status != 200 { t.Fatalf( "%d %v" , status , reply ) }
	prefs , err := models.GetPushPrefs( auth.store , auth.alice.ID )
	if err != nil { t.Fatal( err ) }
	fixture = &sendFixture{
		authFixture:   auth,
		owner_browser: owner,
		token:         reply[ "token" ].( string ),
		app_id:        reply[ "id" ].( string ),
		alice_key:     prefs.UserKey,
	}
	return
}

// sendAs posts to the API with no session, as a script does.
func ( fixture *sendFixture ) sendAs( t *testing.T , body fiber.Map ) ( status int , reply map[ string ]any ) {
	t.Helper()
	status , reply = fixture.browser().do( t , http.MethodPost , "/api/v1/messages" , body )
	return
}

func ( fixture *sendFixture ) inboxCount( t *testing.T , user_id uint64 ) ( count int ) {
	t.Helper()
	items , err := models.ListInbox( fixture.store , user_id , "" )
	if err != nil { t.Fatal( err ) }
	count = len( items )
	return
}

func TestSendingNeedsATokenAndAKey( t *testing.T ) {
	fixture := newSendFixture( t )

	status , reply := fixture.sendAs( t , fiber.Map{ "token": fixture.token , "user": fixture.alice_key , "message": "Hello" } )
	if status != 200 || reply[ "status" ] != float64( 1 ) || reply[ "request" ] == "" { t.Fatalf( "%d %v" , status , reply ) }
	if fixture.inboxCount( t , fixture.alice.ID ) != 1 { t.Fatal( "the message did not arrive" ) }

	refused := map[ string ]fiber.Map{
		"wrong token":     { "token": fixture.app_id + ".wrong" , "user": fixture.alice_key , "message": "x" },
		"no token":        { "user": fixture.alice_key , "message": "x" },
		"key as a token":  { "token": fixture.alice_key , "user": fixture.alice_key , "message": "x" },
		"wrong key":       { "token": fixture.token , "user": "u" + strings.Repeat( "0" , 29 ) , "message": "x" },
		"no key":          { "token": fixture.token , "message": "x" },
		"blank message":   { "token": fixture.token , "user": fixture.alice_key , "message": "  " },
		"bad priority":    { "token": fixture.token , "user": fixture.alice_key , "message": "x" , "priority": 3 },
		"unsafe url":      { "token": fixture.token , "user": fixture.alice_key , "message": "x" , "url": "javascript:alert(1)" },
		"too long":        { "token": fixture.token , "user": fixture.alice_key , "message": strings.Repeat( "x" , 1025 ) },
	}
	for name , body := range refused {
		status , reply = fixture.sendAs( t , body )
		if status != 400 || reply[ "status" ] != float64( 0 ) { t.Fatalf( "%s: %d %v" , name , status , reply ) }
	}
	if fixture.inboxCount( t , fixture.alice.ID ) != 1 { t.Fatal( "a refused send reached the inbox" ) }
}

func TestSendingAsAFormAndWithABearerToken( t *testing.T ) {
	fixture := newSendFixture( t )

	form := url.Values{ "token": { fixture.token } , "user": { fixture.alice_key } , "message": { "From a form" } , "title": { "Hi" } , "unknown_field": { "ignored" } }
	request , _ := http.NewRequest( http.MethodPost , "/1/messages.json" , strings.NewReader( form.Encode() ) )
	request.Header.Set( "Content-Type" , "application/x-www-form-urlencoded" )
	response , err := fixture.app.Test( request )
	if err != nil { t.Fatal( err ) }
	if response.StatusCode != 200 { t.Fatalf( "form: %d" , response.StatusCode ) }

	request , _ = http.NewRequest( http.MethodPost , "/api/v1/messages" , strings.NewReader( `{"user":"` + fixture.alice_key + `","message":"From a header"}` ) )
	request.Header.Set( "Content-Type" , "application/json" )
	request.Header.Set( "Authorization" , "Bearer " + fixture.token )
	if response , err = fixture.app.Test( request ); err != nil { t.Fatal( err ) }
	if response.StatusCode != 200 { t.Fatalf( "bearer: %d" , response.StatusCode ) }

	items , err := models.ListInbox( fixture.store , fixture.alice.ID , "" )
	if err != nil { t.Fatal( err ) }
	if len( items ) != 2 || items[ 1 ].Title != "Hi" || items[ 1 ].AppName != "Doorbell" { t.Fatalf( "%+v" , items ) }
}

func TestRotatingEndsTheOldTokenAndKey( t *testing.T ) {
	fixture := newSendFixture( t )

	status , rotated := send( t , fixture.owner_browser , "/api/apps/"+fixture.app_id+"/rotate-token" , fiber.Map{} )
	if status != 200 { t.Fatalf( "%d" , status ) }
	if status , _ = fixture.sendAs( t , fiber.Map{ "token": fixture.token , "user": fixture.alice_key , "message": "x" } ); status != 400 {
		t.Fatalf( "old token: %d" , status )
	}
	new_token := rotated[ "token" ].( string )
	if status , _ = fixture.sendAs( t , fiber.Map{ "token": new_token , "user": fixture.alice_key , "message": "x" } ); status != 200 {
		t.Fatalf( "new token: %d" , status )
	}

	alice := fixture.signIn( t , fixture.alice.ID )
	status , rotated = send( t , alice , "/api/push/rotate-key" , fiber.Map{} )
	if status != 200 { t.Fatalf( "%d" , status ) }
	if status , _ = fixture.sendAs( t , fiber.Map{ "token": new_token , "user": fixture.alice_key , "message": "x" } ); status != 400 {
		t.Fatalf( "old key: %d" , status )
	}
	if status , _ = fixture.sendAs( t , fiber.Map{ "token": new_token , "user": rotated[ "user_key" ] , "message": "x" } ); status != 200 {
		t.Fatalf( "new key: %d" , status )
	}
}

func TestADeletedAppCannotSendAndCanComeBack( t *testing.T ) {
	fixture := newSendFixture( t )
	path := "/api/apps/" + fixture.app_id
	if status , _ := send( t , fixture.owner_browser , path+"/delete" , fiber.Map{} ); status != 200 { t.Fatalf( "delete %d" , status ) }
	body := fiber.Map{ "token": fixture.token , "user": fixture.alice_key , "message": "x" }
	if status , _ := fixture.sendAs( t , body ); status != 400 { t.Fatalf( "deleted: %d" , status ) }
	if status , _ := send( t , fixture.owner_browser , path+"/restore" , fiber.Map{} ); status != 200 { t.Fatalf( "restore %d" , status ) }
	if status , _ := fixture.sendAs( t , body ); status != 200 { t.Fatalf( "restored: %d" , status ) }
}

func TestAGroupKeyReachesEveryMember( t *testing.T ) {
	fixture := newSendFixture( t )
	status , group := send( t , fixture.owner_browser , "/api/groups" , fiber.Map{
		"name": "Family" , "members": []uint64{ fixture.owner.ID , fixture.alice.ID , 9999 },
	} )
	if status != 200 { t.Fatalf( "%d %v" , status , group ) }

	body := fiber.Map{ "token": fixture.token , "user": group[ "key" ] , "message": "Dinner" }
	if status , _ = fixture.sendAs( t , body ); status != 200 { t.Fatalf( "send %d" , status ) }
	if fixture.inboxCount( t , fixture.owner.ID ) != 1 || fixture.inboxCount( t , fixture.alice.ID ) != 1 {
		t.Fatal( "a member got nothing" )
	}

	alice := fixture.signIn( t , fixture.alice.ID )
	path := "/api/groups/" + group[ "id" ].( string )
	if status , _ = send( t , alice , path+"/delete" , fiber.Map{} ); status != 404 { t.Fatalf( "a member deleted the group: %d" , status ) }
	if status , _ = send( t , alice , path+"/leave" , fiber.Map{} ); status != 200 { t.Fatalf( "leave %d" , status ) }
	if status , _ = fixture.sendAs( t , body ); status != 200 { t.Fatalf( "send %d" , status ) }
	if fixture.inboxCount( t , fixture.alice.ID ) != 1 { t.Fatal( "someone who left still got it" ) }

	if status , _ = send( t , fixture.owner_browser , path+"/delete" , fiber.Map{} ); status != 200 { t.Fatalf( "delete %d" , status ) }
	if status , _ = fixture.sendAs( t , body ); status != 400 { t.Fatalf( "a deleted group's key: %d" , status ) }
}

func TestOnlyTheMakerOrAnAdminChangesAnApp( t *testing.T ) {
	fixture := newSendFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	path := "/api/apps/" + fixture.app_id

	for _ , action := range []string{ "/rename" , "/rotate-token" , "/delete" } {
		if status , _ := send( t , alice , path+action , fiber.Map{ "name": "Mine" } ); status != 404 {
			t.Fatalf( "%s: %d" , action , status )
		}
	}
	if status , _ := send( t , alice , path+"/mute" , fiber.Map{ "muted": true } ); status != 200 {
		t.Fatalf( "anyone may mute: %d" , status )
	}

	status , page := alice.do( t , http.MethodGet , "/api/apps" , nil )
	rows , _ := page[ "apps" ].( []any )
	if status != 200 || len( rows ) != 1 { t.Fatalf( "%d %v" , status , page ) }
	row := rows[ 0 ].( map[ string ]any )
	if row[ "muted" ] != true || row[ "can_manage" ] != false { t.Fatalf( "%v" , row ) }
	if _ , present := row[ "token_hash" ]; present { t.Fatal( "the list shows the token hash" ) }
}

func TestSomeoneElsesMessageCannotBeTouched( t *testing.T ) {
	fixture := newSendFixture( t )
	if status , _ := fixture.sendAs( t , fiber.Map{ "token": fixture.token , "user": fixture.alice_key , "message": "Private" } ); status != 200 {
		t.Fatalf( "%d" , status )
	}
	items , err := models.ListInbox( fixture.store , fixture.alice.ID , "" )
	if err != nil { t.Fatal( err ) }

	for _ , action := range []string{ "/read" , "/delete" , "/restore" } {
		if status , _ := send( t , fixture.owner_browser , "/api/inbox/"+items[ 0 ].ID+action , fiber.Map{} ); status != 404 {
			t.Fatalf( "%s: %d" , action , status )
		}
	}
	_ , page := fixture.owner_browser.do( t , http.MethodGet , "/api/inbox" , nil )
	if rows , _ := page[ "items" ].( []any ); len( rows ) != 0 { t.Fatalf( "the owner sees %v" , rows ) }

	alice := fixture.signIn( t , fixture.alice.ID )
	if status , _ := send( t , alice , "/api/inbox/"+items[ 0 ].ID+"/read" , fiber.Map{} ); status != 200 { t.Fatalf( "%d" , status ) }
	_ , unread := alice.do( t , http.MethodGet , "/api/inbox/unread" , nil )
	if unread[ "unread" ] != float64( 0 ) { t.Fatalf( "%v" , unread ) }
}

func TestOnlyAnAdminSeesEveryonesKeys( t *testing.T ) {
	fixture := newSendFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	if status , _ := alice.do( t , http.MethodGet , "/api/admin/recipient-keys" , nil ); status != 403 { t.Fatalf( "%d" , status ) }
	status , page := fixture.owner_browser.do( t , http.MethodGet , "/api/admin/recipient-keys" , nil )
	if rows , _ := page[ "people" ].( []any ); status != 200 || len( rows ) != 2 { t.Fatalf( "%d %v" , status , page ) }
}

func TestSubscribingOnlyAcceptsPushServices( t *testing.T ) {
	fixture := newSendFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	keys := fiber.Map{ "p256dh": "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4" , "auth": "BTBZMqHH6r4Tts7J_aSIgg" }

	if status , _ := send( t , alice , "/api/push/subscribe" , fiber.Map{ "endpoint": "https://169.254.169.254/x" , "keys": keys } ); status != 400 {
		t.Fatalf( "%d" , status )
	}
	if status , _ := send( t , alice , "/api/push/subscribe" , fiber.Map{ "endpoint": "https://web.push.apple.com/x" , "keys": fiber.Map{ "p256dh": "bad" , "auth": "bad" } } ); status != 400 {
		t.Fatalf( "bad keys: %d" , status )
	}
	if status , _ := send( t , alice , "/api/push/subscribe" , fiber.Map{ "endpoint": "https://web.push.apple.com/x" , "keys": keys } ); status != 200 {
		t.Fatalf( "%d" , status )
	}
	status , mine := alice.do( t , http.MethodGet , "/api/push/me" , nil )
	devices , _ := mine[ "devices" ].( []any )
	if status != 200 || len( devices ) != 1 { t.Fatalf( "%d %v" , status , mine ) }
	if _ , present := devices[ 0 ].( map[ string ]any )[ "endpoint" ]; present { t.Fatal( "the list shows the endpoint" ) }
	id := devices[ 0 ].( map[ string ]any )[ "id" ].( string )

	if status , _ = send( t , fixture.owner_browser , "/api/push/devices/"+id+"/delete" , fiber.Map{} ); status != 404 {
		t.Fatalf( "someone else removed it: %d" , status )
	}
	if status , _ = send( t , alice , "/api/push/devices/"+id+"/delete" , fiber.Map{} ); status != 200 { t.Fatalf( "%d" , status ) }
}

func TestDeletingAnAccountTakesItsPushRecords( t *testing.T ) {
	fixture := newSendFixture( t )
	store := fixture.store
	alice_id := fixture.alice.ID
	if err := models.SavePushSubscription( store , &models.PushSubscription{ UserID: alice_id , Endpoint: "https://web.push.apple.com/a" } ); err != nil { t.Fatal( err ) }
	group , err := models.CreatePushGroup( store , fixture.owner.ID , "Family" , []uint64{ alice_id , fixture.owner.ID } )
	if err != nil { t.Fatal( err ) }
	if status , _ := fixture.sendAs( t , fiber.Map{ "token": fixture.token , "user": fixture.alice_key , "message": "x" } ); status != 200 { t.Fatalf( "%d" , status ) }

	if _ , err = models.DeleteUser( store , alice_id , 0 ); err != nil { t.Fatal( err ) }

	if status , _ := fixture.sendAs( t , fiber.Map{ "token": fixture.token , "user": fixture.alice_key , "message": "x" } ); status != 400 {
		t.Fatalf( "a deleted account's key: %d" , status )
	}
	devices , err := models.PushSubscriptionsFor( store , alice_id )
	if err != nil { t.Fatal( err ) }
	if len( devices ) != 0 { t.Fatal( "the device survived" ) }
	if fixture.inboxCount( t , alice_id ) != 0 { t.Fatal( "the inbox survived" ) }
	found , err := models.GetPushGroup( store , group.ID )
	if err != nil { t.Fatal( err ) }
	if found.HasMember( alice_id ) { t.Fatal( "the group still lists them" ) }
}

func TestRevokingCredentialsStopsPushes( t *testing.T ) {
	fixture := newSendFixture( t )
	store := fixture.store
	if err := models.SavePushSubscription( store , &models.PushSubscription{ UserID: fixture.alice.ID , Endpoint: "https://web.push.apple.com/a" } ); err != nil { t.Fatal( err ) }
	if _ , err := models.RevokeAllCredentials( store , fixture.alice.ID , false ); err != nil { t.Fatal( err ) }
	devices , err := models.PushSubscriptionsFor( store , fixture.alice.ID )
	if err != nil { t.Fatal( err ) }
	if len( devices ) != 0 { t.Fatal( "a lost phone would keep getting pushes" ) }
}

func TestInstallLinks( t *testing.T ) {
	fixture := newSendFixture( t )
	status , link := send( t , fixture.owner_browser , "/api/push/install-link" , fiber.Map{} )
	if status != 200 { t.Fatalf( "%d" , status ) }
	path := link[ "install_path" ].( string )
	if strings.HasPrefix( path , "/i/" ) == false || strings.HasSuffix( path , "/" ) == false { t.Fatalf( "%q" , path ) }

	request , _ := http.NewRequest( http.MethodGet , strings.TrimSuffix( path , "/" ) , nil )
	response , err := fixture.app.Test( request )
	if err != nil { t.Fatal( err ) }
	if response.StatusCode != 302 { t.Fatalf( "no slash: %d" , response.StatusCode ) }

	request , _ = http.NewRequest( http.MethodGet , path , nil )
	if response , err = fixture.app.Test( request ); err != nil { t.Fatal( err ) }
	if response.StatusCode != 200 || response.Header.Get( "Referrer-Policy" ) != "no-referrer" {
		t.Fatalf( "%d %q" , response.StatusCode , response.Header.Get( "Referrer-Policy" ) )
	}
}

// The sound picker takes any file on an iPhone, so this is the only thing
// deciding what counts as a sound.
func TestSniffSound( t *testing.T ) {
	pad := make( []byte , 16 )
	cases := map[ string ]string{
		"ID3" + string( pad ):                                 "audio/mpeg",
		"\xff\xfb\x90" + string( pad ):                        "audio/mpeg",
		"RIFF\x00\x00\x00\x00WAVEfmt ":                        "audio/wav",
		"\x00\x00\x00\x20ftypM4A " + string( pad ):            "audio/mp4",
		"FORM\x00\x00\x00\x00AIFF" + string( pad ):            "audio/aiff",
		"caff\x00\x01\x00\x00" + string( pad ):                "audio/x-caf",
		"%PDF-1.7" + string( pad ):                            "",
		"<html><body>not a sound</body>":                      "",
		"short":                                               "",
	}
	for data , want := range cases {
		if got := sniffSound( []byte( data ) ); got != want {
			t.Errorf( "%q: got %q, want %q" , data , got , want )
		}
	}
}

// A placeholder left in a script gets an answer that says what to do.
func TestAnUnknownKeySaysWhereToFindARealOne( t *testing.T ) {
	fixture := newSendFixture( t )
	status , reply := fixture.sendAs( t , fiber.Map{ "token": fixture.token , "user": "USER_KEY" , "message": "x" } )
	errors_list , _ := reply[ "errors" ].( []any )
	if status != 400 || len( errors_list ) != 1 || strings.Contains( errors_list[ 0 ].( string ) , "Notifications" ) == false {
		t.Fatalf( "%d %v" , status , reply )
	}
}
