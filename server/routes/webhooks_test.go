package routes

import (
	http "net/http"
	strings "strings"
	testing "testing"

	fiber "github.com/gofiber/fiber/v3"

	models "ipb/server/models"
	webhooks "ipb/server/webhooks"
)

// send is a POST with the session's csrf token.
func send( t *testing.T , client *browser , path string , body fiber.Map ) ( status int , reply map[ string ]any ) {
	t.Helper()
	body[ "csrf_token" ] = client.csrf( t )
	status , reply = client.post( t , path , body )
	return
}

func createdWebhook( t *testing.T , owner *browser ) ( id string , secret string ) {
	t.Helper()
	status , reply := send( t , owner , "/api/owner/webhooks" , fiber.Map{
		"name": "Chat" , "url": "https://hooks.example.com/in" , "events": []string{ "*" },
	} )
	if status != fiber.StatusCreated { t.Fatalf( "%d %v" , status , reply ) }
	id , _ = reply[ "id" ].( string )
	secret , _ = reply[ "secret" ].( string )
	return
}

func TestTheOwnerManagesWebhooksAndTheSecretShowsOnce( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	id , secret := createdWebhook( t , owner )
	if strings.HasPrefix( secret , "whsec_" ) == false { t.Fatalf( "%q" , secret ) }

	status , page := owner.do( t , http.MethodGet , "/api/owner/webhooks" , nil )
	rows , _ := page[ "webhooks" ].( []any )
	if status != 200 || len( rows ) != 1 { t.Fatalf( "%d %v" , status , page ) }
	if _ , present := rows[ 0 ].( map[ string ]any )[ "secret" ]; present { t.Fatal( "the list shows the secret" ) }

	if status , _ = send( t , owner , "/api/owner/webhooks/"+id+"/delete" , fiber.Map{} ); status != 200 { t.Fatalf( "delete %d" , status ) }
	if _ , page = owner.do( t , http.MethodGet , "/api/owner/webhooks" , nil ); page[ "total" ] != float64( 0 ) { t.Fatalf( "%v" , page ) }
	if status , _ = send( t , owner , "/api/owner/webhooks/"+id+"/restore" , fiber.Map{} ); status != 200 { t.Fatalf( "restore %d" , status ) }
	if status , _ = send( t , owner , "/api/owner/webhooks/"+id+"/enabled" , fiber.Map{ "enabled": false } ); status != 200 { t.Fatalf( "enabled %d" , status ) }
	hook , err := models.GetWebhook( fixture.store , id )
	if err != nil || hook.Enabled { t.Fatalf( "%+v %v" , hook , err ) }
}

func TestWebhookRoutesAreTheOwnersAlone( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	if status , _ := alice.do( t , http.MethodGet , "/api/owner/webhooks" , nil ); status != fiber.StatusNotFound {
		t.Fatalf( "%d" , status )
	}
}

func TestCreatingAWebhookChecksTheAddress( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	for _ , target := range []string{ "http://hooks.example.com/in" , "https://127.0.0.1/in" , "https://localhost/in" , "https://169.254.169.254/" } {
		status , reply := send( t , owner , "/api/owner/webhooks" , fiber.Map{ "name": "x" , "url": target , "events": []string{ "*" } } )
		if status != fiber.StatusBadRequest { t.Fatalf( "%s: %d %v" , target , status , reply ) }
	}
	status , reply := send( t , owner , "/api/owner/webhooks" , fiber.Map{ "name": "x" , "url": "https://a.example" , "events": []string{ "made.up" } } )
	if status != fiber.StatusBadRequest { t.Fatalf( "%d %v" , status , reply ) }
}

func TestRenamingAWebhook( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	id , _ := createdWebhook( t , owner )
	path := "/api/owner/webhooks/" + id + "/rename"

	status , reply := send( t , owner , path , fiber.Map{ "name": "  Alerts  " } )
	if status != fiber.StatusOK || reply[ "name" ] != "Alerts" { t.Fatalf( "%d %v" , status , reply ) }
	if status , _ = send( t , owner , path , fiber.Map{ "name": "  " } ); status != fiber.StatusBadRequest { t.Fatalf( "%d" , status ) }

	// An undo that finds a different name leaves it alone, and says what is there.
	status , reply = send( t , owner , path , fiber.Map{ "name": "old" , "expect": "stale" } )
	if status != fiber.StatusConflict || reply[ "name" ] != "Alerts" { t.Fatalf( "%d %v" , status , reply ) }

	models.DeleteWebhook( fixture.store , id , fixture.owner.ID )
	if status , _ = send( t , owner , path , fiber.Map{ "name": "gone" } ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

func TestChangingWhereAWebhookGoes( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	id , _ := createdWebhook( t , owner )
	path := "/api/owner/webhooks/" + id + "/target"
	events := []string{ models.EventUserCreated }

	status , reply := send( t , owner , path , fiber.Map{ "url": "https://new.example.com/in" , "events": events } )
	if status != fiber.StatusOK { t.Fatalf( "%d %v" , status , reply ) }
	hook , _ := models.GetWebhook( fixture.store , id )
	if hook.URL != "https://new.example.com/in" || len( hook.Events ) != 1 || hook.Events[ 0 ] != models.EventUserCreated { t.Fatalf( "%+v" , hook ) }

	// The same check as a new endpoint's, so an edit cannot aim one at this machine.
	for _ , target := range []string{ "http://hooks.example.com/in" , "https://127.0.0.1/in" , "https://169.254.169.254/" } {
		if status , _ = send( t , owner , path , fiber.Map{ "url": target , "events": events } ); status != fiber.StatusBadRequest { t.Fatalf( "%s: %d" , target , status ) }
	}
	for _ , picked := range [][]string{ {} , { "made.up" } } {
		if status , _ = send( t , owner , path , fiber.Map{ "url": "https://a.example" , "events": picked } ); status != fiber.StatusBadRequest { t.Fatalf( "%v: %d" , picked , status ) }
	}

	// An undo that finds something else leaves it alone: the address or the events.
	for _ , stale := range []fiber.Map{
		{ "url": "https://old.example.com/in" , "events": events },
		{ "url": "https://new.example.com/in" , "events": []string{ "*" } },
	} {
		status , _ = send( t , owner , path , fiber.Map{ "url": "https://a.example" , "events": []string{ "*" } , "expect": stale } )
		if status != fiber.StatusConflict { t.Fatalf( "%v: %d" , stale , status ) }
	}
	hook , _ = models.GetWebhook( fixture.store , id )
	if hook.URL != "https://new.example.com/in" { t.Fatalf( "%+v" , hook ) }
	status , _ = send( t , owner , path , fiber.Map{ "url": "https://a.example" , "events": []string{ "*" } ,
		"expect": fiber.Map{ "url": "https://new.example.com/in" , "events": events } } )
	if status != fiber.StatusOK { t.Fatalf( "%d" , status ) }

	models.DeleteWebhook( fixture.store , id , fixture.owner.ID )
	if status , _ = send( t , owner , path , fiber.Map{ "url": "https://a.example" , "events": events } ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

func TestRotatingAWebhookSecret( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	id , before := createdWebhook( t , owner )
	path := "/api/owner/webhooks/" + id + "/rotate-secret"

	status , reply := send( t , owner , path , fiber.Map{} )
	after , _ := reply[ "secret" ].( string )
	if status != fiber.StatusOK || strings.HasPrefix( after , "whsec_" ) == false || after == before { t.Fatalf( "%d %v" , status , reply ) }

	// The sender opens the new one, so a delivery is signed with what was shown.
	hook , _ := models.GetWebhook( fixture.store , id )
	opened , err := models.OpenWebhookSecret( hook , fixture.handlers.cfg().SecretKey )
	if err != nil || opened != after { t.Fatalf( "%q %v" , opened , err ) }

	models.DeleteWebhook( fixture.store , id , fixture.owner.ID )
	if status , _ = send( t , owner , path , fiber.Map{} ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

func TestEditingAWebhookIsTheOwnersAlone( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	id , _ := createdWebhook( t , owner )
	for _ , verb := range []string{ "rename" , "target" , "rotate-secret" } {
		status , _ := send( t , alice , "/api/owner/webhooks/"+id+"/"+verb , fiber.Map{ "name": "x" , "url": "https://a.example" , "events": []string{ "*" } } )
		if status != fiber.StatusNotFound { t.Fatalf( "%s: %d" , verb , status ) }
	}
}

func TestATestEventQueuesADeliveryAndListsIt( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.handlers.Webhooks = webhooks.New( fixture.store , fixture.handlers.Settings )
	owner := fixture.signIn( t , fixture.owner.ID )
	id , _ := createdWebhook( t , owner )
	if status , reply := send( t , owner , "/api/owner/webhooks/"+id+"/test" , fiber.Map{} ); status != fiber.StatusAccepted {
		t.Fatalf( "%d %v" , status , reply )
	}
	status , page := owner.do( t , http.MethodGet , "/api/owner/webhooks/"+id+"/deliveries?limit=1" , nil )
	rows , _ := page[ "deliveries" ].( []any )
	if status != 200 || len( rows ) != 1 { t.Fatalf( "%d %v" , status , page ) }
	row := rows[ 0 ].( map[ string ]any )
	if row[ "event" ] != models.EventWebhookTest || row[ "status" ] != models.WebhookPending { t.Fatalf( "%v" , row ) }
	if _ , present := row[ "body" ]; present { t.Fatal( "the list carries the body" ) }
	if status , _ = owner.do( t , http.MethodGet , "/api/owner/webhooks/nope/deliveries" , nil ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

// The two doors reach the same rule, so an event from either should go out.
func TestDisablingAUserEmitsFromTheSharedHelper( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.handlers.Webhooks = webhooks.New( fixture.store , fixture.handlers.Settings )
	_ , hook , err := models.CreateWebhook( fixture.store , fixture.cfg.SecretKey , "x" , "https://a.example" , []string{ models.EventUserDisabled } , fixture.owner.ID )
	if err != nil { t.Fatal( err ) }
	if refused := fixture.handlers.setUserDisabled( fixture.owner.ID , fixture.alice.ID , true ); refused != nil { t.Fatalf( "%+v" , refused ) }
	rows , _ := models.ListWebhookDeliveries( fixture.store , hook.ID )
	if len( rows ) != 1 || strings.Contains( rows[ 0 ].Body , `"disabled":true` ) == false { t.Fatalf( "%+v" , rows ) }
}

// failedDelivery is a delivery for hook that has been given up on.
func failedDelivery( t *testing.T , fixture *authFixture , hook string ) ( id string ) {
	t.Helper()
	stored , err := models.GetWebhook( fixture.store , hook )
	if err != nil { t.Fatal( err ) }
	if err = models.EnqueueWebhookTest( fixture.store , stored ); err != nil { t.Fatal( err ) }
	deliveries , err := models.ListWebhookDeliveries( fixture.store , hook )
	if err != nil || len( deliveries ) != 1 { t.Fatalf( "%d %v" , len( deliveries ) , err ) }
	id = deliveries[ 0 ].ID
	if err = models.RecordWebhookAttempt( fixture.store , id , 500 , "boom" , false ); err != nil { t.Fatal( err ) }
	return
}

func TestResendingQueuesTheSameEventAsANewDelivery( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.handlers.Webhooks = webhooks.New( fixture.store , fixture.handlers.Settings )
	owner := fixture.signIn( t , fixture.owner.ID )
	hook , _ := createdWebhook( t , owner )
	failed := failedDelivery( t , fixture , hook )
	path := "/api/owner/webhooks/" + hook + "/deliveries/"

	status , reply := send( t , owner , path + failed + "/resend" , fiber.Map{} )
	if status != fiber.StatusAccepted { t.Fatalf( "%d %v" , status , reply ) }
	deliveries , _ := models.ListWebhookDeliveries( fixture.store , hook )
	if len( deliveries ) != 2 { t.Fatalf( "%d deliveries" , len( deliveries ) ) }
	var again , original *models.WebhookDelivery
	for _ , delivery := range deliveries {
		if delivery.ID == failed { original = delivery } else { again = delivery }
	}
	if original == nil || again == nil || original.Status != models.WebhookFailed {
		t.Fatalf( "the failed attempt should stay listed: %+v %+v" , original , again )
	}
	if again.Status != models.WebhookPending || again.Attempts != 0 || again.Body != original.Body || again.Event != original.Event {
		t.Fatalf( "%+v" , again )
	}
	if status , _ = send( t , owner , path + again.ID + "/resend" , fiber.Map{} ); status != fiber.StatusConflict {
		t.Fatalf( "a pending one: %d" , status )
	}
	if status , _ = send( t , owner , path + "nothing/resend" , fiber.Map{} ); status != fiber.StatusNotFound {
		t.Fatalf( "no such delivery: %d" , status )
	}
}

func TestADeliveryCannotBeResentThroughAnotherEndpoint( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.handlers.Webhooks = webhooks.New( fixture.store , fixture.handlers.Settings )
	owner := fixture.signIn( t , fixture.owner.ID )
	first , _ := createdWebhook( t , owner )
	second , _ := createdWebhook( t , owner )
	failed := failedDelivery( t , fixture , first )
	status , _ := send( t , owner , "/api/owner/webhooks/" + second + "/deliveries/" + failed + "/resend" , fiber.Map{} )
	if status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}
