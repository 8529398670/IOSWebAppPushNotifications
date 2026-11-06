package webhooks

import (
	json "encoding/json"
	errors "errors"
	io "io"
	http "net/http"
	httptest "net/http/httptest"
	netip "net/netip"
	os "os"
	filepath "path/filepath"
	strconv "strconv"
	strings "strings"
	sync "sync"
	testing "testing"
	time "time"

	config "ipb/server/config"
	db "ipb/server/db"
	encryption "ipb/server/encryption"
	models "ipb/server/models"
)

var testKey = strings.Repeat( "ab" , 32 )

// The file both templates share, so the two cannot drift apart.
type sharedCases struct {
	Signatures []struct {
		Secret    string `json:"secret"`
		Timestamp int64  `json:"timestamp"`
		Body      string `json:"body"`
		Header    string `json:"header"`
	} `json:"signatures"`
	Blocked []string `json:"blocked"`
	Allowed []string `json:"allowed"`
	URLs    []struct {
		URL          string `json:"url"`
		AllowPrivate bool   `json:"allow_private"`
		OK           bool   `json:"ok"`
	} `json:"urls"`
}

func loadCases( t *testing.T ) ( cases sharedCases ) {
	t.Helper()
	raw , err := os.ReadFile( "webhook_cases.json" )
	if err != nil { t.Fatal( err ) }
	if err = json.Unmarshal( raw , &cases ); err != nil { t.Fatal( err ) }
	return
}

func TestSignatureMatchesTheSharedCases( t *testing.T ) {
	for _ , item := range loadCases( t ).Signatures {
		if got := Sign( item.Secret , item.Timestamp , item.Body ); got != item.Header {
			t.Fatalf( "%s: %s" , item.Secret , got )
		}
	}
}

func TestBlockedMatchesTheSharedCases( t *testing.T ) {
	cases := loadCases( t )
	for _ , value := range cases.Blocked {
		if Blocked( netip.MustParseAddr( value ) ) == false { t.Fatalf( "%s should be blocked" , value ) }
	}
	for _ , value := range cases.Allowed {
		if Blocked( netip.MustParseAddr( value ) ) { t.Fatalf( "%s should be allowed" , value ) }
	}
}

func TestCheckURLMatchesTheSharedCases( t *testing.T ) {
	for _ , item := range loadCases( t ).URLs {
		if err := CheckURL( item.URL , item.AllowPrivate ); ( err == nil ) != item.OK {
			t.Fatalf( "%s (allow_private %v): %v" , item.URL , item.AllowPrivate , err )
		}
	}
}

// fixture is a store, a dispatcher, and a receiver that answers with status.
type fixture struct {
	store      *db.Store
	cfg        *config.Config
	dispatcher *Dispatcher
	receiver   *httptest.Server
	hook       *models.Webhook
	secret     string

	lock     sync.Mutex
	status   int
	requests []*http.Request
	bodies   []string
}

func newFixture( t *testing.T , allow_private bool ) ( result *fixture ) {
	t.Helper()
	cfg := &config.Config{
		DatabasePath: filepath.Join( t.TempDir() , "test.db" ),
		SecretKey:    testKey,
		Webhooks:     config.WebhooksConfig{ Enabled: true , Timeout: 2 * time.Second , AllowPrivateTargets: allow_private },
	}
	store , err := db.Open( cfg )
	if err != nil { t.Fatal( err ) }
	t.Cleanup( func() { store.Close() } )

	result = &fixture{ store: store , cfg: cfg , status: 200 }
	result.dispatcher = New( store , config.NewStaticHolder( cfg ) )
	result.receiver = httptest.NewServer( http.HandlerFunc( func( writer http.ResponseWriter , request *http.Request ) {
		body , _ := io.ReadAll( request.Body )
		result.lock.Lock()
		defer result.lock.Unlock()
		result.requests = append( result.requests , request )
		result.bodies = append( result.bodies , string( body ) )
		if result.status == 302 { writer.Header().Set( "Location" , "/elsewhere" ) }
		writer.WriteHeader( result.status )
	} ) )
	t.Cleanup( result.receiver.Close )
	secret , hook , err := models.CreateWebhook( store , testKey , "Receiver" , result.receiver.URL+"/in?token=topsecret" , []string{ models.WebhookAllEvents } , 1 )
	if err != nil { t.Fatal( err ) }
	result.secret , result.hook = secret , hook
	return
}

func ( item *fixture ) deliveries( t *testing.T ) ( rows []*models.WebhookDelivery ) {
	t.Helper()
	rows , err := models.ListWebhookDeliveries( item.store , item.hook.ID )
	if err != nil { t.Fatal( err ) }
	return
}

func TestSwitchedOffNothingIsQueuedOrSent( t *testing.T ) {
	item := newFixture( t , true )
	item.dispatcher.Emit( models.EventUserCreated , map[string]any{ "user_id": 7 } )
	item.cfg.Webhooks.Enabled = false
	item.dispatcher.Emit( models.EventUserDeleted , map[string]any{ "user_id": 7 } )
	if rows := item.deliveries( t ); len( rows ) != 1 { t.Fatalf( "%d deliveries, want only the one queued while on" , len( rows ) ) }
	note , err := item.dispatcher.Run()
	if err != nil || note != "switched off" { t.Fatalf( "%q %v" , note , err ) }
	if len( item.requests ) != 0 { t.Fatalf( "%d requests while off" , len( item.requests ) ) }

	item.cfg.Webhooks.Enabled = true
	if note , err = item.dispatcher.Run(); err != nil || note != "sent 1, failed 0" { t.Fatalf( "%q %v" , note , err ) }
}

func TestASentEventIsSignedAndMarkedDelivered( t *testing.T ) {
	item := newFixture( t , true )
	item.dispatcher.Emit( models.EventUserCreated , map[string]any{ "user_id": 7 } )
	note , err := item.dispatcher.Run()
	if err != nil || note != "sent 1, failed 0" { t.Fatalf( "%q %v" , note , err ) }

	if len( item.requests ) != 1 { t.Fatalf( "%d requests" , len( item.requests ) ) }
	request , body := item.requests[ 0 ] , item.bodies[ 0 ]
	var payload struct {
		ID    string         `json:"id"`
		Event string         `json:"event"`
		Data  map[string]any `json:"data"`
	}
	if err = json.Unmarshal( []byte( body ) , &payload ); err != nil { t.Fatal( err ) }
	if payload.Event != models.EventUserCreated || payload.Data[ "user_id" ] != float64( 7 ) { t.Fatalf( "%s" , body ) }
	if request.Header.Get( "X-Webhook-Event" ) != payload.Event || request.Header.Get( "X-Webhook-Delivery" ) != payload.ID {
		t.Fatalf( "%v" , request.Header )
	}

	// What a receiver does with the header.
	parts := strings.SplitN( request.Header.Get( "X-Webhook-Signature" ) , "," , 2 )
	stamp := strings.TrimPrefix( parts[ 0 ] , "t=" )
	if parsed , parse_err := strconv.ParseInt( stamp , 10 , 64 ); parse_err != nil || time.Since( time.Unix( parsed , 0 ) ) > time.Minute {
		t.Fatalf( "timestamp %q" , stamp )
	}
	if strings.TrimPrefix( parts[ 1 ] , "v1=" ) != encryption.HMACSHA256Hex( item.secret , stamp+"."+body ) {
		t.Fatal( "the signature does not verify" )
	}

	rows := item.deliveries( t )
	if len( rows ) != 1 || rows[ 0 ].Status != models.WebhookDelivered || rows[ 0 ].Attempts != 1 || rows[ 0 ].LastStatus != 200 {
		t.Fatalf( "%+v" , rows[ 0 ] )
	}
	if note , _ = item.dispatcher.Run(); note != "nothing to send" { t.Fatalf( "sent twice: %s" , note ) }
}

func TestAFailureWaitsItsBackoffAndIsEventuallyGivenUpOn( t *testing.T ) {
	item := newFixture( t , true )
	item.status = 500
	item.dispatcher.Emit( models.EventUserDeleted , map[string]any{ "user_id": 7 } )
	if _ , err := item.dispatcher.Run(); err != nil { t.Fatal( err ) }

	rows := item.deliveries( t )
	row := rows[ 0 ]
	if row.Status != models.WebhookPending || row.Attempts != 1 || row.LastError != "status 500" { t.Fatalf( "%+v" , row ) }
	if wait := time.Until( row.NextAttemptAt ); wait < 50*time.Second || wait > time.Minute { t.Fatalf( "wait %s" , wait ) }
	if note , _ := item.dispatcher.Run(); note != "nothing to send" { t.Fatalf( "did not wait: %s" , note ) }

	for attempt := 2; attempt <= 6; attempt++ {
		if err := models.RecordWebhookAttempt( item.store , row.ID , 500 , "status 500" , true ); err != nil { t.Fatal( err ) }
	}
	row = item.deliveries( t )[ 0 ]
	if row.Status != models.WebhookFailed || row.Attempts != 6 || row.FinishedAt == nil { t.Fatalf( "%+v" , row ) }
}

func TestARecoveredReceiverGetsTheSameBody( t *testing.T ) {
	item := newFixture( t , true )
	item.status = 503
	item.dispatcher.Emit( models.EventUserDeleted , map[string]any{ "user_id": 7 } )
	item.dispatcher.Run()
	row := item.deliveries( t )[ 0 ]
	row.NextAttemptAt = time.Now().UTC().Add( -time.Second )
	if err := item.store.Put( db.BucketWebhookDeliveries , []byte( row.ID ) , row ); err != nil { t.Fatal( err ) }

	item.status = 200
	item.dispatcher.Run()
	if len( item.bodies ) != 2 || item.bodies[ 0 ] != item.bodies[ 1 ] { t.Fatalf( "%v" , item.bodies ) }
	if item.requests[ 0 ].Header.Get( "X-Webhook-Delivery" ) != item.requests[ 1 ].Header.Get( "X-Webhook-Delivery" ) {
		t.Fatal( "a retry must keep its delivery id, so a receiver can dedupe" )
	}
	if got := item.deliveries( t )[ 0 ]; got.Status != models.WebhookDelivered || got.LastError != "" { t.Fatalf( "%+v" , got ) }
}

func TestARedirectIsAFailureAndIsNotFollowed( t *testing.T ) {
	item := newFixture( t , true )
	item.status = 302
	item.dispatcher.Emit( models.EventUserDeleted , nil )
	item.dispatcher.Run()
	if len( item.requests ) != 1 { t.Fatalf( "followed it: %d requests" , len( item.requests ) ) }
	if row := item.deliveries( t )[ 0 ]; row.LastError != "status 302" { t.Fatalf( "%+v" , row ) }
}

func TestTheDialerRefusesAPrivateAddress( t *testing.T ) {
	item := newFixture( t , false )
	request , _ := http.NewRequest( http.MethodPost , item.receiver.URL , nil )
	_ , err := client( config.WebhooksConfig{ Timeout: time.Second } ).Do( request )
	if errors.Is( err , ErrPrivateTarget ) == false { t.Fatalf( "%v" , err ) }
	if len( item.requests ) != 0 { t.Fatal( "the request got through" ) }
}

// The saved address passed when allow_private_targets was on, then it was
// turned off: the check at send time is what catches that.
func TestASavedPrivateAddressIsRefusedAtSendTime( t *testing.T ) {
	item := newFixture( t , false )
	item.dispatcher.Emit( models.EventUserDeleted , nil )
	if _ , err := item.dispatcher.Run(); err != nil { t.Fatal( err ) }
	row := item.deliveries( t )[ 0 ]
	if row.Status != models.WebhookFailed || len( item.requests ) != 0 { t.Fatalf( "%+v" , row ) }
}

func TestAFailureNeverQuotesTheURL( t *testing.T ) {
	item := newFixture( t , true )
	item.receiver.Close()
	item.dispatcher.Emit( models.EventUserDeleted , nil )
	item.dispatcher.Run()
	row := item.deliveries( t )[ 0 ]
	if row.LastError == "" || strings.Contains( row.LastError , "topsecret" ) { t.Fatalf( "%q" , row.LastError ) }
}

func TestOnlyWantedEventsAreQueued( t *testing.T ) {
	item := newFixture( t , true )
	_ , _ , err := models.CreateWebhook( item.store , testKey , "Picky" , "https://example.com/in" , []string{ models.EventUserDeleted } , 1 )
	if err != nil { t.Fatal( err ) }
	if queued , _ := models.EnqueueWebhookEvent( item.store , models.EventUserCreated , nil ); queued != 1 { t.Fatalf( "%d" , queued ) }
	if queued , _ := models.EnqueueWebhookEvent( item.store , models.EventUserDeleted , nil ); queued != 2 { t.Fatalf( "%d" , queued ) }
	if err = models.SetWebhookEnabled( item.store , item.hook.ID , false ); err != nil { t.Fatal( err ) }
	if queued , _ := models.EnqueueWebhookEvent( item.store , models.EventUserDeleted , nil ); queued != 1 { t.Fatalf( "disabled: %d" , queued ) }
}

func TestAnEndpointSwitchedOffAfterQueueingStopsItsDeliveries( t *testing.T ) {
	item := newFixture( t , true )
	item.dispatcher.Emit( models.EventUserDeleted , nil )
	if err := models.SetWebhookEnabled( item.store , item.hook.ID , false ); err != nil { t.Fatal( err ) }
	item.dispatcher.Run()
	row := item.deliveries( t )[ 0 ]
	if row.Status != models.WebhookFailed || len( item.requests ) != 0 { t.Fatalf( "%+v" , row ) }
}

func TestANilDispatcherDropsEvents( t *testing.T ) {
	var dispatcher *Dispatcher
	dispatcher.Emit( models.EventUserDeleted , nil )
}

func TestEmitNudgesOnlyWhenSomethingWasQueued( t *testing.T ) {
	item := newFixture( t , true )
	nudges := 0
	item.dispatcher.Nudge = func() { nudges += 1 }
	item.dispatcher.Emit( models.EventUserDeleted , nil )
	if err := models.SetWebhookEnabled( item.store , item.hook.ID , false ); err != nil { t.Fatal( err ) }
	item.dispatcher.Emit( models.EventUserDeleted , nil )
	if nudges != 1 { t.Fatalf( "%d" , nudges ) }
}

// The custom dialer must not cost the certificate check.
func TestTLSIsStillVerified( t *testing.T ) {
	receiver := httptest.NewTLSServer( http.HandlerFunc( func( writer http.ResponseWriter , request *http.Request ) {
		writer.WriteHeader( http.StatusNoContent )
	} ) )
	defer receiver.Close()
	settings := config.WebhooksConfig{ Timeout: 2 * time.Second , AllowPrivateTargets: true }
	hook := &models.Webhook{ URL: receiver.URL }
	delivery := &models.WebhookDelivery{ ID: "a" , Event: models.EventWebhookTest , Body: "{}" }

	status , failure := send( client( settings ) , hook , "s" , delivery )
	if status != 0 || strings.Contains( failure , "certificate" ) == false {
		t.Fatalf( "an untrusted certificate went through: %d %q" , status , failure )
	}

	trusting := client( settings )
	trusting.Transport.( *http.Transport ).TLSClientConfig = receiver.Client().Transport.( *http.Transport ).TLSClientConfig
	if status , failure = send( trusting , hook , "s" , delivery ); status != http.StatusNoContent || failure != "" {
		t.Fatalf( "%d %q" , status , failure )
	}
}
