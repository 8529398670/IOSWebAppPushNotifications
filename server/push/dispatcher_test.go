package push

import (
	base64 "encoding/base64"
	filepath "path/filepath"
	ecdh "crypto/ecdh"
	random "crypto/rand"
	http "net/http"
	httptest "net/http/httptest"
	sync "sync"
	testing "testing"
	time "time"

	config "ipb/server/config"
	db "ipb/server/db"
	models "ipb/server/models"
)

// fakeService is a push service that answers from a list, then with its usual.
type fakeService struct {
	lock    sync.Mutex
	server  *httptest.Server
	answers []int
	usual   int
	calls   int
}

func newFakeService( t *testing.T , usual int , answers ...int ) ( service *fakeService ) {
	t.Helper()
	service = &fakeService{ answers: answers , usual: usual }
	service.server = httptest.NewServer( http.HandlerFunc( func( writer http.ResponseWriter , _ *http.Request ) {
		service.lock.Lock()
		defer service.lock.Unlock()
		service.calls += 1
		status := service.usual
		if len( service.answers ) > 0 {
			status = service.answers[ 0 ]
			service.answers = service.answers[ 1: ]
		}
		writer.WriteHeader( status )
	} ) )
	t.Cleanup( service.server.Close )
	return
}

func ( service *fakeService ) count() ( calls int ) {
	service.lock.Lock()
	defer service.lock.Unlock()
	calls = service.calls
	return
}

type fixture struct {
	store      *db.Store
	dispatcher *Dispatcher
	app        *models.PushApp
	user       *models.User
}

func newFixture( t *testing.T , service *fakeService ) ( built *fixture ) {
	t.Helper()
	cfg := &config.Config{
		DatabasePath: filepath.Join( t.TempDir() , "test.db" ),
		SecretKey:    "0000000000000000000000000000000000000000000000000000000000000000",
		URL:          "https://ipb.example.com",
		Push:         config.PushConfig{ Subject: "https://ipb.example.com" },
	}
	store , err := db.Open( cfg )
	if err != nil { t.Fatal( err ) }
	t.Cleanup( func() { store.Close() } )

	user , err := models.CreateUser( store , "Alice" , models.RoleUser )
	if err != nil { t.Fatal( err ) }
	app , _ , err := models.CreatePushApp( store , user.ID , "Doorbell" )
	if err != nil { t.Fatal( err ) }

	dispatcher := New( store , config.NewStaticHolder( cfg ) )
	dispatcher.client = service.server.Client()
	dispatcher.allow = func( string ) bool { return true }
	built = &fixture{ store: store , dispatcher: dispatcher , app: app , user: user }
	subscribe( t , store , user.ID , service.server.URL + "/device" )
	return
}

func subscribe( t *testing.T , store *db.Store , user_id uint64 , endpoint string ) {
	t.Helper()
	key , err := ecdh.P256().GenerateKey( random.Reader )
	if err != nil { t.Fatal( err ) }
	subscription := &models.PushSubscription{
		UserID:   user_id,
		Endpoint: endpoint,
		P256dh:   base64.RawURLEncoding.EncodeToString( key.PublicKey().Bytes() ),
		Auth:     base64.RawURLEncoding.EncodeToString( make( []byte , 16 ) ),
	}
	if err = models.SavePushSubscription( store , subscription ); err != nil { t.Fatal( err ) }
}

func ( built *fixture ) sendTo( t *testing.T , priority int , user_ids ...uint64 ) {
	t.Helper()
	_ , _ , err := models.EnqueueMessage( built.store , built.app , user_ids , models.OutgoingMessage{
		Body: "Someone is at the door" , Priority: priority , TTL: time.Hour , RepeatEvery: time.Hour , RepeatFor: time.Hour * 2,
	} )
	if err != nil { t.Fatal( err ) }
}

func queued( t *testing.T , store *db.Store ) ( rows []*models.PushDelivery ) {
	t.Helper()
	err := store.ForEach( db.BucketPushDeliveries ,
		func() any { return &models.PushDelivery{} } ,
		func( _ []byte , item any ) bool {
			rows = append( rows , item.( *models.PushDelivery ) )
			return true
		} )
	if err != nil { t.Fatal( err ) }
	return
}

func TestADeliveredPushLeavesTheOutbox( t *testing.T ) {
	service := newFakeService( t , http.StatusCreated )
	built := newFixture( t , service )
	built.sendTo( t , models.PriorityNormal , built.user.ID )

	if _ , err := built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	if service.count() != 1 { t.Fatalf( "%d calls" , service.count() ) }
	if rows := queued( t , built.store ); len( rows ) != 0 { t.Fatalf( "%d rows left" , len( rows ) ) }
}

// The first retry falls inside holdFor, so one run sees it through.
func TestAFailureIsRetried( t *testing.T ) {
	service := newFakeService( t , http.StatusCreated , http.StatusServiceUnavailable )
	built := newFixture( t , service )
	built.sendTo( t , models.PriorityNormal , built.user.ID )

	if _ , err := built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	if service.count() != 2 { t.Fatalf( "%d calls" , service.count() ) }
	if rows := queued( t , built.store ); len( rows ) != 0 { t.Fatalf( "%d rows left" , len( rows ) ) }
}

func TestARefusalIsNotRetried( t *testing.T ) {
	service := newFakeService( t , http.StatusForbidden )
	built := newFixture( t , service )
	built.sendTo( t , models.PriorityNormal , built.user.ID )

	if _ , err := built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	if service.count() != 1 { t.Fatalf( "%d calls" , service.count() ) }
	if rows := queued( t , built.store ); len( rows ) != 0 { t.Fatalf( "%d rows left" , len( rows ) ) }
	devices , err := models.PushSubscriptionsFor( built.store , built.user.ID )
	if err != nil { t.Fatal( err ) }
	if len( devices ) != 1 { t.Fatal( "a refusal must not cost the device" ) }
}

func TestAGoneDeviceIsForgotten( t *testing.T ) {
	service := newFakeService( t , http.StatusGone )
	built := newFixture( t , service )
	built.sendTo( t , models.PriorityNormal , built.user.ID )

	if _ , err := built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	devices , err := models.PushSubscriptionsFor( built.store , built.user.ID )
	if err != nil { t.Fatal( err ) }
	if len( devices ) != 0 { t.Fatal( "the device is still there" ) }
	if rows := queued( t , built.store ); len( rows ) != 0 { t.Fatalf( "%d rows left" , len( rows ) ) }
}

func TestAGivenUpDeliveryLeavesTheOutbox( t *testing.T ) {
	service := newFakeService( t , http.StatusServiceUnavailable )
	built := newFixture( t , service )
	built.sendTo( t , models.PriorityNormal , built.user.ID )

	row := queued( t , built.store )[ 0 ]
	row.Attempts = len( retryAfter )
	if err := built.store.Put( db.BucketPushDeliveries , []byte( row.ID ) , row ); err != nil { t.Fatal( err ) }

	if _ , err := built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	if rows := queued( t , built.store ); len( rows ) != 0 { t.Fatalf( "%d rows left" , len( rows ) ) }
}

func TestAMutedAppReachesTheInboxWithoutAPush( t *testing.T ) {
	service := newFakeService( t , http.StatusCreated )
	built := newFixture( t , service )
	if err := models.SetAppMuted( built.store , built.user.ID , built.app.ID , true ); err != nil { t.Fatal( err ) }
	built.sendTo( t , models.PriorityNormal , built.user.ID )

	if _ , err := built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	if service.count() != 0 { t.Fatal( "a muted app sent a push" ) }
	items , err := models.ListInbox( built.store , built.user.ID , "" )
	if err != nil { t.Fatal( err ) }
	if len( items ) != 1 { t.Fatalf( "%d items" , len( items ) ) }
}

func TestInboxOnlySendsNoPush( t *testing.T ) {
	service := newFakeService( t , http.StatusCreated )
	built := newFixture( t , service )
	built.sendTo( t , models.PriorityInboxOnly , built.user.ID )

	if _ , err := built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	if service.count() != 0 { t.Fatal( "priority -2 sent a push" ) }
}

func TestAGroupSendSkipsDisabledAndMutedPeople( t *testing.T ) {
	service := newFakeService( t , http.StatusCreated )
	built := newFixture( t , service )
	store := built.store
	muted , err := models.CreateUser( store , "Bob" , models.RoleUser )
	if err != nil { t.Fatal( err ) }
	disabled , err := models.CreateUser( store , "Carol" , models.RoleUser )
	if err != nil { t.Fatal( err ) }
	subscribe( t , store , muted.ID , service.server.URL + "/bob" )
	subscribe( t , store , disabled.ID , service.server.URL + "/carol" )
	if err = models.SetAppMuted( store , muted.ID , built.app.ID , true ); err != nil { t.Fatal( err ) }
	now := time.Now().UTC()
	disabled.DisabledAt = &now
	if err = models.SaveUser( store , disabled ); err != nil { t.Fatal( err ) }

	group , err := models.CreatePushGroup( store , built.user.ID , "Family" , []uint64{ built.user.ID , muted.ID , disabled.ID } )
	if err != nil { t.Fatal( err ) }
	user_ids , err := models.ResolveRecipient( store , group.Key )
	if err != nil { t.Fatal( err ) }
	built.sendTo( t , models.PriorityNormal , user_ids... )

	if _ , err = built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	if service.count() != 1 { t.Fatalf( "%d pushes, want 1" , service.count() ) }
	for _ , test := range []struct {
		id   uint64
		want int
	}{ { built.user.ID , 1 } , { muted.ID , 1 } , { disabled.ID , 0 } } {
		items , list_err := models.ListInbox( store , test.id , "" )
		if list_err != nil { t.Fatal( list_err ) }
		if len( items ) != test.want { t.Fatalf( "user %d has %d items, want %d" , test.id , len( items ) , test.want ) }
	}
}

func TestARepeatRunsUntilRead( t *testing.T ) {
	service := newFakeService( t , http.StatusCreated )
	built := newFixture( t , service )
	built.sendTo( t , models.PriorityRepeat , built.user.ID )
	if _ , err := built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	if service.count() != 1 { t.Fatalf( "%d calls" , service.count() ) }

	later := time.Now().UTC().Add( 90 * time.Minute )
	queued_now , err := models.QueueDueRepeats( built.store , later )
	if err != nil { t.Fatal( err ) }
	if queued_now != 1 { t.Fatalf( "queued %d" , queued_now ) }
	if _ , err = built.dispatcher.Run(); err != nil { t.Fatal( err ) }
	if service.count() != 2 { t.Fatalf( "%d calls after the repeat" , service.count() ) }

	items , err := models.ListInbox( built.store , built.user.ID , "" )
	if err != nil { t.Fatal( err ) }
	if err = models.MarkInboxRead( built.store , built.user.ID , items[ 0 ].ID ); err != nil { t.Fatal( err ) }
	queued_now , err = models.QueueDueRepeats( built.store , later.Add( 2 * time.Hour ) )
	if err != nil { t.Fatal( err ) }
	if queued_now != 0 { t.Fatal( "a read message repeated" ) }
}

func TestARepeatStopsWhenItRunsOut( t *testing.T ) {
	service := newFakeService( t , http.StatusCreated )
	built := newFixture( t , service )
	built.sendTo( t , models.PriorityRepeat , built.user.ID )
	if _ , err := built.dispatcher.Run(); err != nil { t.Fatal( err ) }

	queued_now , err := models.QueueDueRepeats( built.store , time.Now().UTC().Add( 3 * time.Hour ) )
	if err != nil { t.Fatal( err ) }
	if queued_now != 0 { t.Fatal( "an expired message repeated" ) }
	next , err := models.NextRepeatAt( built.store )
	if err != nil { t.Fatal( err ) }
	if next.IsZero() == false { t.Fatal( "the repeat is still queued" ) }
}
