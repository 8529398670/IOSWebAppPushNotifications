package models

import (
	json "encoding/json"
	strings "strings"
	testing "testing"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

func TestAWebhookSecretSurvivesARekey( t *testing.T ) {
	old_key , new_key := strings.Repeat( "ab" , 32 ) , strings.Repeat( "cd" , 32 )
	sealed , err := encryption.ChaChaEncryptString( old_key , "whsec_x" )
	if err != nil { t.Fatal( err ) }
	plain , _ := json.Marshal( &Webhook{ ID: "a" , Secret: sealed } )

	rewritten , err := RekeyRecord( old_key , new_key )( db.BucketWebhooks , plain )
	if err != nil { t.Fatal( err ) }
	var hook Webhook
	if err = json.Unmarshal( rewritten , &hook ); err != nil { t.Fatal( err ) }
	secret , err := OpenWebhookSecret( &hook , new_key )
	if err != nil || secret != "whsec_x" { t.Fatalf( "%q %v" , secret , err ) }
	if _ , err = OpenWebhookSecret( &hook , old_key ); err == nil { t.Fatal( "the old key still opens it" ) }
}

func TestValidWebhook( t *testing.T ) {
	if ValidWebhook( "x" , "https://a.example" , []string{ EventUserCreated } ) == false { t.Fatal( "valid" ) }
	if ValidWebhook( "x" , "https://a.example" , []string{ WebhookAllEvents } ) == false { t.Fatal( "valid" ) }
	if ValidWebhook( "" , "https://a.example" , []string{ EventUserCreated } ) { t.Fatal( "no name" ) }
	if ValidWebhook( "x" , "" , []string{ EventUserCreated } ) { t.Fatal( "no url" ) }
	if ValidWebhook( "x" , "https://a.example" , nil ) { t.Fatal( "no events" ) }
	if ValidWebhook( "x" , "https://a.example" , []string{ "made.up" } ) { t.Fatal( "unknown event" ) }
	if ValidWebhook( "x" , "https://a.example" , []string{ EventWebhookTest } ) { t.Fatal( "the test event is not a subscription" ) }
}

func TestPurgeWebhooksKeepsWhatIsRecent( t *testing.T ) {
	store := testStore( t )
	old := time.Now().UTC().Add( -8 * 24 * time.Hour )
	recent := time.Now().UTC().Add( -time.Hour )
	for id , finished := range map[string]*time.Time{ "old": &old , "recent": &recent , "pending": nil } {
		delivery := &WebhookDelivery{ ID: id , WebhookID: "a" , Status: WebhookPending , FinishedAt: finished }
		if err := store.Put( db.BucketWebhookDeliveries , []byte( id ) , delivery ); err != nil { t.Fatal( err ) }
	}
	removed , err := PurgeWebhooks( store )
	if err != nil || removed != 1 { t.Fatalf( "%d %v" , removed , err ) }
	rows , _ := ListWebhookDeliveries( store , "a" )
	if len( rows ) != 2 { t.Fatalf( "%d rows" , len( rows ) ) }
}
