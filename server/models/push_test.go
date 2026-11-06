package models

import (
	json "encoding/json"
	testing "testing"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

const pushTestKey = "0000000000000000000000000000000000000000000000000000000000000000"

func TestVAPIDKeysAreGeneratedOnce( t *testing.T ) {
	store := testStore( t )
	public_key , private_key , err := LoadVAPIDKeys( store , pushTestKey )
	if err != nil { t.Fatal( err ) }
	if public_key == "" || private_key == "" { t.Fatal( "empty key" ) }

	again_public , again_private , err := LoadVAPIDKeys( store , pushTestKey )
	if err != nil { t.Fatal( err ) }
	if again_public != public_key || again_private != private_key {
		t.Fatal( "a second load made a new pair, which would end every subscription" )
	}

	stored := &VAPIDKeys{}
	if err = store.Get( db.BucketPushKeys , vapidKeysID , stored ); err != nil { t.Fatal( err ) }
	if stored.PrivateKey == private_key {
		t.Fatal( "the private key is stored unsealed" )
	}
}

// Without its entry in rekeyFields, rotating secret.key would strand the
// private key, and every phone would have to subscribe again.
func TestVAPIDKeySurvivesRotation( t *testing.T ) {
	old_key := encryption.GenerateKeyHex()
	new_key := encryption.GenerateKeyHex()
	sealed , err := encryption.ChaChaEncryptString( old_key , "the private half" )
	if err != nil { t.Fatal( err ) }
	plain := []byte( `{"public_key":"p","private_key":"` + sealed + `"}` )

	rewritten , err := RekeyRecord( old_key , new_key )( db.BucketPushKeys , plain )
	if err != nil { t.Fatal( err ) }
	if string( rewritten ) == string( plain ) { t.Fatal( "the record was not rewritten" ) }

	stored := &VAPIDKeys{}
	if err = json.Unmarshal( rewritten , stored ); err != nil { t.Fatal( err ) }
	store := testStore( t )
	if err = store.Put( db.BucketPushKeys , vapidKeysID , stored ); err != nil { t.Fatal( err ) }
	_ , private_key , err := LoadVAPIDKeys( store , new_key )
	if err != nil { t.Fatal( err ) }
	if private_key != "the private half" { t.Fatalf( "got %q" , private_key ) }
}

func TestInstallLinksDoNotCancelEachOther( t *testing.T ) {
	store := testStore( t )
	user , err := CreateUser( store , "Alice" , RoleUser )
	if err != nil { t.Fatal( err ) }

	first , err := IssueInstallToken( store , user.ID , time.Hour )
	if err != nil { t.Fatal( err ) }
	second , err := IssueInstallToken( store , user.ID , time.Hour )
	if err != nil { t.Fatal( err ) }

	rules := SignInRules{ SessionTTL: time.Hour }
	if _ , err = RedeemLoginToken( store , first , rules ); err != nil { t.Fatalf( "first: %v" , err ) }
	if _ , err = RedeemLoginToken( store , second , rules ); err != nil { t.Fatalf( "second: %v" , err ) }
	if _ , err = RedeemLoginToken( store , first , rules ); err == nil {
		t.Fatal( "an install link worked twice" )
	}
}

func TestSubscribingAgainReplacesTheRow( t *testing.T ) {
	store := testStore( t )
	endpoint := "https://web.push.apple.com/abc"
	if err := SavePushSubscription( store , &PushSubscription{ UserID: 1 , Endpoint: endpoint } ); err != nil { t.Fatal( err ) }
	if err := SavePushSubscription( store , &PushSubscription{ UserID: 2 , Endpoint: endpoint } ); err != nil { t.Fatal( err ) }

	first , err := PushSubscriptionsFor( store , 1 )
	if err != nil { t.Fatal( err ) }
	second , err := PushSubscriptionsFor( store , 2 )
	if err != nil { t.Fatal( err ) }
	if len( first ) != 0 || len( second ) != 1 {
		t.Fatalf( "user 1 has %d, user 2 has %d" , len( first ) , len( second ) )
	}
}
