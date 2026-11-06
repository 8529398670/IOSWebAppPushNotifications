package push

import (
	json "encoding/json"
	errors "errors"
	url "net/url"
	strings "strings"
	testing "testing"

	encryption "ipb/server/encryption"
)

// An endpoint's path is the subscription's secret, so it must not reach a log.
func TestCauseDropsTheEndpoint( t *testing.T ) {
	failed := &url.Error{ Op: "Post" , URL: "https://web.push.apple.com/secret-path" , Err: errors.New( "timed out" ) }
	if got := Cause( failed ); got != "timed out" || strings.Contains( got , "secret-path" ) {
		t.Fatalf( "got %q" , got )
	}
}

func TestAllowedEndpoint( t *testing.T ) {
	cases := map[string]bool{
		"https://web.push.apple.com/abc":                true,
		"https://api.push.apple.com/abc":                true,
		"https://fcm.googleapis.com/fcm/send/abc":       true,
		"https://updates.push.services.mozilla.com/a":   true,
		"https://db5.notify.windows.com/w/?token=abc":   true,
		"https://web.push.apple.com:443/abc":            true,
		"http://web.push.apple.com/abc":                 false,
		"https://web.push.apple.com:8443/abc":           false,
		"https://user@web.push.apple.com/abc":           false,
		"https://web.push.apple.com.evil.example/abc":   false,
		"https://evilpush.apple.com/abc":                false,
		"https://localhost/abc":                         false,
		"https://169.254.169.254/latest/meta-data":      false,
		"not a url":                                     false,
		"":                                              false,
	}
	for endpoint , want := range cases {
		if got := AllowedEndpoint( endpoint ); got != want {
			t.Errorf( "%q: got %v, want %v" , endpoint , got , want )
		}
	}
}

func TestPayloadIsDeclarative( t *testing.T ) {
	raw , err := Payload( Notification{ Title: "Hi" , Body: "There" , Navigate: "https://x.example/a/b/" , Badge: 2 } )
	if err != nil { t.Fatal( err ) }
	var decoded struct {
		WebPush      int `json:"web_push"`
		Notification struct {
			Title    string `json:"title"`
			Navigate string `json:"navigate"`
			Badge    string `json:"app_badge"`
		} `json:"notification"`
	}
	if err = json.Unmarshal( raw , &decoded ); err != nil { t.Fatal( err ) }
	if decoded.WebPush != 8030 || decoded.Notification.Title != "Hi" || decoded.Notification.Badge != "2" {
		t.Fatalf( "payload %s" , raw )
	}
}

func TestSubscriptionGone( t *testing.T ) {
	cases := []struct {
		status int
		reason string
		want   bool
	}{
		{ 201 , "" , false },
		{ 404 , "" , true },
		{ 410 , "" , true },
		{ 400 , `{"reason":"BadWebPushToken"}` , true },
		{ 400 , `{"reason":"BadJwtToken"}` , false },
		{ 403 , `{"reason":"BadJwtToken"}` , false },
		{ 429 , "" , false },
		{ 500 , "" , false },
	}
	for _ , test := range cases {
		if got := subscriptionGone( test.status , test.reason ); got != test.want {
			t.Errorf( "%d %q: got %v" , test.status , test.reason , got )
		}
	}
}

// One character can take six bytes once encoded, so a message that fits by
// length can still be too big.
func TestPayloadFitsWhateverTheMessage( t *testing.T ) {
	for _ , body := range []string{ strings.Repeat( "<" , 1024 ) , strings.Repeat( "\n" , 1024 ) , strings.Repeat( "é" , 3000 ) , strings.Repeat( "\"" , 6000 ) } {
		raw , err := Payload( Notification{ Title: "Doorbell" , Body: body , Navigate: "https://x.example/#inbox" } )
		if err != nil { t.Fatal( err ) }
		if len( raw ) > encryption.WebPushMaxPlainText { t.Fatalf( "%d bytes" , len( raw ) ) }
	}
}
