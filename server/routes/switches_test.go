package routes

import (
	http "net/http"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	models "ipb/server/models"
)

// What auth.invite_links and webhooks.enabled do while they are off, and that
// switching one back on restores what was there.

func TestInviteLinksSwitchedOffAndBackOn( t *testing.T ) {
	fixture := newAuthFixture( t )
	credential , _ , err := models.IssueInviteLink( fixture.store , "Club" , 10 , 24*time.Hour , fixture.owner.ID )
	if err != nil { t.Fatal( err ) }
	bob := fixture.browser()
	if status , reply := bob.post( t , "/api/join/create" , fiber.Map{ "credential": credential , "display_name": "Bob" } ); status != 201 {
		t.Fatalf( "join: %d %v" , status , reply )
	}
	owner := fixture.browser()
	owner.cookie = sessionCookie( t , fixture.store , fixture.cfg , fixture.owner.ID )
	csrf := bob.csrf( t )

	fixture.cfg.InviteLinksEnabled = false
	visitor := fixture.browser()
	for _ , path := range []string{ "/api/join/info" , "/api/join/match" , "/api/join/claim" , "/api/join/create" } {
		if status , _ := visitor.post( t , path , fiber.Map{ "credential": credential , "display_name": "Eve" } ); status != 404 {
			t.Errorf( "%s: status %d, want 404" , path , status )
		}
	}
	if status , _ := visitor.do( t , http.MethodGet , "/join/" + credential , nil ); status != 404 {
		t.Errorf( "the join page: status %d, want 404" , status )
	}
	if status , _ := owner.do( t , http.MethodGet , "/api/admin/invite-links" , nil ); status != 404 {
		t.Errorf( "the admin list: status %d, want 404" , status )
	}
	if status , _ := bob.post( t , "/api/account/pin" , fiber.Map{ "pin": "1234" , "csrf_token": csrf } ); status != 404 {
		t.Errorf( "setting a PIN: status %d, want 404" , status )
	}
	if _ , me := bob.do( t , http.MethodGet , "/api/me" , nil ); me[ "invite_links_enabled" ] != false {
		t.Errorf( "/api/me should say it is off: %v" , me )
	}

	fixture.cfg.InviteLinksEnabled = true
	if status , reply := fixture.browser().post( t , "/api/join/create" , fiber.Map{ "credential": credential , "display_name": "Eve" } ); status != 201 {
		t.Fatalf( "the same link should work again: %d %v" , status , reply )
	}
}

func TestInviteToolsFollowTheSwitch( t *testing.T ) {
	fixture := newMCPFixture( t )
	listed := func() ( found bool ) {
		_ , reply := fixture.post( t , fixture.admin_key , rpc( "tools/list" , "{}" ) )
		for _ , name := range toolNames( reply ) {
			if name == "admin_list_invite_links" { found = true }
		}
		return
	}
	if listed() == false { t.Fatal( "the tool should be listed while invite links are on" ) }
	fixture.cfg.InviteLinksEnabled = false
	if listed() { t.Fatal( "the tool should not be listed while invite links are off" ) }
	_ , reply := fixture.post( t , fixture.admin_key , callTool( "admin_list_invite_links" , "{}" ) )
	if reply[ "error" ] == nil { t.Fatalf( "calling it should answer like an unknown tool: %v" , reply ) }
}

func TestWebhooksSwitchedOff( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.browser()
	owner.cookie = sessionCookie( t , fixture.store , fixture.cfg , fixture.owner.ID )
	if status , _ := owner.do( t , http.MethodGet , "/api/owner/webhooks" , nil ); status != 200 {
		t.Fatalf( "on: status %d" , status )
	}
	fixture.cfg.Webhooks.Enabled = false
	if status , _ := owner.do( t , http.MethodGet , "/api/owner/webhooks" , nil ); status != 404 {
		t.Errorf( "off: status %d, want 404" , status )
	}
	if _ , me := owner.do( t , http.MethodGet , "/api/me" , nil ); me[ "webhooks_enabled" ] != false {
		t.Errorf( "/api/me should say it is off: %v" , me )
	}
}
