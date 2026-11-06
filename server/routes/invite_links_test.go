package routes

import (
	http "net/http"
	strings "strings"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	models "ipb/server/models"
)

// inviteLink is a link for ten people with a day to run, and its credential.
func inviteLink( t *testing.T , fixture *authFixture ) ( credential string , link *models.InviteLink ) {
	t.Helper()
	credential , link , err := models.IssueInviteLink( fixture.store , "Book club" , 10 , 24 * time.Hour , fixture.owner.ID )
	if err != nil { t.Fatal( err ) }
	return
}

func TestRenamingAnInviteLink( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	_ , link := inviteLink( t , fixture )
	path := "/api/admin/invite-links/" + link.ID + "/rename"

	status , reply := send( t , owner , path , fiber.Map{ "label": "  Choir  " } )
	if status != fiber.StatusOK || reply[ "label" ] != "Choir" { t.Fatalf( "%d %v" , status , reply ) }
	if status , _ = send( t , alice , path , fiber.Map{ "label": "x" } ); status != fiber.StatusForbidden { t.Fatalf( "%d" , status ) }
	if status , _ = send( t , owner , path , fiber.Map{ "label": "  " } ); status != fiber.StatusBadRequest { t.Fatalf( "%d" , status ) }

	// An undo that finds a different label leaves it alone, and says what is there.
	status , reply = send( t , owner , path , fiber.Map{ "label": "old" , "expect": "stale" } )
	if status != fiber.StatusConflict || reply[ "label" ] != "Choir" { t.Fatalf( "%d %v" , status , reply ) }

	models.DeleteInviteLink( fixture.store , link.ID , fixture.owner.ID )
	if status , _ = send( t , owner , path , fiber.Map{ "label": "gone" } ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

func TestChangingAnInviteLinksLimits( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	credential , link := inviteLink( t , fixture )
	path := "/api/admin/invite-links/" + link.ID + "/limits"
	for _ , name := range []string{ "Ann" , "Bo" } {
		if _ , _ , err := models.JoinInviteLink( fixture.store , credential , name , time.Hour ); err != nil { t.Fatal( err ) }
	}

	for _ , bad := range []fiber.Map{ {} , { "max_uses": 1001 } , { "max_uses": 5 , "days": 0 } , { "max_uses": 5 , "days": 366 } } {
		if status , _ := send( t , owner , path , bad ); status != fiber.StatusBadRequest { t.Fatalf( "%v: %d" , bad , status ) }
	}

	// Nobody can be left over the limit.
	if status , _ := send( t , owner , path , fiber.Map{ "max_uses": 1 } ); status != fiber.StatusBadRequest { t.Fatalf( "%d" , status ) }

	// Leaving days out keeps the expiry.
	status , reply := send( t , owner , path , fiber.Map{ "max_uses": 2 } )
	if status != fiber.StatusOK || reply[ "remaining" ] != float64( 0 ) { t.Fatalf( "%d %v" , status , reply ) }
	stored , _ := models.GetInviteLink( fixture.store , link.ID )
	if stored.ExpiresAt.Equal( link.ExpiresAt ) == false { t.Fatalf( "%v" , stored.ExpiresAt ) }
	if _ , _ , err := models.JoinInviteLink( fixture.store , credential , "Cy" , time.Hour ); err == nil { t.Fatal( "joined a full link" ) }

	status , _ = send( t , owner , path , fiber.Map{ "max_uses": 3 , "days": 30 } )
	if status != fiber.StatusOK { t.Fatalf( "%d" , status ) }
	stored , _ = models.GetInviteLink( fixture.store , link.ID )
	if stored.ExpiresAt.Before( time.Now().Add( 29 * 24 * time.Hour ) ) { t.Fatalf( "%v" , stored.ExpiresAt ) }
	if _ , _ , err := models.JoinInviteLink( fixture.store , credential , "Cy" , time.Hour ); err != nil { t.Fatal( err ) }
}

// A replacement would lock out the people who joined, so an old link can come back.
func TestAnExpiredInviteLinkCanBeExtended( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	credential , link , err := models.IssueInviteLink( fixture.store , "Old" , 5 , time.Nanosecond , fixture.owner.ID )
	if err != nil { t.Fatal( err ) }
	time.Sleep( time.Millisecond )
	if _ , err = models.LoadInviteLink( fixture.store , credential ); err == nil { t.Fatal( "expired link loaded" ) }

	status , _ := send( t , owner , "/api/admin/invite-links/" + link.ID + "/limits" , fiber.Map{ "max_uses": 5 , "days": 7 } )
	if status != fiber.StatusOK { t.Fatalf( "%d" , status ) }
	if _ , err = models.LoadInviteLink( fixture.store , credential ); err != nil { t.Fatal( err ) }
}

func TestSwitchingAnInviteLinkBackOn( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	credential , link := inviteLink( t , fixture )
	path := "/api/admin/invite-links/" + link.ID + "/switch-on"

	models.RevokeInviteLink( fixture.store , link.ID )
	if _ , err := models.LoadInviteLink( fixture.store , credential ); err == nil { t.Fatal( "switched off link loaded" ) }
	if status , _ := send( t , alice , path , fiber.Map{} ); status != fiber.StatusForbidden { t.Fatalf( "%d" , status ) }

	status , reply := send( t , owner , path , fiber.Map{} )
	if status != fiber.StatusOK || reply[ "live" ] != true { t.Fatalf( "%d %v" , status , reply ) }
	if _ , err := models.LoadInviteLink( fixture.store , credential ); err != nil { t.Fatal( err ) }

	models.DeleteInviteLink( fixture.store , link.ID , fixture.owner.ID )
	if status , _ = send( t , owner , path , fiber.Map{} ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

func TestAKeyCannotReopenOrGrowAnInviteLink( t *testing.T ) {
	fixture := newAuthFixture( t )
	credential , _ , err := models.IssueAPIKey( fixture.store , fixture.owner.ID , "script" , models.RoleAdmin , time.Hour )
	if err != nil { t.Fatal( err ) }
	_ , link := inviteLink( t , fixture )
	models.RevokeInviteLink( fixture.store , link.ID )
	for _ , route := range []string{ "/rename" , "/limits" , "/switch-on" } {
		request , _ := http.NewRequest( http.MethodPost , "/api/admin/invite-links/" + link.ID + route , strings.NewReader( `{"label":"x","max_uses":999}` ) )
		request.Header.Set( "Content-Type" , "application/json" )
		request.Header.Set( "Authorization" , "Bearer " + credential )
		response , test_err := fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
		if test_err != nil { t.Fatal( test_err ) }
		if response.StatusCode != fiber.StatusForbidden { t.Fatalf( "%s: %d" , route , response.StatusCode ) }
	}
	stored , _ := models.GetInviteLink( fixture.store , link.ID )
	if stored.RevokedAt == nil || stored.MaxUses != 10 || stored.Label != "Book club" { t.Fatalf( "%+v" , stored ) }
}
