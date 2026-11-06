package routes

import (
	fmt "fmt"
	http "net/http"
	strings "strings"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	models "ipb/server/models"
)

// Admins editing other accounts: who may touch whom, and what a change of role
// does to what the account already holds.

func userPath( user *models.User , verb string ) ( path string ) {
	path = fmt.Sprintf( "/api/admin/users/%d/%s" , user.ID , verb )
	return
}

func secondAdmin( t *testing.T , fixture *authFixture ) ( admin *models.User ) {
	t.Helper()
	admin , err := models.CreateUser( fixture.store , "Second admin" , models.RoleAdmin )
	if err != nil { t.Fatal( err ) }
	return
}

func TestRenamingSomeoneElse( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	path := userPath( fixture.alice , "rename" )

	status , reply := send( t , owner , path , fiber.Map{ "display_name": "  Alice B  " } )
	if status != fiber.StatusOK || reply[ "display_name" ] != "Alice B" { t.Fatalf( "%d %v" , status , reply ) }
	if status , _ = send( t , owner , path , fiber.Map{ "display_name": "  " } ); status != fiber.StatusBadRequest { t.Fatalf( "%d" , status ) }
	if status , _ = send( t , alice , path , fiber.Map{ "display_name": "x" } ); status != fiber.StatusForbidden { t.Fatalf( "%d" , status ) }

	// An undo that finds a different name leaves it alone, and says what is there.
	status , reply = send( t , owner , path , fiber.Map{ "display_name": "old" , "expect": "stale" } )
	if status != fiber.StatusConflict || reply[ "display_name" ] != "Alice B" { t.Fatalf( "%d %v" , status , reply ) }

	if status , _ = send( t , owner , "/api/admin/users/9999/rename" , fiber.Map{ "display_name": "x" } ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

func TestOnlyTheOwnerRenamesAnAdmin( t *testing.T ) {
	fixture := newAuthFixture( t )
	second := secondAdmin( t , fixture )
	owner := fixture.signIn( t , fixture.owner.ID )
	admin := fixture.signIn( t , second.ID )

	if status , _ := send( t , admin , userPath( fixture.alice , "rename" ) , fiber.Map{ "display_name": "fine" } ); status != fiber.StatusOK { t.Fatalf( "%d" , status ) }
	if status , _ := send( t , admin , userPath( fixture.owner , "rename" ) , fiber.Map{ "display_name": "x" } ); status != fiber.StatusForbidden { t.Fatalf( "%d" , status ) }
	if status , _ := send( t , admin , userPath( second , "rename" ) , fiber.Map{ "display_name": "x" } ); status != fiber.StatusForbidden { t.Fatalf( "%d" , status ) }
	if status , _ := send( t , owner , userPath( second , "rename" ) , fiber.Map{ "display_name": "Sam" } ); status != fiber.StatusOK { t.Fatalf( "%d" , status ) }
}

func TestBecomingAnAdminEndsWhatWasOpen( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	credential , err := models.IssueLoginToken( fixture.store , fixture.alice.ID , time.Hour )
	if err != nil { t.Fatal( err ) }
	path := userPath( fixture.alice , "role" )

	if status , _ := send( t , owner , path , fiber.Map{ "role": "owner" } ); status != fiber.StatusBadRequest { t.Fatalf( "%d" , status ) }
	if status , _ := send( t , alice , path , fiber.Map{ "role": "admin" } ); status != fiber.StatusForbidden { t.Fatalf( "%d" , status ) }
	if status , reply := send( t , owner , path , fiber.Map{ "role": "admin" } ); status != fiber.StatusOK { t.Fatalf( "%d %v" , status , reply ) }

	user , _ := models.GetUser( fixture.store , fixture.alice.ID )
	if user.IsAdmin() == false { t.Fatalf( "%+v" , user ) }
	if status , _ := alice.do( t , http.MethodGet , "/api/me" , nil ); status != fiber.StatusUnauthorized { t.Fatalf( "%d" , status ) }
	if _ , redeem_err := models.RedeemLoginToken( fixture.store , credential , models.SignInRules{ SessionTTL: time.Hour } ); redeem_err == nil {
		t.Fatal( "a link from before the promotion still works" )
	}
	if status , reply := fixture.signIn( t , fixture.alice.ID ).do( t , http.MethodGet , "/api/me" , nil ); status != fiber.StatusOK || reply[ "role" ] != "admin" {
		t.Fatalf( "%d %v" , status , reply )
	}
}

func TestAskingForTheRoleTheyHaveChangesNothing( t *testing.T ) {
	fixture := newAuthFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	if status , _ := send( t , owner , userPath( fixture.alice , "role" ) , fiber.Map{ "role": "user" } ); status != fiber.StatusOK { t.Fatalf( "%d" , status ) }
	if status , _ := alice.do( t , http.MethodGet , "/api/me" , nil ); status != fiber.StatusOK { t.Fatalf( "%d" , status ) }
}

func TestLosingAdminRightsAppliesAtOnce( t *testing.T ) {
	fixture := newAuthFixture( t )
	second := secondAdmin( t , fixture )
	owner := fixture.signIn( t , fixture.owner.ID )
	admin := fixture.signIn( t , second.ID )
	link_credential , _ , err := models.IssueInviteLink( fixture.store , "Club" , 5 , time.Hour , second.ID )
	if err != nil { t.Fatal( err ) }

	if status , _ := send( t , owner , userPath( second , "role" ) , fiber.Map{ "role": "user" } ); status != fiber.StatusOK { t.Fatalf( "%d" , status ) }

	// Still signed in, but as a user, and the link they made has stopped.
	if status , reply := admin.do( t , http.MethodGet , "/api/me" , nil ); status != fiber.StatusOK || reply[ "role" ] != "user" { t.Fatalf( "%d %v" , status , reply ) }
	if status , _ := admin.do( t , http.MethodGet , "/api/admin/users" , nil ); status != fiber.StatusForbidden { t.Fatalf( "%d" , status ) }
	if _ , load_err := models.LoadInviteLink( fixture.store , link_credential ); load_err == nil { t.Fatal( "their link still works" ) }

	// Made an admin again, the link is back, as the screen's question says.
	if status , _ := send( t , owner , userPath( second , "role" ) , fiber.Map{ "role": "admin" } ); status != fiber.StatusOK { t.Fatalf( "%d" , status ) }
	if _ , load_err := models.LoadInviteLink( fixture.store , link_credential ); load_err != nil { t.Fatal( load_err ) }
}

func TestWhoMayChangeWhoseRole( t *testing.T ) {
	fixture := newAuthFixture( t )
	second := secondAdmin( t , fixture )
	third := secondAdmin( t , fixture )
	owner := fixture.signIn( t , fixture.owner.ID )
	admin := fixture.signIn( t , second.ID )

	cases := []struct {
		client *browser
		target *models.User
		role   string
		want   int
	}{
		{ owner , fixture.owner , "user" , fiber.StatusBadRequest }, // yourself
		{ admin , second , "user" , fiber.StatusBadRequest },        // yourself
		{ admin , fixture.owner , "user" , fiber.StatusForbidden },  // the owner
		{ admin , third , "user" , fiber.StatusForbidden },          // another admin
		{ admin , fixture.alice , "admin" , fiber.StatusOK },        // anyone may make one
	}
	for index , item := range cases {
		if status , reply := send( t , item.client , userPath( item.target , "role" ) , fiber.Map{ "role": item.role } ); status != item.want {
			t.Fatalf( "case %d: %d %v" , index , status , reply )
		}
	}
	if status , _ := send( t , owner , "/api/admin/users/9999/role" , fiber.Map{ "role": "admin" } ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

func TestAnAdminKeyCannotChangeAnAccount( t *testing.T ) {
	fixture := newAuthFixture( t )
	key , _ , err := models.IssueAPIKey( fixture.store , fixture.owner.ID , "ops" , models.RoleAdmin , time.Hour )
	if err != nil { t.Fatal( err ) }
	for _ , verb := range []string{ "rename" , "role" } {
		request , _ := http.NewRequest( http.MethodPost , userPath( fixture.alice , verb ) , strings.NewReader( `{"display_name":"x","role":"admin"}` ) )
		request.Header.Set( "Authorization" , "Bearer " + key )
		request.Header.Set( "Content-Type" , "application/json" )
		response , test_err := fixture.app.Test( request )
		if test_err != nil { t.Fatal( test_err ) }
		if response.StatusCode != fiber.StatusForbidden { t.Fatalf( "%s: %d" , verb , response.StatusCode ) }
	}
}
