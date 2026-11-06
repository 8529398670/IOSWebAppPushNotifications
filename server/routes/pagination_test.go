package routes

import (
	json "encoding/json"
	fmt "fmt"
	io "io"
	http "net/http"
	testing "testing"
	time "time"

	models "ipb/server/models"
)

func ( fixture *mcpFixture ) get( t *testing.T , key string , path string ) ( status int , reply map[ string ]any ) {
	t.Helper()
	request , _ := http.NewRequest( http.MethodGet , path , nil )
	request.Header.Set( "Authorization" , "Bearer "+key )
	response , err := fixture.app.Test( request )
	if err != nil { t.Fatal( err ) }
	raw , _ := io.ReadAll( response.Body )
	status = response.StatusCode
	json.Unmarshal( raw , &reply )
	return
}

func TestPageBodyCutsAndPointsAtTheNextPage( t *testing.T ) {
	rows := []int{ 1 , 2 , 3 , 4 , 5 }
	cases := []struct {
		limit , offset int
		count          int
		next           any
	}{
		{ 2 , 0 , 2 , 2 },
		{ 2 , 2 , 2 , 4 },
		{ 2 , 4 , 1 , nil },
		{ 5 , 0 , 5 , nil },
		{ 2 , 99 , 0 , nil },
	}
	for _ , item := range cases {
		body := pageBody( "rows" , rows , item.limit , item.offset )
		if got := len( body[ "rows" ].( []int ) ); got != item.count {
			t.Fatalf( "limit %d offset %d: %d rows" , item.limit , item.offset , got )
		}
		if body[ "next" ] != item.next || body[ "total" ] != 5 {
			t.Fatalf( "limit %d offset %d: %v" , item.limit , item.offset , body )
		}
	}
}

func TestListRoutesPage( t *testing.T ) {
	fixture := newMCPFixture( t )
	for index := 0; index < 5; index++ {
		models.CreateUser( fixture.store , fmt.Sprintf( "Person %d" , index ) , models.RoleUser )
	}

	status , first := fixture.get( t , fixture.admin_key , "/api/admin/users?limit=3" )
	if status != http.StatusOK || len( first[ "users" ].( []any ) ) != 3 || first[ "next" ] != float64( 3 ) || first[ "total" ] != float64( 7 ) {
		t.Fatalf( "first page: %d %v" , status , first )
	}
	_ , last := fixture.get( t , fixture.admin_key , "/api/admin/users?limit=3&offset=6" )
	if len( last[ "users" ].( []any ) ) != 1 || last[ "next" ] != nil {
		t.Fatalf( "last page: %v" , last )
	}
	_ , past := fixture.get( t , fixture.admin_key , "/api/admin/users?offset=50" )
	if rows , ok := past[ "users" ].( []any ); ok == false || len( rows ) != 0 {
		t.Fatalf( "a page past the end should be an empty list: %v" , past )
	}

	// Each list answers under its own name, with no arguments too. The key
	// lists and sessions need a browser session: see sessions_test.go.
	for path , name := range map[ string ]string{
		"/api/team":               "members",
		"/api/admin/invite-links": "invite_links",
	} {
		status , reply := fixture.get( t , fixture.admin_key , path )
		if _ , ok := reply[ name ].( []any ); status != http.StatusOK || ok == false {
			t.Fatalf( "%s: %d %v" , path , status , reply )
		}
	}
}

func TestListRoutesRefuseABadPage( t *testing.T ) {
	fixture := newMCPFixture( t )
	for _ , query := range []string{ "limit=0" , "limit=1001" , "limit=x" , "offset=-1" , "offset=x" } {
		if status , _ := fixture.get( t , fixture.admin_key , "/api/admin/users?"+query ); status != http.StatusBadRequest {
			t.Fatalf( "%s: status %d" , query , status )
		}
	}
}

// A key's bucket key is random, so pages only hold still if the list is sorted.
func TestAPIKeysListOldestFirst( t *testing.T ) {
	fixture := newMCPFixture( t )
	for index := 0; index < 8; index++ {
		time.Sleep( time.Millisecond )
		if _ , _ , err := models.IssueAPIKey( fixture.store , fixture.owner.ID , fmt.Sprintf( "key %d" , index ) , models.RoleUser , time.Hour ); err != nil {
			t.Fatal( err )
		}
	}
	for _ , load := range []func() ( []*models.APIKey , error ){
		func() ( []*models.APIKey , error ) { return models.ListAPIKeys( fixture.store ) },
		func() ( []*models.APIKey , error ) { return models.ListAPIKeysForUser( fixture.store , fixture.owner.ID ) },
	} {
		keys , err := load()
		if err != nil { t.Fatal( err ) }
		for index := 1; index < len( keys ); index++ {
			if keys[ index ].CreatedAt.Before( keys[ index-1 ].CreatedAt ) {
				t.Fatalf( "row %d is older than the one before it" , index )
			}
		}
	}
}

func TestMCPListToolsPage( t *testing.T ) {
	fixture := newMCPFixture( t )

	structured := func( reply map[ string ]any ) ( content map[ string ]any ) {
		result , _ := reply[ "result" ].( map[ string ]any )
		content , _ = result[ "structuredContent" ].( map[ string ]any )
		return
	}
	_ , reply := fixture.post( t , fixture.admin_key , callTool( "admin_list_users" , `{"limit":1}` ) )
	page := structured( reply )
	if len( page[ "users" ].( []any ) ) != 1 || page[ "next" ] != float64( 1 ) || page[ "total" ] != float64( 2 ) {
		t.Fatalf( "%v" , reply )
	}
	_ , reply = fixture.post( t , fixture.admin_key , callTool( "list_team" , `{}` ) )
	if page = structured( reply ); len( page[ "members" ].( []any ) ) != 2 || page[ "next" ] != nil {
		t.Fatalf( "no arguments should still work: %v" , reply )
	}
	_ , reply = fixture.post( t , fixture.admin_key , callTool( "admin_list_users" , `{"limit":5000}` ) )
	if result , _ := reply[ "result" ].( map[ string ]any ); result[ "isError" ] != true {
		t.Fatalf( "a limit over the maximum should be refused: %v" , reply )
	}
	_ , reply = fixture.post( t , fixture.admin_key , callTool( "admin_list_users" , `{"page":1}` ) )
	if reply[ "error" ] == nil {
		t.Fatalf( "an unknown argument should be invalid: %v" , reply )
	}
}

// Without the guard the static catch-all would answer a mistyped endpoint.
func TestAnUnknownAPIPathIsAJSON404( t *testing.T ) {
	fixture := newMCPFixture( t )
	status , reply := fixture.get( t , fixture.admin_key , "/api/nope" )
	if status != http.StatusNotFound || reply[ "error" ] != "not found" {
		t.Fatalf( "%d %v" , status , reply )
	}
}
