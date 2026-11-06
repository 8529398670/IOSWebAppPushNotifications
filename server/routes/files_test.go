package routes

import (
	bytes "bytes"
	json "encoding/json"
	fmt "fmt"
	io "io"
	http "net/http"
	os "os"
	filepath "path/filepath"
	strings "strings"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
	models "ipb/server/models"
)

// Uploads through the real routes: who may reach whose file, what a download
// says about itself, and a client resuming.

func newFilesFixture( t *testing.T ) ( fixture *authFixture ) {
	t.Helper()
	fixture = newAuthFixture( t )
	directory := t.TempDir()
	fixture.cfg.Files = config.FilesConfig{
		Enabled:           true,
		MaxFileBytes:      16 << 20,
		QuotaBytesPerUser: 16 << 20,
		AbandonedAfter:    time.Hour,
		Dir:               filepath.Join( directory , "storage" , "files" ),
		UploadsDir:        filepath.Join( directory , "uploads" ),
	}
	return
}

// raw is one request with a binary body, or none. It answers the whole body.
func raw( t *testing.T , client *browser , method string , path string , body []byte , headers map[ string ]string ) ( response *http.Response , content []byte ) {
	t.Helper()
	request , _ := http.NewRequest( method , path , bytes.NewReader( body ) )
	if client.cookie != "" {
		request.Header.Set( "Cookie" , client.cookie )
	}
	for name , value := range headers {
		request.Header.Set( name , value )
	}
	response , err := client.fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
	if err != nil { t.Fatal( err ) }
	content , _ = io.ReadAll( response.Body )
	return
}

func sendPiece( t *testing.T , client *browser , file_id string , index int , piece []byte ) ( status int , reply map[ string ]any ) {
	t.Helper()
	response , content := raw( t , client , http.MethodPost , fmt.Sprintf( "/api/files/%s/chunks/%d" , file_id , index ) , piece , map[ string ]string{ "X-CSRF-Token": client.csrf( t ) } )
	status = response.StatusCode
	json.Unmarshal( content , &reply )
	return
}

// uploaded puts content up the way files.js does and answers the file's id.
func uploaded( t *testing.T , client *browser , name string , content []byte ) ( file_id string ) {
	t.Helper()
	status , reply := send( t , client , "/api/files" , fiber.Map{ "name": name , "size": len( content ) , "type": "text/html" } )
	if status != fiber.StatusCreated { t.Fatalf( "create: %d %v" , status , reply ) }
	file_id , _ = reply[ "id" ].( string )
	if int( reply[ "chunk_bytes" ].( float64 ) ) != config.FileChunkBytes { t.Fatalf( "%v" , reply ) }
	for index := 0 ; index * config.FileChunkBytes < len( content ) ; index++ {
		start := index * config.FileChunkBytes
		end := min( start + config.FileChunkBytes , len( content ) )
		if status , reply = sendPiece( t , client , file_id , index , content[ start:end ] ); status != 200 { t.Fatalf( "piece %d: %d %v" , index , status , reply ) }
	}
	if status , reply = send( t , client , "/api/files/" + file_id + "/finish" , fiber.Map{} ); status != 200 { t.Fatalf( "finish: %d %v" , status , reply ) }
	return
}

func TestAnUploadRoundTripsWithSafeHeaders( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	content := bytes.Repeat( []byte( "<script>alert(1)</script>" ) , 80000 )
	file_id := uploaded( t , alice , "page.html" , content )

	response , body := raw( t , alice , http.MethodGet , "/api/files/" + file_id + "/download" , nil , nil )
	if response.StatusCode != 200 || bytes.Equal( body , content ) == false { t.Fatalf( "%d, %d bytes" , response.StatusCode , len( body ) ) }
	for header , wanted := range map[ string ]string{
		"Content-Type":        "application/octet-stream",
		"Content-Disposition": `attachment; filename="page.html"; filename*=UTF-8''page.html`,
		"Cache-Control":       "private, no-store",
		"Content-Length":      fmt.Sprint( len( content ) ),
	} {
		if got := response.Header.Get( header ); got != wanted { t.Fatalf( "%s: %q" , header , got ) }
	}

	status , page := alice.do( t , http.MethodGet , "/api/files" , nil )
	rows , _ := page[ "files" ].( []any )
	if status != 200 || len( rows ) != 1 { t.Fatalf( "%d %v" , status , page ) }
	encoded , _ := json.Marshal( rows )
	if strings.Contains( string( encoded ) , `"key"` ) { t.Fatalf( "the sealed key is in a response: %s" , encoded ) }
}

func TestAnAwkwardNameCannotBreakTheHeader( t *testing.T ) {
	got := contentDisposition( `na"ï;ve.txt` )
	if got != `attachment; filename="na___ve.txt"; filename*=UTF-8''na%22%C3%AF%3Bve.txt` { t.Fatal( got ) }
}

func TestSomeoneElsesFileIsNotThere( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	bob_user , _ := models.CreateUser( fixture.store , "Bob" , models.RoleUser )
	bob := fixture.signIn( t , bob_user.ID )
	file_id := uploaded( t , alice , "a.txt" , []byte( "alice's" ) )

	if status , _ := bob.do( t , http.MethodGet , "/api/files/" + file_id , nil ); status != 404 { t.Fatalf( "status: %d" , status ) }
	if response , _ := raw( t , bob , http.MethodGet , "/api/files/" + file_id + "/download" , nil , nil ); response.StatusCode != 404 { t.Fatalf( "download: %d" , response.StatusCode ) }
	if status , _ := send( t , bob , "/api/files/" + file_id + "/delete" , fiber.Map{} ); status != 404 { t.Fatalf( "delete: %d" , status ) }
	if status , _ := sendPiece( t , bob , file_id , 0 , []byte( "x" ) ); status != 404 { t.Fatalf( "piece: %d" , status ) }
	if status , _ := bob.do( t , http.MethodGet , "/api/admin/files" , nil ); status != 403 { t.Fatalf( "admin list: %d" , status ) }
	if response , _ := raw( t , bob , http.MethodGet , "/api/admin/files/" + file_id + "/download" , nil , nil ); response.StatusCode != 403 { t.Fatalf( "admin download: %d" , response.StatusCode ) }

	// Nor can anyone get in without signing in.
	anonymous := fixture.browser()
	if response , _ := raw( t , anonymous , http.MethodGet , "/api/files/" + file_id + "/download" , nil , nil ); response.StatusCode != 401 { t.Fatalf( "anonymous: %d" , response.StatusCode ) }
}

func TestAnAdminCanOpenAndRemoveAnyFile( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	owner := fixture.signIn( t , fixture.owner.ID )
	file_id := uploaded( t , alice , "a.txt" , []byte( "alice's" ) )

	status , page := owner.do( t , http.MethodGet , "/api/admin/files" , nil )
	rows , _ := page[ "files" ].( []any )
	if status != 200 || len( rows ) != 1 || rows[ 0 ].( map[ string ]any )[ "user_name" ] != "Alice" { t.Fatalf( "%d %v" , status , page ) }
	response , body := raw( t , owner , http.MethodGet , "/api/admin/files/" + file_id + "/download" , nil , nil )
	if response.StatusCode != 200 || string( body ) != "alice's" { t.Fatalf( "%d %q" , response.StatusCode , body ) }

	if status , reply := send( t , owner , "/api/admin/files/" + file_id + "/delete" , fiber.Map{} ); status != 200 { t.Fatalf( "%d %v" , status , reply ) }
	if status , _ := alice.do( t , http.MethodGet , "/api/files/" + file_id , nil ); status != 404 { t.Fatalf( "still there: %d" , status ) }
	if status , reply := send( t , owner , "/api/admin/files/" + file_id + "/restore" , fiber.Map{} ); status != 200 { t.Fatalf( "%d %v" , status , reply ) }
	if status , _ := alice.do( t , http.MethodGet , "/api/files/" + file_id , nil ); status != 200 { t.Fatalf( "not back: %d" , status ) }
}

func TestAKeyReachesItsOwnFilesButAnAdminKeyCannotOpenOthers( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	file_id := uploaded( t , alice , "a.txt" , []byte( "alice's" ) )
	user_key , _ , err := models.IssueAPIKey( fixture.store , fixture.alice.ID , "script" , models.RoleUser , time.Hour )
	if err != nil { t.Fatal( err ) }
	admin_key , _ , err := models.IssueAPIKey( fixture.store , fixture.owner.ID , "ops" , models.RoleAdmin , time.Hour )
	if err != nil { t.Fatal( err ) }
	nobody := fixture.browser()
	bearer := func( key string ) map[ string ]string { return map[ string ]string{ "Authorization": "Bearer " + key } }

	response , body := raw( t , nobody , http.MethodGet , "/api/files/" + file_id + "/download" , nil , bearer( user_key ) )
	if response.StatusCode != 200 || string( body ) != "alice's" { t.Fatalf( "%d %q" , response.StatusCode , body ) }

	// A key needs no csrf token, for a piece or anything else.
	headers := bearer( user_key )
	headers[ "Content-Type" ] = "application/json"
	response , body = raw( t , nobody , http.MethodPost , "/api/files" , []byte( `{"name":"b","size":1}` ) , headers )
	if response.StatusCode != 201 { t.Fatalf( "%d %s" , response.StatusCode , body ) }
	var created map[ string ]any
	json.Unmarshal( body , &created )
	response , body = raw( t , nobody , http.MethodPost , fmt.Sprintf( "/api/files/%s/chunks/0" , created[ "id" ] ) , []byte( "x" ) , bearer( user_key ) )
	if response.StatusCode != 200 { t.Fatalf( "%d %s" , response.StatusCode , body ) }

	if response , _ = raw( t , nobody , http.MethodGet , "/api/admin/files" , nil , bearer( admin_key ) ); response.StatusCode != 200 { t.Fatalf( "list: %d" , response.StatusCode ) }
	if response , _ = raw( t , nobody , http.MethodGet , "/api/admin/files/" + file_id + "/download" , nil , bearer( admin_key ) ); response.StatusCode != 403 { t.Fatalf( "download: %d" , response.StatusCode ) }
}

func TestAPieceNeedsItsCSRFToken( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	_ , reply := send( t , alice , "/api/files" , fiber.Map{ "name": "a" , "size": 1 } )
	response , _ := raw( t , alice , http.MethodPost , fmt.Sprintf( "/api/files/%s/chunks/0" , reply[ "id" ] ) , []byte( "x" ) , nil )
	if response.StatusCode != 403 { t.Fatalf( "%d" , response.StatusCode ) }
}

func TestAClientResumesFromWhatTheServerReports( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	content := bytes.Repeat( []byte( "z" ) , config.FileChunkBytes + 10 )
	_ , reply := send( t , alice , "/api/files" , fiber.Map{ "name": "a" , "size": len( content ) } )
	file_id := reply[ "id" ].( string )

	status , reply := sendPiece( t , alice , file_id , 1 , content[ config.FileChunkBytes: ] )
	if status != 409 || reply[ "received" ] != float64( 0 ) { t.Fatalf( "%d %v" , status , reply ) }
	if status , reply = sendPiece( t , alice , file_id , 0 , content[ :10 ] ); status != 400 { t.Fatalf( "%d %v" , status , reply ) }
	if status , reply = sendPiece( t , alice , file_id , 0 , content[ :config.FileChunkBytes ] ); status != 200 { t.Fatalf( "%d %v" , status , reply ) }
	// The reply was lost, and the same piece comes again.
	status , reply = sendPiece( t , alice , file_id , 0 , content[ :config.FileChunkBytes ] )
	if status != 409 || reply[ "received" ] != float64( 1 ) { t.Fatalf( "%d %v" , status , reply ) }

	if status , reply = send( t , alice , "/api/files/" + file_id + "/finish" , fiber.Map{} ); status != 409 { t.Fatalf( "early finish: %d %v" , status , reply ) }
	status , state := alice.do( t , http.MethodGet , "/api/files/" + file_id , nil )
	if status != 200 || state[ "received" ] != float64( 1 ) { t.Fatalf( "%d %v" , status , state ) }
	if response , _ := raw( t , alice , http.MethodGet , "/api/files/" + file_id + "/download" , nil , nil ); response.StatusCode != 404 { t.Fatalf( "unfinished download: %d" , response.StatusCode ) }

	if status , reply = sendPiece( t , alice , file_id , 1 , content[ config.FileChunkBytes: ] ); status != 200 { t.Fatalf( "%d %v" , status , reply ) }
	if status , reply = sendPiece( t , alice , file_id , 2 , []byte( "x" ) ); status != 400 { t.Fatalf( "past the end: %d %v" , status , reply ) }
	if status , reply = send( t , alice , "/api/files/" + file_id + "/finish" , fiber.Map{} ); status != 200 { t.Fatalf( "%d %v" , status , reply ) }
	if status , reply = send( t , alice , "/api/files/" + file_id + "/finish" , fiber.Map{} ); status != 200 { t.Fatalf( "finish twice: %d %v" , status , reply ) }
	_ , body := raw( t , alice , http.MethodGet , "/api/files/" + file_id + "/download" , nil , nil )
	if bytes.Equal( body , content ) == false { t.Fatal( "came back different" ) }
}

func TestAnEmptyFileWorks( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	file_id := uploaded( t , alice , "empty" , nil )
	response , body := raw( t , alice , http.MethodGet , "/api/files/" + file_id + "/download" , nil , nil )
	if response.StatusCode != 200 || len( body ) != 0 { t.Fatalf( "%d %d" , response.StatusCode , len( body ) ) }
}

func TestLimitsAnswerWithCodes( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	fixture.cfg.Files.MaxFileBytes = 10
	status , reply := send( t , alice , "/api/files" , fiber.Map{ "name": "a" , "size": 11 } )
	if status != 409 || reply[ "error" ] != "file_too_large" { t.Fatalf( "%d %v" , status , reply ) }
	fixture.cfg.Files.MaxFileBytes = 100
	fixture.cfg.Files.QuotaBytesPerUser = 10
	status , reply = send( t , alice , "/api/files" , fiber.Map{ "name": "a" , "size": 11 } )
	if status != 409 || reply[ "error" ] != "file_quota" { t.Fatalf( "%d %v" , status , reply ) }
}

func TestSwitchedOffEveryRouteIsGone( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	owner := fixture.signIn( t , fixture.owner.ID )
	file_id := uploaded( t , alice , "a" , []byte( "x" ) )
	fixture.cfg.Files.Enabled = false
	if status , _ := alice.do( t , http.MethodGet , "/api/files" , nil ); status != 404 { t.Fatalf( "%d" , status ) }
	if response , _ := raw( t , alice , http.MethodGet , "/api/files/" + file_id + "/download" , nil , nil ); response.StatusCode != 404 { t.Fatalf( "%d" , response.StatusCode ) }
	if status , _ := owner.do( t , http.MethodGet , "/api/admin/files" , nil ); status != 404 { t.Fatalf( "%d" , status ) }
	_ , me := alice.do( t , http.MethodGet , "/api/me" , nil )
	if me[ "files_enabled" ] != false { t.Fatalf( "%v" , me ) }
}

func TestRenamingAFile( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	content := []byte( "the same bytes" )
	id := uploaded( t , alice , "old.txt" , content )
	path := "/api/files/" + id + "/rename"

	// Cleaned like an upload's name, and the reply says what was stored.
	status , reply := send( t , alice , path , fiber.Map{ "name": `..\\dir/new name.txt` } )
	if status != fiber.StatusOK || reply[ "name" ] != "new name.txt" { t.Fatalf( "%d %v" , status , reply ) }
	for _ , bad := range []string{ "  " , "dir/" , strings.Repeat( "a" , 256 ) } {
		if status , _ = send( t , alice , path , fiber.Map{ "name": bad } ); status != fiber.StatusBadRequest { t.Fatalf( "%q: %d" , bad , status ) }
	}

	// Only the record changed: the download has the new name and the same bytes.
	response , got := raw( t , alice , http.MethodGet , "/api/files/"+id+"/download" , nil , nil )
	if bytes.Equal( got , content ) == false { t.Fatalf( "%q" , got ) }
	if strings.Contains( response.Header.Get( "Content-Disposition" ) , "new" ) == false { t.Fatalf( "%v" , response.Header ) }

	// An undo that finds a different name leaves it alone, and says what is there.
	status , reply = send( t , alice , path , fiber.Map{ "name": "old.txt" , "expect": "stale.txt" } )
	if status != fiber.StatusConflict || reply[ "name" ] != "new name.txt" { t.Fatalf( "%d %v" , status , reply ) }

	models.DeleteFile( fixture.store , id , fixture.alice.ID )
	if status , _ = send( t , alice , path , fiber.Map{ "name": "gone.txt" } ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

func TestAFileStillUploadingCannotBeRenamed( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	status , reply := send( t , alice , "/api/files" , fiber.Map{ "name": "big.bin" , "size": 10 } )
	if status != fiber.StatusCreated { t.Fatalf( "%d %v" , status , reply ) }
	id , _ := reply[ "id" ].( string )
	if status , _ = send( t , alice , "/api/files/"+id+"/rename" , fiber.Map{ "name": "x" } ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
}

func TestWhoMayRenameWhoseFile( t *testing.T ) {
	fixture := newFilesFixture( t )
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	id := uploaded( t , alice , "hers.txt" , []byte( "x" ) )

	if status , _ := send( t , owner , "/api/files/"+id+"/rename" , fiber.Map{ "name": "x" } ); status != fiber.StatusNotFound { t.Fatalf( "%d" , status ) }
	if status , _ := send( t , alice , "/api/admin/files/"+id+"/rename" , fiber.Map{ "name": "x" } ); status != fiber.StatusForbidden { t.Fatalf( "%d" , status ) }
	status , reply := send( t , owner , "/api/admin/files/"+id+"/rename" , fiber.Map{ "name": "tidied.txt" } )
	if status != fiber.StatusOK || reply[ "name" ] != "tidied.txt" { t.Fatalf( "%d %v" , status , reply ) }
}

func TestDeleteAndUndo( t *testing.T ) {
	fixture := newFilesFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	file_id := uploaded( t , alice , "a" , []byte( "x" ) )
	if status , reply := send( t , alice , "/api/files/" + file_id + "/delete" , fiber.Map{} ); status != 200 { t.Fatalf( "%d %v" , status , reply ) }
	if response , _ := raw( t , alice , http.MethodGet , "/api/files/" + file_id + "/download" , nil , nil ); response.StatusCode != 404 { t.Fatalf( "%d" , response.StatusCode ) }
	if status , reply := send( t , alice , "/api/files/" + file_id + "/restore" , fiber.Map{} ); status != 200 { t.Fatalf( "%d %v" , status , reply ) }
	if response , _ := raw( t , alice , http.MethodGet , "/api/files/" + file_id + "/download" , nil , nil ); response.StatusCode != 200 { t.Fatalf( "%d" , response.StatusCode ) }
}

func TestStorageSaysWhatIsUsedAndWhatIsLeft( t *testing.T ) {
	fixture := newFilesFixture( t )
	if err := os.MkdirAll( fixture.cfg.Files.Dir , 0o700 ); err != nil { t.Fatal( err ) }
	owner := fixture.signIn( t , fixture.owner.ID )
	alice := fixture.signIn( t , fixture.alice.ID )
	if _ , err := models.CreateFile( fixture.store , fixture.cfg , fixture.alice.ID , "a.txt" , "text/plain" , 1000 ); err != nil { t.Fatal( err ) }
	if _ , err := models.CreateFile( fixture.store , fixture.cfg , fixture.owner.ID , "b.txt" , "text/plain" , 500 ); err != nil { t.Fatal( err ) }

	status , mine := alice.do( t , http.MethodGet , "/api/account/storage" , nil )
	if status != http.StatusOK || mine[ "used_bytes" ] != float64( 1000 ) || mine[ "quota_bytes" ] != float64( 16 << 20 ) {
		t.Fatalf( "%d %v" , status , mine )
	}
	status , all := owner.do( t , http.MethodGet , "/api/admin/storage" , nil )
	if status != http.StatusOK || all[ "used_bytes" ] != float64( 1500 ) {
		t.Fatalf( "%d %v" , status , all )
	}
	if free , _ := all[ "disk_free_bytes" ].( float64 ); free <= 0 { t.Fatalf( "%v" , all ) }
	if total , _ := all[ "disk_total_bytes" ].( float64 ); total <= 0 { t.Fatalf( "%v" , all ) }

	if status , _ = alice.do( t , http.MethodGet , "/api/admin/storage" , nil ); status != http.StatusForbidden {
		t.Fatalf( "a user: %d" , status )
	}
	fixture.cfg.Files.Enabled = false
	if status , _ = alice.do( t , http.MethodGet , "/api/account/storage" , nil ); status != http.StatusNotFound {
		t.Fatalf( "files off: %d" , status )
	}
}
