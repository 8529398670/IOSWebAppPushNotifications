package routes

import (
	errors "errors"
	fmt "fmt"
	log "log"
	strconv "strconv"
	strings "strings"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
	db "ipb/server/db"
	disk "ipb/server/disk"
	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

// Uploaded files. How they are stored is in models/file.go; here is who may do
// what. Everyone has their own, and someone else's answers 404, like a key that
// is not yours. Admins have their own routes for everyone's, and one opening a
// file that is not theirs is written to the log.
//
// An upload is three steps, so that every request stays under the global body
// limit: POST /api/files, one POST per piece, then POST .../finish.
//
// A piece's body is the raw bytes, so its csrf token cannot ride in the body
// like everywhere else, and comes in fileCSRFHeader instead.

const (
	fileCSRFHeader = "X-CSRF-Token"
	// fileWriteWait is how long a piece of a download may take to send.
	// server.WriteTimeout is one deadline for a whole response, which would
	// cut a big file off at 30 seconds.
	fileWriteWait = 60 * time.Second
)

type createFileRequest struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Type      string `json:"type"`
	CSRFToken string `json:"csrf_token"`
}

// RequireFiles makes /api/files answer 404 while files.enabled is off.
func ( handlers *Handlers ) RequireFiles( c fiber.Ctx ) ( err error ) {
	if handlers.cfg().Files.Enabled == false {
		err = notFound( c , "not found" )
		return
	}
	err = c.Next()
	return
}
type renameFileRequest struct {
	Name      string  `json:"name"`
	Expect    *string `json:"expect"`
	CSRFToken string  `json:"csrf_token"`
}

// fileRow picks the fields by hand, so the sealed key cannot reach a response
// by way of a change to the model.
func fileRow( file *models.File ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":         file.ID,
		"name":       file.Name,
		"type":       file.Type,
		"size":       file.Size,
		"state":      file.State,
		"chunks":     file.Chunks,
		"received":   file.Received,
		"created_at": file.CreatedAt,
	}
	return
}

// contentDisposition always says attachment: an uploaded page must never run
// as this site. The plain filename is the fallback for old clients, and
// filename* carries the real name (RFC 6266).
func contentDisposition( name string ) ( result string ) {
	plain := strings.Builder{}
	encoded := strings.Builder{}
	for _ , character := range name {
		safe := character < 0x80 && ( character == '.' || character == '-' || character == '_' ||
			( character >= '0' && character <= '9' ) || ( character >= 'a' && character <= 'z' ) || ( character >= 'A' && character <= 'Z' ) )
		if safe {
			plain.WriteRune( character )
		} else {
			plain.WriteByte( '_' )
		}
	}
	for _ , value := range []byte( name ) {
		safe := value == '.' || value == '-' || value == '_' || value == '~' ||
			( value >= '0' && value <= '9' ) || ( value >= 'a' && value <= 'z' ) || ( value >= 'A' && value <= 'Z' )
		if safe {
			encoded.WriteByte( value )
		} else {
			fmt.Fprintf( &encoded , "%%%02X" , value )
		}
	}
	result = fmt.Sprintf( `attachment; filename="%s"; filename*=UTF-8''%s` , plain.String() , encoded.String() )
	return
}

// myFile is the signed-in account's own, not deleted. Anything else is
// ErrNotFound, which does not say whether the id exists.
func ( handlers *Handlers ) myFile( c fiber.Ctx , file_id string ) ( file *models.File , err error ) {
	file , err = models.GetFile( handlers.Store , file_id )
	if err == nil && ( file.Deleted() || file.UserID != security.UserFrom( c ).ID ) {
		file , err = nil , db.ErrNotFound
	}
	return
}

// MyStorage says how much of the quota an account has used, so it finds out
// before an upload is refused rather than from the refusal.
func ( handlers *Handlers ) MyStorage( c fiber.Ctx ) ( err error ) {
	used , use_err := models.StorageUsed( handlers.Store , security.UserFrom( c ).ID )
	if use_err != nil {
		err = serverError( c , use_err )
		return
	}
	err = c.JSON( fiber.Map{ "used_bytes": used , "quota_bytes": handlers.cfg().Files.QuotaBytesPerUser } )
	return
}

// AllStorage is every account's files together, and what room the disk has
// left, which no quota looks at. The disk figures are left out where the
// system will not say.
func ( handlers *Handlers ) AllStorage( c fiber.Ctx ) ( err error ) {
	used , use_err := models.StorageUsed( handlers.Store , 0 )
	if use_err != nil {
		err = serverError( c , use_err )
		return
	}
	body := fiber.Map{ "used_bytes": used }
	if free , total , space_err := disk.Space( handlers.cfg().Files.Dir ); space_err == nil {
		body[ "disk_free_bytes" ] = free
		body[ "disk_total_bytes" ] = total
	}
	err = c.JSON( body )
	return
}

func ( handlers *Handlers ) ListMyFiles( c fiber.Ctx ) ( err error ) {
	files , list_err := models.ListFiles( handlers.Store , security.UserFrom( c ).ID )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	rows := []fiber.Map{}
	for _ , file := range files {
		rows = append( rows , fileRow( file ) )
	}
	err = sendPage( c , "files" , rows )
	return
}

// ListAllFiles adds who each file belongs to. The names, sizes and owners are
// what an admin needs to keep the disk in order.
func ( handlers *Handlers ) ListAllFiles( c fiber.Ctx ) ( err error ) {
	files , list_err := models.ListFiles( handlers.Store , 0 )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	users , users_err := models.ListUsers( handlers.Store )
	if users_err != nil {
		err = serverError( c , users_err )
		return
	}
	names := map[ uint64 ]string{}
	for _ , user := range users {
		names[ user.ID ] = user.DisplayName
	}
	rows := []fiber.Map{}
	for _ , file := range files {
		row := fileRow( file )
		row[ "user_id" ] = file.UserID
		row[ "user_name" ] = names[ file.UserID ]
		rows = append( rows , row )
	}
	err = sendPage( c , "files" , rows )
	return
}

func ( handlers *Handlers ) CreateFile( c fiber.Ctx ) ( err error ) {
	var body createFileRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	file , create_err := models.CreateFile( handlers.Store , handlers.cfg() , security.UserFrom( c ).ID , body.Name , body.Type , body.Size )
	switch {
	case errors.Is( create_err , models.ErrBadFile ):
		err = badRequest( c , create_err.Error() )
		return
	case errors.Is( create_err , models.ErrFileTooLarge ) || errors.Is( create_err , models.ErrFileQuota ):
		err = conflict( c , create_err.Error() , nil )
		return
	case create_err != nil:
		err = serverError( c , create_err )
		return
	}
	row := fileRow( file )
	row[ "chunk_bytes" ] = config.FileChunkBytes
	err = c.Status( fiber.StatusCreated ).JSON( row )
	return
}

// GetMyFile is how a client finds out where to resume: see received.
func ( handlers *Handlers ) GetMyFile( c fiber.Ctx ) ( err error ) {
	file , get_err := handlers.myFile( c , strings.Clone( c.Params( "file_id" ) ) )
	if get_err != nil {
		err = notFound( c , "no such file" )
		return
	}
	row := fileRow( file )
	row[ "chunk_bytes" ] = config.FileChunkBytes
	err = c.JSON( row )
	return
}

// PutFileChunk takes the next piece. Out of order is a 409 carrying received,
// which is also what a retry of a piece that did arrive gets: the client goes
// on from there.
func ( handlers *Handlers ) PutFileChunk( c fiber.Ctx ) ( err error ) {
	if handlers.Guard.CheckCSRF( c , c.Get( fileCSRFHeader ) ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	index , parse_err := strconv.Atoi( c.Params( "index" ) )
	if parse_err != nil || index < 0 {
		err = badRequest( c , "bad piece number" )
		return
	}
	file_id := strings.Clone( c.Params( "file_id" ) )
	if handlers.uploads.Hold( file_id ) == false {
		err = conflict( c , "another request is writing this upload" , nil )
		return
	}
	defer handlers.uploads.Release( file_id )

	file , get_err := handlers.myFile( c , file_id )
	if get_err != nil {
		err = notFound( c , "no such file" )
		return
	}
	if file.State != models.FileUploading || index != file.Received {
		err = conflict( c , "that is not the next piece" , fiber.Map{ "received": file.Received } )
		return
	}
	if index >= file.Chunks {
		err = badRequest( c , "bad piece number" )
		return
	}
	write_err := models.WriteFileChunk( handlers.Store , handlers.cfg() , file , index , c.Body() )
	switch {
	case errors.Is( write_err , models.ErrFileChunkSize ):
		err = badRequest( c , write_err.Error() )
	case errors.Is( write_err , models.ErrFileMissing ):
		err = notFound( c , "upload_lost" )
	case write_err != nil:
		err = serverError( c , write_err )
	default:
		err = c.JSON( fiber.Map{ "received": index + 1 } )
	}
	return
}

func ( handlers *Handlers ) FinishFile( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	file_id := strings.Clone( c.Params( "file_id" ) )
	if handlers.uploads.Hold( file_id ) == false {
		err = conflict( c , "another request is writing this upload" , nil )
		return
	}
	defer handlers.uploads.Release( file_id )

	file , get_err := handlers.myFile( c , file_id )
	if get_err != nil {
		err = notFound( c , "no such file" )
		return
	}
	// Asked twice, the second answer is the same as the first.
	if file.State == models.FileReady {
		err = c.JSON( fileRow( file ) )
		return
	}
	if file.Received != file.Chunks {
		err = conflict( c , "some of the file has not arrived" , fiber.Map{ "received": file.Received } )
		return
	}
	finished , finish_err := models.FinishFile( handlers.Store , handlers.cfg() , file )
	if errors.Is( finish_err , models.ErrFileMissing ) {
		err = notFound( c , "upload_lost" )
		return
	}
	if finish_err != nil {
		err = serverError( c , finish_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "file uploaded" , fiber.Map{ "file_id": finished.ID , "size": finished.Size } )
	handlers.Webhooks.Emit( models.EventFileUploaded , map[string]any{ "file_id": finished.ID , "user_id": finished.UserID , "name": finished.Name , "size": finished.Size } )
	err = c.JSON( fileRow( finished ) )
	return
}

// sendFile streams a finished file. It is only ever an attachment of an opaque
// type: nosniff is on every response, and nothing the uploader said about the
// file reaches the headers except its cleaned name.
func ( handlers *Handlers ) sendFile( c fiber.Ctx , file *models.File ) ( err error ) {
	if file.State != models.FileReady {
		err = notFound( c , "no such file" )
		return
	}
	reader , open_err := models.OpenFile( handlers.cfg() , file )
	if errors.Is( open_err , models.ErrFileMissing ) {
		log.Printf( "[files] file %s has a record but not the right data on disk" , file.ID )
		err = notFound( c , "no such file" )
		return
	}
	if open_err != nil {
		err = serverError( c , open_err )
		return
	}
	c.Set( fiber.HeaderContentType , fiber.MIMEOctetStream )
	c.Set( fiber.HeaderContentDisposition , contentDisposition( file.Name ) )
	c.Set( fiber.HeaderCacheControl , "private, no-store" )
	if c.Method() == fiber.MethodHead {
		c.Set( fiber.HeaderContentLength , strconv.FormatInt( file.Size , 10 ) )
		reader.Close()
		return
	}
	// Taken here: the reader runs after the handler, when c has been reused.
	connection := c.RequestCtx().Conn()
	reader.BeforeRead = func() { connection.SetWriteDeadline( time.Now().Add( fileWriteWait ) ) }
	// fasthttp closes the reader, and the fixed size means a piece that fails
	// to open ends the connection short rather than looking complete.
	c.Response().SetBodyStream( reader , int( file.Size ) )
	return
}

func ( handlers *Handlers ) DownloadMyFile( c fiber.Ctx ) ( err error ) {
	file , get_err := handlers.myFile( c , strings.Clone( c.Params( "file_id" ) ) )
	if get_err != nil {
		err = notFound( c , "no such file" )
		return
	}
	err = handlers.sendFile( c , file )
	return
}

func ( handlers *Handlers ) DownloadAnyFile( c fiber.Ctx ) ( err error ) {
	file , get_err := models.GetFile( handlers.Store , strings.Clone( c.Params( "file_id" ) ) )
	if get_err != nil || file.Deleted() {
		err = notFound( c , "no such file" )
		return
	}
	if file.UserID != security.UserFrom( c ).ID {
		handlers.audit( c , logs.KindAdmin , "file opened by admin" , fiber.Map{ "file_id": file.ID , "user_id": file.UserID } )
	}
	err = handlers.sendFile( c , file )
	return
}

// removeFile is the two delete routes after each has decided the caller may.
func ( handlers *Handlers ) removeFile( c fiber.Ctx , file *models.File ) ( err error ) {
	if models.DeleteFile( handlers.Store , file.ID , security.UserFrom( c ).ID ) != nil {
		err = notFound( c , "no such file" )
		return
	}
	handlers.audit( c , logs.KindAdmin , "file deleted" , fiber.Map{ "file_id": file.ID , "user_id": file.UserID } )
	handlers.Webhooks.Emit( models.EventFileDeleted , map[string]any{ "file_id": file.ID , "user_id": file.UserID , "name": file.Name } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// renameFile is the two rename routes. own_only is the difference: an admin may
// rename anyone's, as an admin may delete anyone's.
func ( handlers *Handlers ) renameFile( c fiber.Ctx , own_only bool ) ( err error ) {
	var body renameFileRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	file_id := strings.Clone( c.Params( "file_id" ) )
	var file *models.File
	var get_err error
	if own_only {
		file , get_err = handlers.myFile( c , file_id )
	} else {
		file , get_err = models.GetFile( handlers.Store , file_id )
	}
	if get_err != nil {
		err = notFound( c , "no such file" )
		return
	}
	name , rename_err := models.RenameFile( handlers.Store , file.ID , body.Name , body.Expect )
	var refusal *models.RenameConflictError
	switch {
	case errors.As( rename_err , &refusal ):
		err = conflict( c , refusal.Error() , fiber.Map{ "name": refusal.Current } )
		return
	case errors.Is( rename_err , models.ErrBadFileName ):
		err = badRequest( c , rename_err.Error() )
		return
	case errors.Is( rename_err , db.ErrNotFound ):
		err = notFound( c , "no such file" )
		return
	case rename_err != nil:
		err = serverError( c , rename_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "file renamed" , fiber.Map{ "file_id": file.ID , "user_id": file.UserID } )
	err = c.JSON( fiber.Map{ "ok": true , "name": name } )
	return
}

func ( handlers *Handlers ) RenameMyFile( c fiber.Ctx ) ( err error ) {
	err = handlers.renameFile( c , true )
	return
}

func ( handlers *Handlers ) RenameAnyFile( c fiber.Ctx ) ( err error ) {
	err = handlers.renameFile( c , false )
	return
}

func ( handlers *Handlers ) DeleteMyFile( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	file , get_err := handlers.myFile( c , strings.Clone( c.Params( "file_id" ) ) )
	if get_err != nil {
		err = notFound( c , "no such file" )
		return
	}
	err = handlers.removeFile( c , file )
	return
}

func ( handlers *Handlers ) DeleteAnyFile( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	file , get_err := models.GetFile( handlers.Store , strings.Clone( c.Params( "file_id" ) ) )
	if get_err != nil || file.Deleted() {
		err = notFound( c , "no such file" )
		return
	}
	err = handlers.removeFile( c , file )
	return
}

// restoreFile answers an undo. Someone else's file looks like no file at all,
// unless the caller is an admin on the admin route.
func ( handlers *Handlers ) restoreFile( c fiber.Ctx , as_admin bool ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	file_id := strings.Clone( c.Params( "file_id" ) )
	user := security.UserFrom( c )
	if as_admin == false {
		existing , get_err := models.GetFile( handlers.Store , file_id )
		if get_err != nil || existing.UserID != user.ID {
			err = notFound( c , models.ErrRestoreGone.Error() )
			return
		}
	}
	file , restore_err := models.RestoreFile( handlers.Store , handlers.cfg() , file_id , user.ID , as_admin )
	if errors.Is( restore_err , models.ErrFileQuota ) {
		err = conflict( c , restore_err.Error() , nil )
		return
	}
	if restore_err != nil {
		err = restoreRefused( c , restore_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "file restored" , fiber.Map{ "file_id": file_id } )
	err = c.JSON( fileRow( file ) )
	return
}

func ( handlers *Handlers ) RestoreMyFile( c fiber.Ctx ) ( err error ) {
	err = handlers.restoreFile( c , false )
	return
}

func ( handlers *Handlers ) RestoreAnyFile( c fiber.Ctx ) ( err error ) {
	err = handlers.restoreFile( c , true )
	return
}
