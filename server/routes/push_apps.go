package routes

import (
	bytes "bytes"
	errors "errors"
	image "image"
	_ "image/png"
	strings "strings"

	fiber "github.com/gofiber/fiber/v3"

	db "ipb/server/db"
	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

const (
	iconBytesMax = 512 * 1024
	iconSideMax  = 1024
	// soundBytesMax stays under server.body_limit, which a raw upload has to
	// fit, and a notification sound has no need of more.
	soundBytesMax = 900 * 1024
)

// appRow picks fields by hand, so the token hash cannot reach a response.
func ( handlers *Handlers ) appRow( app *models.PushApp , prefs *models.PushPrefs , actor *security.Actor , owners map[uint64]string ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":            app.ID,
		"name":          app.Name,
		"owner_name":    owners[ app.OwnerID ],
		"has_icon":      app.HasIcon,
		"has_sound":     app.HasSound,
		"media_version": app.MediaVersion,
		"muted":         prefs.Muted( app.ID ),
		"can_manage":    canManageApp( app , actor ),
		"created_at":    app.CreatedAt,
	}
	return
}

func canManageApp( app *models.PushApp , actor *security.Actor ) ( result bool ) {
	result = app.OwnerID == actor.User.ID || actor.IsAdmin()
	return
}

func ( handlers *Handlers ) userNames() ( names map[uint64]string , err error ) {
	users , err := models.ListUsers( handlers.Store )
	if err != nil { return }
	names = map[uint64]string{}
	for _ , user := range users {
		names[ user.ID ] = user.DisplayName
	}
	return
}

// ListApps is every app, because anyone may need to find one to mute it.
func ( handlers *Handlers ) ListApps( c fiber.Ctx ) ( err error ) {
	actor := security.ActorFrom( c )
	apps , list_err := models.ListPushApps( handlers.Store )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	prefs , prefs_err := models.GetPushPrefs( handlers.Store , actor.User.ID )
	if prefs_err != nil {
		err = serverError( c , prefs_err )
		return
	}
	owners , names_err := handlers.userNames()
	if names_err != nil {
		err = serverError( c , names_err )
		return
	}
	rows := []fiber.Map{}
	for _ , app := range apps {
		rows = append( rows , handlers.appRow( app , prefs , actor , owners ) )
	}
	err = sendPage( c , "apps" , rows )
	return
}

type appNameRequest struct {
	Name      string `json:"name"`
	CSRFToken string `json:"csrf_token"`
}

// CreateApp answers with the token, the only time it is shown.
func ( handlers *Handlers ) CreateApp( c fiber.Ctx ) ( err error ) {
	var body appNameRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	app , token , create_err := models.CreatePushApp( handlers.Store , security.UserFrom( c ).ID , body.Name )
	if errors.Is( create_err , models.ErrPushAppName ) {
		err = badRequest( c , create_err.Error() )
		return
	}
	if create_err != nil {
		err = serverError( c , create_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "app created" , fiber.Map{ "app_id": app.ID , "name": app.Name } )
	err = c.JSON( fiber.Map{ "id": app.ID , "name": app.Name , "token": token } )
	return
}

// managedApp loads the app in the URL for someone allowed to change it. Someone
// else gets the same 404 as an app that is not there.
func ( handlers *Handlers ) managedApp( c fiber.Ctx ) ( app *models.PushApp , err error ) {
	found , get_err := models.GetPushApp( handlers.Store , strings.Clone( c.Params( "app_id" ) ) )
	if errors.Is( get_err , models.ErrPushAppGone ) {
		err = notFound( c , "no such app" )
		return
	}
	if get_err != nil {
		err = serverError( c , get_err )
		return
	}
	if canManageApp( found , security.ActorFrom( c ) ) == false {
		err = notFound( c , "no such app" )
		return
	}
	app = found
	return
}

func ( handlers *Handlers ) RenameApp( c fiber.Ctx ) ( err error ) {
	var body appNameRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	app , err := handlers.managedApp( c )
	if app == nil { return }
	rename_err := models.RenamePushApp( handlers.Store , app.ID , body.Name )
	if errors.Is( rename_err , models.ErrPushAppName ) {
		err = badRequest( c , rename_err.Error() )
		return
	}
	if rename_err != nil {
		err = serverError( c , rename_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "app renamed" , fiber.Map{ "app_id": app.ID } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// RotateAppToken ends the old token at once and shows the new one, once.
func ( handlers *Handlers ) RotateAppToken( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	app , err := handlers.managedApp( c )
	if app == nil { return }
	token , rotate_err := models.RotatePushAppToken( handlers.Store , app.ID )
	if rotate_err != nil {
		err = serverError( c , rotate_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "app token rotated" , fiber.Map{ "app_id": app.ID } )
	err = c.JSON( fiber.Map{ "token": token } )
	return
}

func ( handlers *Handlers ) DeleteApp( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	app , err := handlers.managedApp( c )
	if app == nil { return }
	if delete_err := models.DeletePushApp( handlers.Store , app.ID , security.UserFrom( c ).ID ); delete_err != nil {
		err = serverError( c , delete_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "app deleted" , fiber.Map{ "app_id": app.ID } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

func ( handlers *Handlers ) RestoreApp( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	actor := security.ActorFrom( c )
	restore_err := models.RestorePushApp( handlers.Store , strings.Clone( c.Params( "app_id" ) ) , actor.User.ID , actor.IsAdmin() )
	if restore_err != nil {
		err = restoreRefused( c , restore_err )
		return
	}
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

type muteRequest struct {
	Muted     bool   `json:"muted"`
	CSRFToken string `json:"csrf_token"`
}

// MuteApp is each person's own switch, whoever made the app.
func ( handlers *Handlers ) MuteApp( c fiber.Ctx ) ( err error ) {
	var body muteRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	app , get_err := models.GetPushApp( handlers.Store , strings.Clone( c.Params( "app_id" ) ) )
	if get_err != nil {
		err = notFound( c , "no such app" )
		return
	}
	if mute_err := models.SetAppMuted( handlers.Store , security.UserFrom( c ).ID , app.ID , body.Muted ); mute_err != nil {
		err = serverError( c , mute_err )
		return
	}
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// GetAppMedia answers with an app's icon or sound.
func ( handlers *Handlers ) GetAppMedia( kind string ) ( handler fiber.Handler ) {
	handler = func( c fiber.Ctx ) ( err error ) {
		media , get_err := models.GetPushAppMedia( handlers.Store , strings.Clone( c.Params( "app_id" ) ) , kind )
		if errors.Is( get_err , db.ErrNotFound ) {
			err = notFound( c , "not found" )
			return
		}
		if get_err != nil {
			err = serverError( c , get_err )
			return
		}
		c.Set( fiber.HeaderContentType , media.ContentType )
		// The page asks with the app's media_version, so a change is a new URL.
		c.Set( fiber.HeaderCacheControl , "private, max-age=86400" )
		err = c.Send( media.Data )
		return
	}
	return
}

// sniffSound names the formats Safari can decode, from the bytes rather than
// what the upload claims.
func sniffSound( data []byte ) ( content_type string ) {
	switch {
	case len( data ) < 12:
	case bytes.HasPrefix( data , []byte( "ID3" ) ) || ( data[ 0 ] == 0xFF && data[ 1 ] & 0xE0 == 0xE0 ):
		content_type = "audio/mpeg"
	case bytes.HasPrefix( data , []byte( "RIFF" ) ) && string( data[ 8:12 ] ) == "WAVE":
		content_type = "audio/wav"
	case string( data[ 4:8 ] ) == "ftyp":
		content_type = "audio/mp4"
	case bytes.HasPrefix( data , []byte( "FORM" ) ) && string( data[ 8:12 ] ) == "AIFF":
		content_type = "audio/aiff"
	case bytes.HasPrefix( data , []byte( "caff" ) ):
		content_type = "audio/x-caf"
	}
	return
}

// validIcon decodes the header, so what is stored is a PNG of a sensible size
// whatever the upload claimed. The browser has already made it square.
func validIcon( data []byte ) ( ok bool ) {
	config , format , err := image.DecodeConfig( bytes.NewReader( data ) )
	ok = err == nil && format == "png" && config.Width <= iconSideMax && config.Height <= iconSideMax
	return
}

// putMedia stores a raw upload, which carries its CSRF token in a header, like
// a file's pieces. An empty body clears it.
func ( handlers *Handlers ) putMedia( c fiber.Ctx , kind string , limit int , check func( []byte ) string ) ( err error ) {
	if handlers.Guard.CheckCSRF( c , c.Get( fileCSRFHeader ) ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	app , err := handlers.managedApp( c )
	if app == nil { return }

	data := bytes.Clone( c.Body() )
	content_type := ""
	if len( data ) > 0 {
		if len( data ) > limit {
			err = badRequest( c , "that file is too big: keep it under 900 KB" )
			return
		}
		if content_type = check( data ); content_type == "" {
			err = badRequest( c , "that file type is not supported: use MP3, M4A, WAV, AIFF or CAF for a sound, PNG for an icon" )
			return
		}
	}
	if set_err := models.SetPushAppMedia( handlers.Store , app.ID , kind , content_type , data ); set_err != nil {
		err = serverError( c , set_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "app "+kind+" changed" , fiber.Map{ "app_id": app.ID } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

func ( handlers *Handlers ) PutAppIcon( c fiber.Ctx ) ( err error ) {
	err = handlers.putMedia( c , models.MediaIcon , iconBytesMax , func( data []byte ) ( content_type string ) {
		if validIcon( data ) { content_type = "image/png" }
		return
	} )
	return
}

func ( handlers *Handlers ) PutAppSound( c fiber.Ctx ) ( err error ) {
	err = handlers.putMedia( c , models.MediaSound , soundBytesMax , sniffSound )
	return
}
