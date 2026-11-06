package routes

import (
	url "net/url"
	strings "strings"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	encryption "ipb/server/encryption"
	logs "ipb/server/logs"
	models "ipb/server/models"
	push "ipb/server/push"
	security "ipb/server/security"
)

// testPushTTL is how long a push service holds a test it cannot deliver.
const testPushTTL = time.Hour

// registerPush puts the signed-in notification routes on the /api group.
// Changing anything takes a browser session. A script's way in is the send
// route and nothing else.
func ( handlers *Handlers ) registerPush( account fiber.Router ) {
	session := handlers.Guard.RequireSession

	account.Get( "/push/key" , handlers.GetPushKey )
	account.Get( "/push/me" , handlers.GetPushMe )
	account.Post( "/push/subscribe" , session , handlers.SubscribePush )
	account.Post( "/push/unsubscribe" , session , handlers.UnsubscribePush )
	account.Post( "/push/test" , session , handlers.SendTestPush )
	account.Post( "/push/rotate-key" , session , handlers.RotateMyKey )
	// This is a login link, so only a person may ask for one.
	account.Post( "/push/install-link" , session , handlers.CreateInstallLink )
	account.Post( "/push/devices/:device_id/delete" , session , handlers.DeleteDevice )

	account.Get( "/apps" , handlers.ListApps )
	account.Post( "/apps" , session , handlers.CreateApp )
	account.Post( "/apps/:app_id/rename" , session , handlers.RenameApp )
	account.Post( "/apps/:app_id/rotate-token" , session , handlers.RotateAppToken )
	account.Post( "/apps/:app_id/delete" , session , handlers.DeleteApp )
	account.Post( "/apps/:app_id/restore" , session , handlers.RestoreApp )
	account.Post( "/apps/:app_id/mute" , session , handlers.MuteApp )
	account.Get( "/apps/:app_id/icon" , handlers.GetAppMedia( models.MediaIcon ) )
	account.Get( "/apps/:app_id/sound" , handlers.GetAppMedia( models.MediaSound ) )
	account.Post( "/apps/:app_id/icon" , session , handlers.PutAppIcon )
	account.Post( "/apps/:app_id/sound" , session , handlers.PutAppSound )

	account.Get( "/groups" , handlers.ListGroups )
	account.Post( "/groups" , session , handlers.CreateGroup )
	account.Post( "/groups/:group_id/update" , session , handlers.UpdateGroup )
	account.Post( "/groups/:group_id/leave" , session , handlers.LeaveGroup )
	account.Post( "/groups/:group_id/rotate-key" , session , handlers.RotateGroupKey )
	account.Post( "/groups/:group_id/delete" , session , handlers.DeleteGroup )
	account.Post( "/groups/:group_id/restore" , session , handlers.RestoreGroup )

	account.Get( "/inbox" , handlers.ListInbox )
	account.Get( "/inbox/unread" , handlers.GetInboxUnread )
	account.Get( "/inbox/stream" , session , handlers.StreamInbox )
	account.Post( "/inbox/read-all" , session , handlers.ReadAllInbox )
	account.Post( "/inbox/:item_id/read" , session , handlers.ReadInboxItem )
	account.Post( "/inbox/:item_id/delete" , session , handlers.DeleteInboxItem )
	account.Post( "/inbox/:item_id/restore" , session , handlers.RestoreInboxItem )

	account.Get( "/admin/recipient-keys" , handlers.Guard.RequireAdmin , handlers.ListRecipientKeys )
}

// ShowInstallPage is the app itself, at an address whose relative manifest href
// finds the manifest carrying this link's sign-in. Nothing is redeemed by
// opening it, for the same reason as ShowLoginPage.
func ( handlers *Handlers ) ShowInstallPage( c fiber.Ctx ) ( err error ) {
	if strings.HasSuffix( c.Path() , "/" ) == false {
		err = c.Redirect().Status( fiber.StatusFound ).To( c.Path() + "/" )
		return
	}
	c.Set( fiber.HeaderReferrerPolicy , "no-referrer" )
	err = handlers.Static.ServeIndex( c )
	return
}

// GetManifest is what iOS keeps when iPB is added to a Home Screen. The one from
// an install link differs only in start_url, which carries the one-time
// credential to the first launch. Its id is the same, so adding iPB twice
// replaces rather than adds.
func ( handlers *Handlers ) GetManifest( c fiber.Ctx ) ( err error ) {
	start_url := "/"
	if credential := c.Params( "credential" ); credential != "" {
		start_url += "?credential=" + url.QueryEscape( credential )
	}
	name := handlers.Language.Get( "app.title" )
	c.Set( fiber.HeaderCacheControl , "no-store" )
	err = c.JSON( fiber.Map{
		"id":               "/",
		"name":             name,
		"short_name":       name,
		"start_url":        start_url,
		"scope":            "/",
		"display":          "standalone",
		"theme_color":      "#ffffff",
		"background_color": "#ffffff",
		"icons": []fiber.Map{
			{ "src": "/icons/icon-192.png" , "sizes": "192x192" , "type": "image/png" , "purpose": "any" },
			{ "src": "/icons/icon-512.png" , "sizes": "512x512" , "type": "image/png" , "purpose": "any" },
		},
	} , "application/manifest+json" )
	return
}

// GetPushKey is the public half of the VAPID pair, which a browser needs in
// order to subscribe.
func ( handlers *Handlers ) GetPushKey( c fiber.Ctx ) ( err error ) {
	public_key , _ , key_err := models.LoadVAPIDKeys( handlers.Store , handlers.cfg().SecretKey )
	if key_err != nil {
		err = serverError( c , key_err )
		return
	}
	err = c.JSON( fiber.Map{ "public_key": public_key } )
	return
}

// deviceRow picks the fields by hand: an endpoint is a credential for reaching
// that device, so it never goes back to a page.
func deviceRow( subscription *models.PushSubscription ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":         subscription.ID,
		"user_agent": subscription.UserAgent,
		"created_at": subscription.CreatedAt,
	}
	return
}

// GetPushMe is the Notifications screen: this person's key and devices.
func ( handlers *Handlers ) GetPushMe( c fiber.Ctx ) ( err error ) {
	user_id := security.UserFrom( c ).ID
	prefs , prefs_err := models.GetPushPrefs( handlers.Store , user_id )
	if prefs_err != nil {
		err = serverError( c , prefs_err )
		return
	}
	subscriptions , list_err := models.PushSubscriptionsFor( handlers.Store , user_id )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	devices := []fiber.Map{}
	for _ , subscription := range subscriptions {
		devices = append( devices , deviceRow( subscription ) )
	}
	err = c.JSON( fiber.Map{ "user_key": prefs.UserKey , "devices": devices } )
	return
}

type subscribeRequest struct {
	CSRFToken string `json:"csrf_token"`
	Endpoint  string `json:"endpoint"`
	Keys      struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

// SubscribePush stores what a browser got from pushManager.subscribe.
func ( handlers *Handlers ) SubscribePush( c fiber.Ctx ) ( err error ) {
	var body subscribeRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if push.AllowedEndpoint( body.Endpoint ) == false {
		err = badRequest( c , "that is not a known push service" )
		return
	}
	// Sealing a test message is the real check of the keys.
	if _ , seal_err := encryption.WebPushEncrypt( []byte( "check" ) , body.Keys.P256dh , body.Keys.Auth ); seal_err != nil {
		err = badRequest( c , "those subscription keys are not valid" )
		return
	}
	subscription := &models.PushSubscription{
		UserID:    security.UserFrom( c ).ID,
		Endpoint:  body.Endpoint,
		P256dh:    body.Keys.P256dh,
		Auth:      body.Keys.Auth,
		UserAgent: logs.Truncate( c.Get( fiber.HeaderUserAgent ) , models.SubscriptionUserAgentMax ),
	}
	if save_err := models.SavePushSubscription( handlers.Store , subscription ); save_err != nil {
		err = serverError( c , save_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "device subscribed" , nil )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

type unsubscribeRequest struct {
	CSRFToken string `json:"csrf_token"`
	Endpoint  string `json:"endpoint"`
}

// UnsubscribePush is signing out on a device: it stops pushes to it.
func ( handlers *Handlers ) UnsubscribePush( c fiber.Ctx ) ( err error ) {
	var body unsubscribeRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	err = handlers.removeDevice( c , models.SubscriptionID( body.Endpoint ) )
	return
}

type csrfOnly struct {
	CSRFToken string `json:"csrf_token"`
}

// checkedCSRF decodes a body that carries only the token. ok false means the
// answer has been written.
func ( handlers *Handlers ) checkedCSRF( c fiber.Ctx ) ( ok bool , err error ) {
	var body csrfOnly
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	ok = true
	return
}

// DeleteDevice removes one of the caller's own devices.
func ( handlers *Handlers ) DeleteDevice( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	err = handlers.removeDevice( c , strings.Clone( c.Params( "device_id" ) ) )
	return
}

func ( handlers *Handlers ) removeDevice( c fiber.Ctx , device_id string ) ( err error ) {
	found , get_err := models.GetPushSubscription( handlers.Store , device_id )
	if get_err != nil || found.UserID != security.UserFrom( c ).ID {
		err = notFound( c , "no such device" )
		return
	}
	if delete_err := models.DeletePushSubscription( handlers.Store , device_id ); delete_err != nil {
		err = serverError( c , delete_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "device removed" , nil )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// RotateMyKey replaces the caller's user key.
func ( handlers *Handlers ) RotateMyKey( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	key , rotate_err := models.RotateUserKey( handlers.Store , security.UserFrom( c ).ID )
	if rotate_err != nil {
		err = serverError( c , rotate_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "user key rotated" , nil )
	err = c.JSON( fiber.Map{ "user_key": key } )
	return
}

// SendTestPush sends to the caller's own devices straight away and reports
// exactly what each push service said, which is what makes a refusal something
// a person can see. It leaves nothing in the inbox.
func ( handlers *Handlers ) SendTestPush( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	subscriptions , list_err := models.PushSubscriptionsFor( handlers.Store , security.UserFrom( c ).ID )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	cfg := handlers.cfg()
	public_key , private_key , key_err := models.LoadVAPIDKeys( handlers.Store , cfg.SecretKey )
	if key_err != nil {
		err = serverError( c , key_err )
		return
	}
	payload , payload_err := push.Payload( push.Notification{
		Title:    handlers.Language.Get( "app.title" ),
		Body:     handlers.Language.Get( "notifications.test_body" ),
		Navigate: cfg.URL + "/#notifications",
	} )
	if payload_err != nil {
		err = serverError( c , payload_err )
		return
	}

	sender := &push.Sender{ PublicKey: public_key , PrivateKey: private_key , Subject: cfg.Push.Subject , Client: push.NewClient() }
	results := []fiber.Map{}
	for _ , subscription := range subscriptions {
		result , send_err := sender.Send( subscription , payload , testPushTTL , "normal" )
		if send_err != nil {
			cause := push.Cause( send_err )
			handlers.audit( c , logs.KindAdmin , "push send failed" , fiber.Map{ "cause": cause } )
			results = append( results , fiber.Map{ "status": 0 , "reason": cause } )
			continue
		}
		if result.Gone {
			if delete_err := models.DeletePushSubscription( handlers.Store , subscription.ID ); delete_err != nil {
				err = serverError( c , delete_err )
				return
			}
		}
		results = append( results , fiber.Map{ "status": result.Status , "reason": result.Reason } )
	}
	err = c.JSON( fiber.Map{ "results": results } )
	return
}

// CreateInstallLink makes the link a person opens in Safari to add iPB to their
// Home Screen. The credential signs the new install in, for an iOS that does
// not carry Safari's cookies over, and it is a login, so it needs a session.
func ( handlers *Handlers ) CreateInstallLink( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	cfg := handlers.cfg()
	credential , token_err := models.IssueInstallToken( handlers.Store , security.UserFrom( c ).ID , cfg.LoginTokenTTL )
	if token_err != nil {
		err = serverError( c , token_err )
		return
	}
	handlers.audit( c , logs.KindAuth , "install link created" , nil )
	err = c.JSON( fiber.Map{
		"install_path":       "/i/" + credential + "/",
		"expires_in_seconds": int( cfg.LoginTokenTTL.Seconds() ),
	} )
	return
}

// ListRecipientKeys is everyone's user key, for an admin writing a script that
// should reach a particular person. A key alone cannot send anything.
func ( handlers *Handlers ) ListRecipientKeys( c fiber.Ctx ) ( err error ) {
	users , list_err := models.ListUsers( handlers.Store )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	rows := []fiber.Map{}
	for _ , user := range users {
		prefs , prefs_err := models.GetPushPrefs( handlers.Store , user.ID )
		if prefs_err != nil {
			err = serverError( c , prefs_err )
			return
		}
		rows = append( rows , fiber.Map{ "id": user.ID , "display_name": user.DisplayName , "user_key": prefs.UserKey } )
	}
	err = sendPage( c , "people" , rows )
	return
}
