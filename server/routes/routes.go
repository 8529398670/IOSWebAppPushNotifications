// Package routes contains one file per group of endpoints, plus this file,
// which is the only place that knows the full URL map.
//
// The API here stays deliberately small: it covers logging in, managing who
// can log in, issuing the API keys that let non-browser callers in, and
// reading the UI's text. Everything else an app does belongs in a new file in
// this package (server side) and in static/js/ (browser side) -- see
// references/architecture.md for where the line sits and why.
package routes

import (
	errors "errors"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
	db "ipb/server/db"
	errorpage "ipb/server/errorpage"
	jobs "ipb/server/jobs"
	language "ipb/server/language"
	logs "ipb/server/logs"
	metrics "ipb/server/metrics"
	mcp "ipb/server/mcp"
	models "ipb/server/models"
	push "ipb/server/push"
	security "ipb/server/security"
	static "ipb/server/static"
	webhooks "ipb/server/webhooks"
	stream "ipb/server/stream"
)

// Handlers carries the dependencies every route group needs. Passing this in
// rather than reaching for package-level globals is what makes the handlers
// testable and keeps the wiring visible in main.go.
type Handlers struct {
	Store *db.Store
	// Settings is the running configuration: read it through cfg(), once per
	// request, since config.yaml can change while the server runs.
	Settings *config.Holder
	Guard    *security.Guard
	Language *language.Language
	Static   *static.Server
	Pins     *models.AttemptGuard[ uint64 ]
	// Codes counts wrong two-factor codes per account, wherever they are
	// typed. Six digits with a window of three steps would otherwise fall to
	// a patient guesser.
	Codes *models.AttemptGuard[ uint64 ]
	// Per name typed, not per account, so a lockout does not say which names
	// are real; and per address, across names.
	PasswordNames     *models.AttemptGuard[ string ]
	PasswordAddresses *models.AttemptGuard[ string ]
	// Version is reported to MCP clients as serverInfo.version.
	Version string
	// Logs is the activity log (server/logs), set by main.go after New. Nil
	// or switched off, nothing is logged and its routes are not registered.
	Logs *logs.Logger
	// Jobs is the background job registry (server/jobs), set by main.go.
	Jobs *jobs.Registry
	// Webhooks is how a route says something happened (server/webhooks), set
	// by main.go. Nil is fine: nothing is sent.
	Webhooks *webhooks.Dispatcher
	// Metrics counts requests for /metrics, set by main.go.
	Metrics *metrics.Recorder
	// LogStream is who has the Logs screen open with Live on, set by main.go.
	LogStream *stream.Hub
	// Push works through the notification outbox, set by main.go.
	Push *push.Dispatcher
	// InboxStreams tells each person's open pages about a new message.
	InboxStreams *InboxStreams
	// ErrorPages is what a browser gets while the app is in maintenance mode,
	// set by main.go. Nil is fine: everyone gets the JSON answer.
	ErrorPages *errorpage.Pages
	// OpenAPI is config/openapi.json, set by main.go.
	OpenAPI []byte

	uploads       models.UploadLocks
	uiEventBudget eventBudget
	readiness     readiness
}

func New( store *db.Store , settings *config.Holder , guard *security.Guard , lang *language.Language , static_server *static.Server , version string ) ( handlers *Handlers ) {
	handlers = &Handlers{
		Store:    store,
		Settings: settings,
		Guard:    guard,
		Language: lang,
		Static:   static_server,
		Pins:     models.NewAttemptGuard[ uint64 ]( models.AttemptMaxFailures ),
		Codes:    models.NewAttemptGuard[ uint64 ]( models.AttemptMaxFailures ),
		PasswordNames:     models.NewAttemptGuard[ string ]( models.AttemptMaxFailures ),
		PasswordAddresses: models.NewAttemptGuard[ string ]( passwordAddressMaxFailures ),
		Version:  version,
		InboxStreams: NewInboxStreams(),
	}
	return
}

// Register wires every route. Read it top to bottom to see the whole surface
// of this server.
func ( handlers *Handlers ) Register( app *fiber.App ) {
	// Resolve the session once, before anything else looks at the request.
	app.Use( handlers.Guard.LoadUser )

	// Next, because it needs to know who is asking and has to come before
	// every route below. See maintenance.go.
	app.Use( handlers.Maintenance )

	// Public: the login link's page and the call it makes, and the UI's text
	// (needed to render the signed-out page at all). Opening a login link
	// only shows a page; the link is spent by the POST that page sends when
	// the person confirms. See auth.go.
	app.Get( "/login/manifest.webmanifest" , handlers.GetManifest )
	app.Get( "/login/*" , handlers.ShowLoginPage )
	app.Post( "/api/login" , handlers.RedeemLoginLink )
	app.Get( "/api/login/options" , handlers.GetLoginOptions )
	app.Post( "/api/login/two-factor" , handlers.FinishSignIn )
	app.Post( "/api/login/password" , handlers.RequirePasswords , handlers.PasswordLogin )
	app.Get( "/api/language" , handlers.GetLanguage )
	app.Get( "/api/health" , handlers.GetHealth )
	app.Get( "/api/ready" , handlers.GetReady )

	// Public: invite links (see join.go). Holding the link is the permission,
	// so these sit before the signed-in "/api" group below -- registered
	// after it, they would pick up RequireLogin from the shared prefix.
	app.Get( "/join/manifest.webmanifest" , handlers.GetManifest )
	app.Get( "/join/*" , handlers.ShowJoinPage )
	app.Post( "/api/join/info" , handlers.RequireInviteLinks , handlers.JoinInfo )
	app.Post( "/api/join/match" , handlers.RequireInviteLinks , handlers.JoinMatch )
	app.Post( "/api/join/claim" , handlers.RequireInviteLinks , handlers.JoinClaim )
	app.Post( "/api/join/create" , handlers.RequireInviteLinks , handlers.JoinCreate )

	// Public: the notification API. A token is the permission, so these sit
	// before the signed-in "/api" group, which would otherwise ask for a login.
	app.Post( "/api/v1/messages" , handlers.SendMessage )
	app.Post( "/1/messages.json" , handlers.SendMessage )

	// Public: what iOS reads when iPB is added to a Home Screen. It fetches the
	// manifest without cookies, and a new install has none. The page's manifest
	// href is relative, so a login or join page finds it beside itself. See
	// push.go.
	app.Get( "/manifest.webmanifest" , handlers.GetManifest )
	app.Get( "/i/:credential" , handlers.ShowInstallPage )
	app.Get( "/i/:credential/manifest.webmanifest" , handlers.GetManifest )

	// Any signed-in user.
	account := app.Group( "/api" , handlers.Guard.RequireLogin )
	account.Get( "/me" , handlers.GetMe )
	handlers.registerPush( account )
	account.Post( "/account/rename" , handlers.RenameAccount )
	// A session only: a PIN lets its holder sign in through an invite link,
	// so a key that could set one could turn itself into a session.
	account.Post( "/account/pin" , handlers.RequireInviteLinks , handlers.Guard.RequireSession , handlers.SetPin )
	// A session only, for the same reason as every route that hands out a
	// login link: the link becomes a session. See the admin group below.
	account.Post( "/account/login-link" , handlers.Guard.RequireSession , handlers.CreateMyLoginLink )
	// Passwords and 2FA change how an account signs in, so setting them needs
	// a session, like the PIN: a key that could set a password could turn
	// itself into a session.
	account.Post( "/account/password" , handlers.RequirePasswords , handlers.Guard.RequireSession , handlers.SetPassword )
	account.Post( "/account/two-factor/start" , handlers.RequireTwoFactor , handlers.Guard.RequireSession , handlers.StartTwoFactor )
	account.Post( "/account/two-factor/confirm" , handlers.RequireTwoFactor , handlers.Guard.RequireSession , handlers.ConfirmTwoFactor )
	account.Post( "/account/two-factor/disable" , handlers.RequireTwoFactor , handlers.Guard.RequireSession , handlers.DisableTwoFactor )
	// Your own signed-in devices. A session only: a key that could end
	// sessions could lock its owner out of the screen that revokes it.
	account.Get( "/account/sessions" , handlers.Guard.RequireSession , handlers.ListMySessions )
	account.Get( "/account/storage" , handlers.RequireFiles , handlers.MyStorage )
	account.Post( "/account/sessions/revoke-others" , handlers.Guard.RequireSession , handlers.RevokeMyOtherSessions )
	account.Post( "/account/sessions/:session_id/revoke" , handlers.Guard.RequireSession , handlers.RevokeMySession )
	account.Post( "/logout" , handlers.Logout )
	account.Get( "/team" , handlers.ListTeam )
	account.Get( "/openapi.json" , handlers.GetOpenAPI )
	// What someone did on the page, sent by track.js. Theirs to send, the
	// owner's to read (below).
	if handlers.Logs.Enabled() {
		account.Post( "/logs/events" , handlers.RecordUIEvents )
	}

	// API keys: any signed-in user manages their own.
	//
	// Note the group prefix. A group's middleware is mounted on a path
	// *prefix*, not on the routes written under it, so it applies to every
	// route registered after it whose path starts with that prefix. Mounting
	// these two on "/api" would put RequireSession in front of /api/admin/users
	// as well, and an admin-scoped API key would then be refused there. That is
	// also why the prefix is exactly "/api/keys": a future "/api/keysets" would
	// pick up this middleware by sharing the string, so keep new routes off
	// these prefixes unless they want these rules.
	keys := app.Group( "/api/keys" , handlers.RequireAPIKeys , handlers.Guard.RequireLogin , handlers.Guard.RequireSession )
	keys.Get( "" , handlers.ListMyAPIKeys )
	keys.Post( "" , handlers.CreateMyAPIKey )
	keys.Post( "/:key_id/rename" , handlers.RenameMyAPIKey )
	keys.Post( "/:key_id/expiry" , handlers.SetMyAPIKeyExpiry )
	keys.Post( "/:key_id/revoke" , handlers.RevokeMyAPIKey )
	keys.Post( "/:key_id/delete" , handlers.DeleteMyAPIKey )
	keys.Post( "/:key_id/restore" , handlers.RestoreMyAPIKey )

	// Uploaded files: everyone their own, API keys included. See files.go.
	// Always registered, like /mcp: files.enabled can change while the server
	// runs, so RequireFiles checks it per request.
	files := app.Group( "/api/files" , handlers.RequireFiles , handlers.Guard.RequireLogin )
	files.Get( "" , handlers.ListMyFiles )
	files.Post( "" , handlers.CreateFile )
	files.Get( "/:file_id" , handlers.GetMyFile )
	files.Post( "/:file_id/chunks/:index" , handlers.PutFileChunk )
	files.Post( "/:file_id/finish" , handlers.FinishFile )
	files.Get( "/:file_id/download" , handlers.DownloadMyFile )
	files.Post( "/:file_id/rename" , handlers.RenameMyFile )
	files.Post( "/:file_id/delete" , handlers.DeleteMyFile )
	files.Post( "/:file_id/restore" , handlers.RestoreMyFile )

	// Admin only: deciding who gets in. Note this is the *only* thing admin
	// rights gate in the base template -- see architecture.md on defaulting
	// new features to "any signed-in user".
	//
	// The two routes that hand out a login link also require a browser
	// session, attached per route rather than on a group prefix. A login link
	// becomes a session, and a session can mint API keys -- so if an
	// admin-scoped key could create accounts or reissue links, a leaked key
	// could turn itself into a fresh session and a fresh key, and revoking
	// the leaked one would not end the compromise. The rule is: an API key
	// may use what an account can do, but it never creates credentials.
	//
	// Deleting an account requires a session too, for a different reason: it
	// cannot be undone. A leaked admin key can disable accounts, which an
	// admin can reverse; it must not be able to erase them. Who may delete
	// whom (the owner rules) is enforced in models.DeleteUser.
	admin := app.Group( "/api/admin" , handlers.Guard.RequireAdmin )
	admin.Get( "/users" , handlers.ListUsers )
	admin.Post( "/users" , handlers.Guard.RequireSession , handlers.CreateUser )
	admin.Post( "/users/:user_id/reissue-login" , handlers.Guard.RequireSession , handlers.ReissueLogin )
	admin.Post( "/users/:user_id/rename" , handlers.Guard.RequireSession , handlers.RenameUser )
	admin.Post( "/users/:user_id/role" , handlers.Guard.RequireSession , handlers.SetUserRole )
	admin.Post( "/users/:user_id/disabled" , handlers.SetUserDisabled )
	admin.Post( "/users/:user_id/revoke-access" , handlers.RevokeAccess )
	admin.Post( "/users/:user_id/delete" , handlers.Guard.RequireSession , handlers.DeleteUser )
	admin.Post( "/users/:user_id/reset-two-factor" , handlers.Guard.RequireSession , handlers.ResetTwoFactor )
	// A session only, like your own devices list: a key that could end
	// sessions could end the one that would revoke it.
	admin.Get( "/users/:user_id/sessions" , handlers.Guard.RequireSession , handlers.ListUserSessions )
	admin.Post( "/users/:user_id/sessions/:session_id/revoke" , handlers.Guard.RequireSession , handlers.RevokeUserSession )
	admin.Get( "/storage" , handlers.RequireFiles , handlers.AllStorage )

	// Invite links: one link for a group, each person who opens it joins as a
	// new user (see invite_links.go). Creating one needs a session for the
	// same reason as creating a user -- the link mints accounts and sessions.
	// Deleting one needs a session like deleting a user. Listing and
	// switching one off are safe for an admin key.
	admin.Get( "/invite-links" , handlers.RequireInviteLinks , handlers.ListInviteLinks )
	admin.Post( "/invite-links" , handlers.RequireInviteLinks , handlers.Guard.RequireSession , handlers.CreateInviteLink )
	admin.Post( "/invite-links/:link_id/rename" , handlers.RequireInviteLinks , handlers.Guard.RequireSession , handlers.RenameInviteLink )
	admin.Post( "/invite-links/:link_id/limits" , handlers.RequireInviteLinks , handlers.Guard.RequireSession , handlers.SetInviteLinkLimits )
	admin.Post( "/invite-links/:link_id/switch-on" , handlers.RequireInviteLinks , handlers.Guard.RequireSession , handlers.SwitchOnInviteLink )
	admin.Post( "/invite-links/:link_id/revoke" , handlers.RequireInviteLinks , handlers.RevokeInviteLink )
	admin.Post( "/invite-links/:link_id/delete" , handlers.RequireInviteLinks , handlers.Guard.RequireSession , handlers.DeleteInviteLink )
	admin.Post( "/invite-links/:link_id/restore" , handlers.RequireInviteLinks , handlers.Guard.RequireSession , handlers.RestoreInviteLink )

	// Admin view of every key in the app -- "who has standing access" -- and
	// the ability to revoke or delete someone else's. Its own prefix for the
	// same reason as above: mounted on "/api/admin" it would gate the account
	// routes too.
	admin_keys := app.Group( "/api/admin/keys" , handlers.RequireAPIKeys , handlers.Guard.RequireAdmin , handlers.Guard.RequireSession )
	admin_keys.Get( "" , handlers.ListAllAPIKeys )
	admin_keys.Post( "" , handlers.CreateAPIKeyForUser )
	admin_keys.Post( "/:key_id/rename" , handlers.RenameAnyAPIKey )
	admin_keys.Post( "/:key_id/expiry" , handlers.SetAnyAPIKeyExpiry )
	admin_keys.Post( "/:key_id/revoke" , handlers.RevokeAnyAPIKey )
	admin_keys.Post( "/:key_id/delete" , handlers.DeleteAnyAPIKey )
	admin_keys.Post( "/:key_id/restore" , handlers.RestoreAnyAPIKey )

	// Every account's files. An admin key may list them, but reading or
	// deleting someone else's needs a session: a leaked key must not be a way
	// to carry off the contents of every account.
	admin_files := app.Group( "/api/admin/files" , handlers.RequireFiles , handlers.Guard.RequireAdmin )
	admin_files.Get( "" , handlers.ListAllFiles )
	admin_files.Get( "/:file_id/download" , handlers.Guard.RequireSession , handlers.DownloadAnyFile )
	admin_files.Post( "/:file_id/rename" , handlers.Guard.RequireSession , handlers.RenameAnyFile )
	admin_files.Post( "/:file_id/delete" , handlers.Guard.RequireSession , handlers.DeleteAnyFile )
	admin_files.Post( "/:file_id/restore" , handlers.Guard.RequireSession , handlers.RestoreAnyFile )

	// config.yaml, as the owner's Settings screen: the owner only, from a
	// browser session, like the activity log below. See settings.go.
	owner_settings := app.Group( "/api/owner/settings" , handlers.Guard.RequireOwner )
	owner_settings.Get( "" , handlers.GetSettings )
	owner_settings.Post( "" , handlers.SaveSettings )

	// The per-account password switch. One exact path, so nothing else picks
	// up these guards. See passwords.go.
	app.Post( "/api/owner/users/:user_id/password-access" , handlers.RequirePasswords , handlers.Guard.RequireOwner , handlers.SetPasswordAccess )

	// The activity log: the owner only, from a browser session -- not other
	// admins, not any API key (see Guard.RequireOwner). Its own prefix, so
	// nothing else picks up RequireOwner by sharing the string.
	if handlers.Logs.Enabled() {
		owner_logs := app.Group( "/api/owner/logs" , handlers.Guard.RequireOwner )
		owner_logs.Get( "/stream" , handlers.StreamLogs )
		owner_logs.Get( "/days" , handlers.ListLogDays )
		owner_logs.Get( "/days/:date" , handlers.GetLogDay )
		owner_logs.Get( "/days/:date/download" , handlers.DownloadLogDay )
		owner_logs.Post( "/days/:date/delete" , handlers.DeleteLogDay )
		owner_logs.Post( "/prune" , handlers.PruneLogs )
	}

	// Background jobs: the owner only, from a browser session, like the log.
	owner_jobs := app.Group( "/api/owner/jobs" , handlers.Guard.RequireOwner )
	owner_jobs.Get( "" , handlers.ListJobs )
	owner_jobs.Post( "/:name/run" , handlers.RunJob )

	// Outbound webhooks: the owner only, from a browser session, like the log.
	owner_webhooks := app.Group( "/api/owner/webhooks" , handlers.RequireWebhooks , handlers.Guard.RequireOwner )
	owner_webhooks.Get( "" , handlers.ListWebhooks )
	owner_webhooks.Post( "" , handlers.CreateWebhook )
	owner_webhooks.Get( "/events" , handlers.ListWebhookEvents )
	owner_webhooks.Post( "/:webhook_id/enabled" , handlers.SetWebhookEnabled )
	owner_webhooks.Post( "/:webhook_id/rename" , handlers.RenameWebhook )
	owner_webhooks.Post( "/:webhook_id/target" , handlers.SetWebhookTarget )
	owner_webhooks.Post( "/:webhook_id/rotate-secret" , handlers.RotateWebhookSecret )
	owner_webhooks.Post( "/:webhook_id/delete" , handlers.DeleteWebhook )
	owner_webhooks.Post( "/:webhook_id/restore" , handlers.RestoreWebhook )
	owner_webhooks.Post( "/:webhook_id/test" , handlers.TestWebhook )
	owner_webhooks.Get( "/:webhook_id/deliveries" , handlers.ListWebhookDeliveries )
	owner_webhooks.Post( "/:webhook_id/deliveries/:delivery_id/resend" , handlers.ResendWebhookDelivery )

	// MCP: agents calling the app with an API key (see server/mcp and
	// mcp_tools.go). Keys only -- RequireAPIKey turns a browser session away
	// -- and every tool runs at the key's effective role, so this is the API
	// above in another shape, not a wider one. One exact path, not a group:
	// a group on "/mcp" would also catch any later "/mcp..." route.
	//
	// Always registered: server.mcp and auth.api_keys can be switched while
	// the server runs, so RequireMCP checks them per request and answers 404
	// when either is off -- exactly what an unregistered route would say.
	mcp_server := mcp.New( handlers.Settings.Boot().ProjectName , handlers.Version )
	handlers.registerMCPTools( mcp_server )
	app.Post( "/mcp" , handlers.RequireMCP , handlers.Guard.RequireAPIKey , mcp_server.Handle )
	app.Get( "/mcp" , handlers.RequireMCP , mcp_server.MethodNotAllowed )
	app.Delete( "/mcp" , handlers.RequireMCP , mcp_server.MethodNotAllowed )

	// Prometheus. One exact path outside /api, so no group's guards reach it,
	// and always registered so metrics.enabled can change while the server
	// runs. An admin key only: the numbers say how the server is doing, and a
	// browser session has no business scraping.
	app.Get( "/metrics" , handlers.RequireMetrics , handlers.Guard.RequireAPIKey , handlers.Guard.RequireAdmin , handlers.GetMetrics )

	// Any other /api/ path is a JSON 404, not a static page.
	app.Get( "/api/*" , func( c fiber.Ctx ) ( err error ) {
		err = c.Status( fiber.StatusNotFound ).JSON( fiber.Map{ "error": "not found" } )
		return
	} )

	// Catch-all static serving. Must be registered last -- it matches every
	// remaining path, so anything added after this line never runs.
	app.Get( "/*" , handlers.Static.Handler )
}

func ( handlers *Handlers ) cfg() ( cfg *config.Config ) {
	cfg = handlers.Settings.Get()
	return
}

// RequireMCP makes /mcp answer 404 while server.mcp or auth.api_keys is off.
func ( handlers *Handlers ) RequireMCP( c fiber.Ctx ) ( err error ) {
	cfg := handlers.cfg()
	if cfg.MCPEnabled == false || cfg.APIKeysEnabled == false {
		err = notFound( c , "not found" )
		return
	}
	err = c.Next()
	return
}

// badRequest / notFound keep error bodies uniform, so the frontend has one
// shape to handle and no handler accidentally leaks internal detail.
func badRequest( c fiber.Ctx , message string ) ( err error ) {
	err = c.Status( fiber.StatusBadRequest ).JSON( fiber.Map{ "error": message } )
	return
}

func notFound( c fiber.Ctx , message string ) ( err error ) {
	err = c.Status( fiber.StatusNotFound ).JSON( fiber.Map{ "error": message } )
	return
}

func forbidden( c fiber.Ctx , message string ) ( err error ) {
	err = c.Status( fiber.StatusForbidden ).JSON( fiber.Map{ "error": message } )
	return
}

// conflict is 409: the request was fine but the record has moved on -- an
// undo whose window has passed, or a rename that expected a name someone else
// has since changed. extra carries the current state, so the caller can show
// it.
func conflict( c fiber.Ctx , message string , extra fiber.Map ) ( err error ) {
	body := fiber.Map{ "error": message }
	for name , value := range extra {
		body[ name ] = value
	}
	err = c.Status( fiber.StatusConflict ).JSON( body )
	return
}

// restoreRefused answers each way a restore can be refused.
func restoreRefused( c fiber.Ctx , refusal error ) ( err error ) {
	switch {
	case errors.Is( refusal , models.ErrRestoreGone ):
		err = notFound( c , refusal.Error() )
	case errors.Is( refusal , models.ErrRestoreForbidden ):
		err = forbidden( c , refusal.Error() )
	case errors.Is( refusal , models.ErrRestoreExpired ):
		err = conflict( c , refusal.Error() , nil )
	case errors.Is( refusal , models.ErrAPIKeyLimit ):
		err = conflict( c , "its owner already has the maximum number of live API keys" , nil )
	default:
		err = serverError( c , refusal )
	}
	return
}

// serverError ends a request that failed on our side. It writes nothing:
// handing cause back up is what gets it to the log, and to the ErrorHandler
// (server/middleware/errors.go), which answers with the generic message and a
// reference the person can quote. The cause itself never reaches them.
func serverError( _ fiber.Ctx , cause error ) ( err error ) {
	err = cause
	if err == nil {
		err = errors.New( "internal error" )
	}
	return
}
