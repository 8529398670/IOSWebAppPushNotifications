package routes

import (
	errors "errors"
	strings "strings"

	fiber "github.com/gofiber/fiber/v3"

	db "ipb/server/db"
	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
	webhooks "ipb/server/webhooks"
)

// The owner's Webhooks screen. Owner only, from a browser session, like the
// Logs and Settings screens: an endpoint sends what happens here to somewhere
// else, so a leaked key must not be able to add one. There are no MCP tools
// for this, for the same reason. See server/webhooks.

// RequireWebhooks makes the Webhooks screen's routes answer 404 while
// webhooks.enabled is off. Per request, like RequireFiles.
func ( handlers *Handlers ) RequireWebhooks( c fiber.Ctx ) ( err error ) {
	if handlers.cfg().Webhooks.Enabled == false {
		err = notFound( c , "not found" )
		return
	}
	err = c.Next()
	return
}

type createWebhookRequest struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	CSRFToken string   `json:"csrf_token"`
}

type webhookEnabledRequest struct {
	Enabled   bool   `json:"enabled"`
	CSRFToken string `json:"csrf_token"`
}

type renameWebhookRequest struct {
	Name      string  `json:"name"`
	Expect    *string `json:"expect"`
	CSRFToken string  `json:"csrf_token"`
}

type webhookTargetRequest struct {
	URL       string                `json:"url"`
	Events    []string              `json:"events"`
	Expect    *models.WebhookTarget `json:"expect"`
	CSRFToken string                `json:"csrf_token"`
}

// webhookRow picks the fields by hand, like sessionRow, so the sealed secret
// cannot reach a response by way of a change to the model.
func webhookRow( hook *models.Webhook ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":         hook.ID,
		"name":       hook.Name,
		"url":        hook.URL,
		"events":     hook.Events,
		"enabled":    hook.Enabled,
		"created_at": hook.CreatedAt,
	}
	return
}

// deliveryRow leaves out the body: the screen is for "did it arrive".
func deliveryRow( delivery *models.WebhookDelivery ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":              delivery.ID,
		"event":           delivery.Event,
		"status":          delivery.Status,
		"attempts":        delivery.Attempts,
		"created_at":      delivery.CreatedAt,
		"next_attempt_at": delivery.NextAttemptAt,
	}
	if delivery.LastStatus != 0 {
		row[ "last_status" ] = delivery.LastStatus
	}
	if delivery.LastError != "" {
		row[ "last_error" ] = delivery.LastError
	}
	if delivery.FinishedAt != nil {
		row[ "finished_at" ] = delivery.FinishedAt
	}
	return
}

// ListWebhookEvents is what the form offers.
func ( handlers *Handlers ) ListWebhookEvents( c fiber.Ctx ) ( err error ) {
	err = c.JSON( fiber.Map{ "events": models.WebhookEvents } )
	return
}

func ( handlers *Handlers ) ListWebhooks( c fiber.Ctx ) ( err error ) {
	hooks , list_err := models.ListWebhooks( handlers.Store )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	rows := []fiber.Map{}
	for _ , hook := range hooks {
		rows = append( rows , webhookRow( hook ) )
	}
	err = sendPage( c , "webhooks" , rows )
	return
}

// CreateWebhook answers with the signing secret, the only time it is shown.
func ( handlers *Handlers ) CreateWebhook( c fiber.Ctx ) ( err error ) {
	var body createWebhookRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	cfg := handlers.cfg()
	if models.ValidWebhook( body.Name , body.URL , body.Events ) == false {
		err = badRequest( c , models.ErrBadWebhook.Error() )
		return
	}
	if check_err := webhooks.CheckURL( body.URL , cfg.Webhooks.AllowPrivateTargets ); check_err != nil {
		err = badRequest( c , check_err.Error() )
		return
	}
	secret , hook , create_err := models.CreateWebhook( handlers.Store , cfg.SecretKey , body.Name , body.URL , body.Events , security.UserFrom( c ).ID )
	if create_err != nil {
		err = serverError( c , create_err )
		return
	}
	// The name only: the url can hold a token of its own.
	handlers.audit( c , logs.KindAdmin , "webhook created" , fiber.Map{ "webhook_id": hook.ID , "name": hook.Name } )
	row := webhookRow( hook )
	row[ "secret" ] = secret
	err = c.Status( fiber.StatusCreated ).JSON( row )
	return
}

func ( handlers *Handlers ) SetWebhookEnabled( c fiber.Ctx ) ( err error ) {
	var body webhookEnabledRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	// Clone: the log entry outlives this request, and fiber reuses the buffer.
	webhook_id := strings.Clone( c.Params( "webhook_id" ) )
	if models.SetWebhookEnabled( handlers.Store , webhook_id , body.Enabled ) != nil {
		err = notFound( c , "no such webhook" )
		return
	}
	handlers.audit( c , logs.KindAdmin , "webhook enabled set" , fiber.Map{ "webhook_id": webhook_id , "enabled": body.Enabled } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

func ( handlers *Handlers ) RenameWebhook( c fiber.Ctx ) ( err error ) {
	var body renameWebhookRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if models.ValidWebhookName( body.Name ) == false {
		err = badRequest( c , models.ErrBadWebhookName.Error() )
		return
	}
	webhook_id := strings.Clone( c.Params( "webhook_id" ) )
	rename_err := models.RenameWebhook( handlers.Store , webhook_id , body.Name , body.Expect )
	var refusal *models.RenameConflictError
	switch {
	case errors.As( rename_err , &refusal ):
		err = conflict( c , refusal.Error() , fiber.Map{ "name": refusal.Current } )
		return
	case errors.Is( rename_err , db.ErrNotFound ):
		err = notFound( c , "no such webhook" )
		return
	case rename_err != nil:
		err = serverError( c , rename_err )
		return
	}
	name := strings.TrimSpace( body.Name )
	handlers.audit( c , logs.KindAdmin , "webhook renamed" , fiber.Map{ "webhook_id": webhook_id , "name": name } )
	err = c.JSON( fiber.Map{ "ok": true , "name": name } )
	return
}

// SetWebhookTarget changes the address and the events. The address gets the
// same check as a new endpoint's, every time: an events-only edit of one that
// has since been ruled out is refused too, and the sender would refuse it anyway.
func ( handlers *Handlers ) SetWebhookTarget( c fiber.Ctx ) ( err error ) {
	var body webhookTargetRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	target := models.WebhookTarget{ URL: body.URL , Events: body.Events }
	if models.ValidWebhookTarget( target ) == false {
		err = badRequest( c , models.ErrBadWebhookTarget.Error() )
		return
	}
	if check_err := webhooks.CheckURL( body.URL , handlers.cfg().Webhooks.AllowPrivateTargets ); check_err != nil {
		err = badRequest( c , check_err.Error() )
		return
	}
	webhook_id := strings.Clone( c.Params( "webhook_id" ) )
	set_err := models.SetWebhookTarget( handlers.Store , webhook_id , target , body.Expect )
	switch {
	case errors.Is( set_err , models.ErrWebhookChanged ):
		err = conflict( c , set_err.Error() , nil )
		return
	case errors.Is( set_err , db.ErrNotFound ):
		err = notFound( c , "no such webhook" )
		return
	case set_err != nil:
		err = serverError( c , set_err )
		return
	}
	// The events but not the url, which can hold a token of its own.
	handlers.audit( c , logs.KindAdmin , "webhook target changed" , fiber.Map{ "webhook_id": webhook_id , "events": body.Events } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// RotateWebhookSecret answers with the new signing secret, the only time it
// is shown.
func ( handlers *Handlers ) RotateWebhookSecret( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	webhook_id := strings.Clone( c.Params( "webhook_id" ) )
	secret , rotate_err := models.RotateWebhookSecret( handlers.Store , handlers.cfg().SecretKey , webhook_id )
	switch {
	case errors.Is( rotate_err , db.ErrNotFound ):
		err = notFound( c , "no such webhook" )
		return
	case rotate_err != nil:
		err = serverError( c , rotate_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "webhook secret rotated" , fiber.Map{ "webhook_id": webhook_id } )
	err = c.JSON( fiber.Map{ "secret": secret } )
	return
}

func ( handlers *Handlers ) DeleteWebhook( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	webhook_id := strings.Clone( c.Params( "webhook_id" ) )
	if models.DeleteWebhook( handlers.Store , webhook_id , security.UserFrom( c ).ID ) != nil {
		err = notFound( c , "no such webhook" )
		return
	}
	handlers.audit( c , logs.KindAdmin , "webhook deleted" , fiber.Map{ "webhook_id": webhook_id } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

func ( handlers *Handlers ) RestoreWebhook( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	webhook_id := strings.Clone( c.Params( "webhook_id" ) )
	actor := security.UserFrom( c )
	hook , restore_err := models.RestoreWebhook( handlers.Store , webhook_id , actor.ID , actor.IsAdmin() )
	if restore_err != nil {
		err = restoreRefused( c , restore_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "webhook restored" , fiber.Map{ "webhook_id": webhook_id } )
	err = c.JSON( webhookRow( hook ) )
	return
}

// liveWebhook loads an endpoint the screen can act on.
func ( handlers *Handlers ) liveWebhook( webhook_id string ) ( hook *models.Webhook , err error ) {
	hook , err = models.GetWebhook( handlers.Store , webhook_id )
	if err == nil && hook.Deleted() {
		hook , err = nil , db.ErrNotFound
	}
	return
}

// TestWebhook queues a webhook.test event. For an endpoint that is switched
// off, the delivery says so rather than the event going out.
func ( handlers *Handlers ) TestWebhook( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	hook , get_err := handlers.liveWebhook( c.Params( "webhook_id" ) )
	switch {
	case errors.Is( get_err , db.ErrNotFound ):
		err = notFound( c , "no such webhook" )
		return
	case get_err != nil:
		err = serverError( c , get_err )
		return
	}
	if send_err := handlers.Webhooks.SendTest( hook ); send_err != nil {
		err = serverError( c , send_err )
		return
	}
	err = c.Status( fiber.StatusAccepted ).JSON( fiber.Map{ "ok": true } )
	return
}

// ResendWebhookDelivery queues a delivery that was given up on.
func ( handlers *Handlers ) ResendWebhookDelivery( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	hook , get_err := handlers.liveWebhook( c.Params( "webhook_id" ) )
	switch {
	case errors.Is( get_err , db.ErrNotFound ):
		err = notFound( c , "no such webhook" )
		return
	case get_err != nil:
		err = serverError( c , get_err )
		return
	}
	// Clone: the log entry outlives this request, and fiber reuses the buffer.
	delivery_id := strings.Clone( c.Params( "delivery_id" ) )
	send_err := handlers.Webhooks.Resend( hook.ID , delivery_id )
	switch {
	case errors.Is( send_err , db.ErrNotFound ):
		err = notFound( c , "no such delivery" )
	case errors.Is( send_err , models.ErrDeliveryNotFailed ):
		err = conflict( c , "delivery_not_failed" , nil )
	case send_err != nil:
		err = serverError( c , send_err )
	default:
		handlers.audit( c , logs.KindAdmin , "webhook delivery resent" , fiber.Map{ "webhook_id": hook.ID , "delivery_id": delivery_id } )
		err = c.Status( fiber.StatusAccepted ).JSON( fiber.Map{ "ok": true } )
	}
	return
}

func ( handlers *Handlers ) ListWebhookDeliveries( c fiber.Ctx ) ( err error ) {
	hook , get_err := handlers.liveWebhook( c.Params( "webhook_id" ) )
	switch {
	case errors.Is( get_err , db.ErrNotFound ):
		err = notFound( c , "no such webhook" )
		return
	case get_err != nil:
		err = serverError( c , get_err )
		return
	}
	deliveries , list_err := models.ListWebhookDeliveries( handlers.Store , hook.ID )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	rows := []fiber.Map{}
	for _ , delivery := range deliveries {
		rows = append( rows , deliveryRow( delivery ) )
	}
	err = sendPage( c , "deliveries" , rows )
	return
}
