package models

import (
	json "encoding/json"
	errors "errors"
	slices "slices"
	sort "sort"
	strings "strings"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// The events an endpoint can subscribe to by name. These are a promise to
// whoever receives them, so a name never changes once it ships; the activity
// log's messages are free text and make no such promise.
//
// An app adds its own by appending here and calling Emit where the thing
// happens. An event missing from this list still reaches "*" subscribers.
const (
	EventUserCreated       = "user.created"
	EventUserDisabled      = "user.disabled"
	EventUserDeleted       = "user.deleted"
	EventAPIKeyCreated     = "api_key.created"
	EventAPIKeyRevoked     = "api_key.revoked"
	EventInviteLinkCreated = "invite_link.created"
	EventInviteLinkRevoked = "invite_link.revoked"
	EventJobFailed         = "job.failed"
	EventFileUploaded      = "file.uploaded"
	EventFileDeleted       = "file.deleted"
	// EventWebhookTest only ever goes to the one endpoint being tested.
	EventWebhookTest = "webhook.test"

	// WebhookAllEvents subscribes an endpoint to everything but the test.
	WebhookAllEvents = "*"
)

var WebhookEvents = []string{
	EventUserCreated , EventUserDisabled , EventUserDeleted ,
	EventAPIKeyCreated , EventAPIKeyRevoked ,
	EventInviteLinkCreated , EventInviteLinkRevoked ,
	EventJobFailed ,
	EventFileUploaded , EventFileDeleted ,
}

const (
	WebhookPending   = "pending"
	WebhookDelivered = "delivered"
	WebhookFailed    = "failed"

	// webhookDeliveryRetention is how long a finished delivery stays listed.
	webhookDeliveryRetention = 7 * 24 * time.Hour
	webhookNameMax           = 80
	webhookURLMax            = 2000
)

// webhookBackoff is the wait after each failed attempt. One more failure after
// the last of these and the delivery is given up on: six attempts over about
// fifteen hours, long enough to ride out a receiver's bad night.
var webhookBackoff = []time.Duration{
	time.Minute , 5 * time.Minute , 30 * time.Minute , 2 * time.Hour , 12 * time.Hour ,
}

var (
	ErrBadWebhook       = errors.New( "name must be 1-80 characters, the url at most 2000, and at least one known event picked" )
	ErrBadWebhookName   = errors.New( "name must be 1-80 characters" )
	ErrBadWebhookTarget = errors.New( "the url must be at most 2000 characters, with at least one known event picked" )
	ErrWebhookChanged   = errors.New( "the webhook was changed somewhere else in the meantime" )
)

// Webhook is one endpoint that wants to hear about things. Secret signs what
// is sent to it, so unlike a key's secret it has to come back: it is sealed
// with the secret key on its own, the way a TOTP secret is, because records
// may be stored unencrypted. RekeyRecord carries it across a rotation.
type Webhook struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	Secret    string    `json:"secret"`
	Enabled   bool      `json:"enabled"`
	CreatedBy uint64    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	SoftDelete
}

// WebhookTarget is where an endpoint's events go and which ones it wants.
type WebhookTarget struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
}

// Wants says whether an event should go to this endpoint.
func ( hook *Webhook ) Wants( event string ) ( result bool ) {
	if hook.Enabled == false || hook.Deleted() { return }
	for _ , wanted := range hook.Events {
		if wanted == event || wanted == WebhookAllEvents {
			result = true
			return
		}
	}
	return
}

// WebhookDelivery is one event on its way to one endpoint: the outbox row.
// Emit writes it and the webhooks job sends it, so a slow receiver never holds
// up a request and a restart loses nothing. Body is exactly what is sent, so a
// retry signs and sends the same bytes.
type WebhookDelivery struct {
	ID            string     `json:"id"`
	WebhookID     string     `json:"webhook_id"`
	Event         string     `json:"event"`
	Body          string     `json:"body"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LastStatus    int        `json:"last_status,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

// ValidWebhook checks everything but the address, which is
// webhooks.CheckURL's job: that depends on the running config.
func ValidWebhook( name string , url string , events []string ) ( result bool ) {
	result = ValidWebhookName( name ) && ValidWebhookTarget( WebhookTarget{ URL: url , Events: events } )
	return
}

// ValidWebhookName is the name half of ValidWebhook, for a rename.
func ValidWebhookName( name string ) ( result bool ) {
	trimmed := strings.TrimSpace( name )
	result = len( trimmed ) >= 1 && len( trimmed ) <= webhookNameMax
	return
}

// ValidWebhookTarget is the rest of ValidWebhook. The address itself is
// webhooks.CheckURL's job here too.
func ValidWebhookTarget( target WebhookTarget ) ( result bool ) {
	url , events := target.URL , target.Events
	if len( url ) < 1 || len( url ) > webhookURLMax || len( events ) == 0 { return }
	for _ , event := range events {
		known := event == WebhookAllEvents
		for _ , candidate := range WebhookEvents {
			known = known || candidate == event
		}
		if known == false { return }
	}
	result = true
	return
}

// CreateWebhook returns the signing secret exactly once, like a key: it can
// be recovered by the server, but no route ever shows it again.
func CreateWebhook( store *db.Store , secret_key string , name string , url string , events []string , created_by uint64 ) ( secret string , hook *Webhook , err error ) {
	if ValidWebhook( name , url , events ) == false {
		err = ErrBadWebhook
		return
	}
	secret = "whsec_" + encryption.GenerateURLToken( 24 )
	sealed , err := encryption.ChaChaEncryptString( secret_key , secret )
	if err != nil { return }
	hook = &Webhook{
		ID:        encryption.GenerateURLToken( 12 ),
		Name:      strings.TrimSpace( name ),
		URL:       url,
		Events:    events,
		Secret:    sealed,
		Enabled:   true,
		CreatedBy: created_by,
		CreatedAt: time.Now().UTC(),
	}
	if err = store.Put( db.BucketWebhooks , []byte( hook.ID ) , hook ); err != nil {
		secret , hook = "" , nil
	}
	return
}

// OpenWebhookSecret is the signing secret in the clear, for the sender.
func OpenWebhookSecret( hook *Webhook , secret_key string ) ( secret string , err error ) {
	secret , err = encryption.ChaChaDecryptBase64String( secret_key , hook.Secret )
	return
}

// GetWebhook loads an endpoint, deleted or not; db.ErrNotFound when there is
// no such id.
func GetWebhook( store *db.Store , webhook_id string ) ( hook *Webhook , err error ) {
	hook = &Webhook{}
	if err = store.Get( db.BucketWebhooks , []byte( webhook_id ) , hook ); err != nil { hook = nil }
	return
}

// ListWebhooks is every endpoint, newest first, leaving out deleted ones.
func ListWebhooks( store *db.Store ) ( hooks []*Webhook , err error ) {
	hooks = []*Webhook{}
	err = store.ForEach( db.BucketWebhooks ,
		func() any { return &Webhook{} } ,
		func( key []byte , item any ) bool {
			if hook := item.( *Webhook ); hook.Deleted() == false {
				hooks = append( hooks , hook )
			}
			return true
		} )
	sort.SliceStable( hooks , func( i int , j int ) bool { return hooks[ i ].CreatedAt.After( hooks[ j ].CreatedAt ) } )
	return
}

// SetWebhookEnabled switches an endpoint on or off; db.ErrNotFound when there
// is no such endpoint or it is deleted.
func SetWebhookEnabled( store *db.Store , webhook_id string , enabled bool ) ( err error ) {
	err = store.UpdateValue( db.BucketWebhooks , []byte( webhook_id ) ,
		func() any { return &Webhook{} } ,
		func( item any ) ( mutate_err error ) {
			hook := item.( *Webhook )
			if hook.Deleted() {
				mutate_err = db.ErrNotFound
				return
			}
			hook.Enabled = enabled
			return
		} )
	return
}

// RenameWebhook changes an endpoint's name. db.ErrNotFound when there is none
// or it is deleted. expect, when not nil, is the name the caller believes is
// stored, as in RenameUser: a *RenameConflictError if it is not.
func RenameWebhook( store *db.Store , webhook_id string , name string , expect *string ) ( err error ) {
	err = store.UpdateValue( db.BucketWebhooks , []byte( webhook_id ) ,
		func() any { return &Webhook{} } ,
		func( item any ) ( mutate_err error ) {
			hook := item.( *Webhook )
			if hook.Deleted() {
				mutate_err = db.ErrNotFound
				return
			}
			if expect != nil && hook.Name != strings.TrimSpace( *expect ) {
				mutate_err = &RenameConflictError{ Current: hook.Name }
				return
			}
			hook.Name = strings.TrimSpace( name )
			return
		} )
	return
}

// SetWebhookTarget changes an endpoint's address and events. The sender reads
// the endpoint at each attempt, so deliveries still waiting go to the new
// address: that is what fixing a mistyped one needs. Their events were picked
// when they were queued and stay queued. db.ErrNotFound when there is no such
// endpoint or it is deleted. expect, when not nil, is what the caller believes
// is stored: ErrWebhookChanged if it is not, so an undo cannot overwrite a
// later edit.
func SetWebhookTarget( store *db.Store , webhook_id string , target WebhookTarget , expect *WebhookTarget ) ( err error ) {
	err = store.UpdateValue( db.BucketWebhooks , []byte( webhook_id ) ,
		func() any { return &Webhook{} } ,
		func( item any ) ( mutate_err error ) {
			hook := item.( *Webhook )
			if hook.Deleted() {
				mutate_err = db.ErrNotFound
				return
			}
			if expect != nil && ( hook.URL != expect.URL || slices.Equal( hook.Events , expect.Events ) == false ) {
				mutate_err = ErrWebhookChanged
				return
			}
			hook.URL , hook.Events = target.URL , target.Events
			return
		} )
	return
}

// RotateWebhookSecret gives an endpoint a new signing secret and returns it,
// the only time it is shown, as with CreateWebhook. The old one stops at once
// and cannot come back. Each attempt is signed as it is sent, so a receiver
// that refuses deliveries until it has the new secret gets them on a retry.
// db.ErrNotFound when there is no such endpoint or it is deleted.
func RotateWebhookSecret( store *db.Store , secret_key string , webhook_id string ) ( secret string , err error ) {
	fresh := "whsec_" + encryption.GenerateURLToken( 24 )
	sealed , err := encryption.ChaChaEncryptString( secret_key , fresh )
	if err != nil { return }
	err = store.UpdateValue( db.BucketWebhooks , []byte( webhook_id ) ,
		func() any { return &Webhook{} } ,
		func( item any ) ( mutate_err error ) {
			hook := item.( *Webhook )
			if hook.Deleted() {
				mutate_err = db.ErrNotFound
				return
			}
			hook.Secret = sealed
			return
		} )
	if err == nil { secret = fresh }
	return
}

// DeleteWebhook marks an endpoint deleted, restorable for RestoreWindow;
// db.ErrNotFound when there is none or it is already deleted.
func DeleteWebhook( store *db.Store , webhook_id string , actor_id uint64 ) ( err error ) {
	err = store.UpdateValue( db.BucketWebhooks , []byte( webhook_id ) ,
		func() any { return &Webhook{} } ,
		func( item any ) ( mutate_err error ) {
			if item.( *Webhook ).markDeleted( actor_id ) == false {
				mutate_err = db.ErrNotFound
			}
			return
		} )
	return
}

// RestoreWebhook undoes DeleteWebhook, or returns ErrRestoreGone,
// ErrRestoreForbidden or ErrRestoreExpired.
func RestoreWebhook( store *db.Store , webhook_id string , actor_id uint64 , actor_is_admin bool ) ( hook *Webhook , err error ) {
	err = store.UpdateValue( db.BucketWebhooks , []byte( webhook_id ) ,
		func() any { return &Webhook{} } ,
		func( item any ) ( mutate_err error ) {
			hook = item.( *Webhook )
			mutate_err = hook.unmarkDeleted( actor_id , actor_is_admin )
			return
		} )
	if errors.Is( err , db.ErrNotFound ) { err = ErrRestoreGone }
	if err != nil { hook = nil }
	return
}

// newWebhookDelivery builds the outbox row. data carries ids and names only,
// the same rule as a log entry's detail: this leaves the server.
func newWebhookDelivery( webhook_id string , event string , data map[string]any ) ( delivery *WebhookDelivery , err error ) {
	now := time.Now().UTC()
	id := encryption.GenerateURLToken( 12 )
	body , err := json.Marshal( map[string]any{ "id": id , "event": event , "created_at": now , "data": data } )
	if err != nil { return }
	delivery = &WebhookDelivery{
		ID:            id,
		WebhookID:     webhook_id,
		Event:         event,
		Body:          string( body ),
		Status:        WebhookPending,
		NextAttemptAt: now,
		CreatedAt:     now,
	}
	return
}

// ErrDeliveryNotFailed answers a resend of a delivery still pending or already
// delivered: only one that was given up on has anything to resend.
var ErrDeliveryNotFailed = errors.New( "delivery has not failed" )

// ResendWebhookDelivery queues a delivery that was given up on for another go,
// once the receiver is fixed. A new row, so the failed attempts stay listed, but
// the same body, so its id still names one event: a receiver that handled the
// event and only failed to answer can tell this is the same one again.
func ResendWebhookDelivery( store *db.Store , webhook_id string , delivery_id string ) ( err error ) {
	original := &WebhookDelivery{}
	if err = store.Get( db.BucketWebhookDeliveries , []byte( delivery_id ) , original ); err != nil { return }
	if original.WebhookID != webhook_id {
		err = db.ErrNotFound
		return
	}
	if original.Status != WebhookFailed {
		err = ErrDeliveryNotFailed
		return
	}
	now := time.Now().UTC()
	again := &WebhookDelivery{
		ID:            encryption.GenerateURLToken( 12 ),
		WebhookID:     webhook_id,
		Event:         original.Event,
		Body:          original.Body,
		Status:        WebhookPending,
		NextAttemptAt: now,
		CreatedAt:     now,
	}
	err = store.Put( db.BucketWebhookDeliveries , []byte( again.ID ) , again )
	return
}

// EnqueueWebhookEvent writes one delivery per endpoint that wants the event,
// and says how many.
func EnqueueWebhookEvent( store *db.Store , event string , data map[string]any ) ( queued int , err error ) {
	hooks , err := ListWebhooks( store )
	if err != nil { return }
	for _ , hook := range hooks {
		if hook.Wants( event ) == false { continue }
		delivery , build_err := newWebhookDelivery( hook.ID , event , data )
		if build_err != nil {
			err = build_err
			return
		}
		if err = store.Put( db.BucketWebhookDeliveries , []byte( delivery.ID ) , delivery ); err != nil { return }
		queued += 1
	}
	return
}

// EnqueueWebhookTest queues a test event for one endpoint, whatever it
// subscribes to.
func EnqueueWebhookTest( store *db.Store , hook *Webhook ) ( err error ) {
	delivery , err := newWebhookDelivery( hook.ID , EventWebhookTest , map[string]any{ "webhook_id": hook.ID } )
	if err != nil { return }
	err = store.Put( db.BucketWebhookDeliveries , []byte( delivery.ID ) , delivery )
	return
}

// DueWebhookDeliveries is what the job should send now, oldest first, at most
// limit of them.
func DueWebhookDeliveries( store *db.Store , now time.Time , limit int ) ( due []*WebhookDelivery , err error ) {
	due = []*WebhookDelivery{}
	err = store.ForEach( db.BucketWebhookDeliveries ,
		func() any { return &WebhookDelivery{} } ,
		func( key []byte , item any ) bool {
			delivery := item.( *WebhookDelivery )
			if delivery.Status == WebhookPending && delivery.NextAttemptAt.After( now ) == false {
				due = append( due , delivery )
			}
			return true
		} )
	sort.SliceStable( due , func( i int , j int ) bool { return due[ i ].CreatedAt.Before( due[ j ].CreatedAt ) } )
	if len( due ) > limit {
		due = due[ :limit ]
	}
	return
}

// RecordWebhookAttempt notes how a send went. failure empty means delivered;
// otherwise the delivery waits its backoff, or is given up on when retry is
// false or the backoff has run out.
func RecordWebhookAttempt( store *db.Store , delivery_id string , status int , failure string , retry bool ) ( err error ) {
	err = store.UpdateValue( db.BucketWebhookDeliveries , []byte( delivery_id ) ,
		func() any { return &WebhookDelivery{} } ,
		func( item any ) ( mutate_err error ) {
			delivery := item.( *WebhookDelivery )
			now := time.Now().UTC()
			delivery.Attempts += 1
			delivery.LastStatus = status
			delivery.LastError = failure
			switch {
			case failure == "":
				delivery.Status = WebhookDelivered
				delivery.FinishedAt = &now
			case retry && delivery.Attempts <= len( webhookBackoff ):
				delivery.NextAttemptAt = now.Add( webhookBackoff[ delivery.Attempts-1 ] )
			default:
				delivery.Status = WebhookFailed
				delivery.FinishedAt = &now
			}
			return
		} )
	return
}

// ListWebhookDeliveries is one endpoint's deliveries, newest first.
func ListWebhookDeliveries( store *db.Store , webhook_id string ) ( deliveries []*WebhookDelivery , err error ) {
	deliveries = []*WebhookDelivery{}
	err = store.ForEach( db.BucketWebhookDeliveries ,
		func() any { return &WebhookDelivery{} } ,
		func( key []byte , item any ) bool {
			if delivery := item.( *WebhookDelivery ); delivery.WebhookID == webhook_id {
				deliveries = append( deliveries , delivery )
			}
			return true
		} )
	sort.SliceStable( deliveries , func( i int , j int ) bool { return deliveries[ i ].CreatedAt.After( deliveries[ j ].CreatedAt ) } )
	return
}

// PurgeWebhooks drops deleted endpoints past RestoreWindow and deliveries that
// finished longer than webhookDeliveryRetention ago.
func PurgeWebhooks( store *db.Store ) ( removed int , err error ) {
	hooks , hooks_err := store.DeleteWhere( db.BucketWebhooks ,
		func() any { return &Webhook{} } ,
		func( key []byte , item any ) bool { return item.( *Webhook ).deletedLongAgo() } )
	cutoff := time.Now().UTC().Add( -webhookDeliveryRetention )
	deliveries , deliveries_err := store.DeleteWhere( db.BucketWebhookDeliveries ,
		func() any { return &WebhookDelivery{} } ,
		func( key []byte , item any ) bool {
			finished := item.( *WebhookDelivery ).FinishedAt
			return finished != nil && finished.Before( cutoff )
		} )
	removed = hooks + deliveries
	err = errors.Join( hooks_err , deliveries_err )
	return
}
