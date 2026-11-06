// Package push sends one notification to one browser over Web Push.
package push

import (
	bytes "bytes"
	json "encoding/json"
	errors "errors"
	io "io"
	http "net/http"
	url "net/url"
	strconv "strconv"
	strings "strings"
	time "time"

	encryption "ipb/server/encryption"
	models "ipb/server/models"
	webhooks "ipb/server/webhooks"
)

const (
	// sendTimeout bounds one request to a push service.
	sendTimeout = 10 * time.Second
	// tokenLifetime is how long a signed request stays good. Apple refuses
	// anything over a day, and each request is signed as it is sent.
	tokenLifetime = time.Hour
	// reasonLimit caps how much of a push service's refusal is kept.
	reasonLimit = 200
	// declarativeMagic marks a payload as Declarative Web Push: iOS 18.4 and
	// later show it without running any script.
	declarativeMagic = 8030
)

// ErrUnknownService refuses an endpoint that is not on a known push service.
var ErrUnknownService = errors.New( "push endpoint is not on a known push service" )

// Exact hosts, and suffixes that match any host under them. An endpoint is a
// URL a browser handed in, so anything signed in could otherwise point this
// server at an address of its choosing.
var (
	allowedHosts    = []string{ "web.push.apple.com" , "fcm.googleapis.com" , "updates.push.services.mozilla.com" }
	allowedSuffixes = []string{ ".push.apple.com" , ".push.services.mozilla.com" , ".notify.windows.com" }
)

// AllowedEndpoint is true for an https URL on a known push service.
func AllowedEndpoint( raw string ) ( ok bool ) {
	parsed , err := url.Parse( raw )
	if err != nil || parsed.Scheme != "https" || parsed.User != nil { return }
	if parsed.Port() != "" && parsed.Port() != "443" { return }
	host := strings.ToLower( parsed.Hostname() )
	for _ , allowed := range allowedHosts {
		if host == allowed {
			ok = true
			return
		}
	}
	for _ , suffix := range allowedSuffixes {
		if strings.HasSuffix( host , suffix ) {
			ok = true
			return
		}
	}
	return
}

// Notification is what a person sees. Navigate has to be inside the install
// that receives it, or a tap opens somewhere else.
type Notification struct {
	Title    string
	Body     string
	Navigate string
	Silent   bool
	Badge    int
}

// NotificationFor turns an inbox item into what a person sees. Every push shows
// iPB's own icon, so the app's name in the title is what tells them apart.
func NotificationFor( item *models.InboxItem , base_url string , badge int ) ( notification Notification ) {
	title := item.AppName
	if item.Title != "" { title += ": " + item.Title }
	notification = Notification{
		Title:    title,
		Body:     item.Body,
		Navigate: base_url + "/#inbox",
		Silent:   item.Priority == models.PrioritySilent,
		Badge:    badge,
	}
	return
}

// UrgencyFor is the Urgency header for a priority.
func UrgencyFor( priority int ) ( urgency string ) {
	urgency = "normal"
	if priority >= models.PriorityHigh { urgency = "high" }
	if priority == models.PrioritySilent { urgency = "low" }
	return
}

// Payload is the JSON sent to a browser. One shape serves everyone: iOS 18.4
// and later read it themselves, and static/sw.js shows it everywhere else.
//
// A long message is cut to fit what a push can carry, by what it comes to once
// encoded, since one character can take six bytes there. The whole text stays
// in the inbox.
func Payload( notification Notification ) ( result []byte , err error ) {
	body := notification.Body
	for trims := 0; ; trims++ {
		result , err = json.Marshal( map[string]any{
			"web_push": declarativeMagic,
			"notification": map[string]any{
				"title":     notification.Title,
				"body":      body,
				"navigate":  notification.Navigate,
				"silent":    notification.Silent,
				"app_badge": strconv.Itoa( notification.Badge ),
			},
		} )
		if err != nil || len( result ) <= encryption.WebPushMaxPlainText { return }
		if trims == maxPayloadTrims {
			err = encryption.ErrWebPushTooLong
			return
		}
		runes := []rune( body )
		body = string( runes[ : len( runes ) * 3 / 4 ] ) + "…"
	}
}

// Sender holds what every request needs.
type Sender struct {
	PublicKey  string
	PrivateKey string
	Subject    string
	Client     *http.Client
	// allow overrides AllowedEndpoint, for a test's fake push service.
	allow func( string ) bool
}

// NewClient is the client a Sender uses. A push service is a public address,
// so this never needs to reach anything private.
func NewClient() ( result *http.Client ) {
	result = webhooks.GuardedClient( sendTimeout , false , true )
	return
}

// Cause is what went wrong with a request, fit to show and log. The http
// package's own message quotes the whole URL, and an endpoint's path is the
// subscription's secret, so only the reason underneath is kept.
func Cause( err error ) ( result string ) {
	result = err.Error()
	var failed *url.Error
	if errors.As( err , &failed ) {
		result = failed.Err.Error()
	}
	return
}

// Result is how a push service answered. Gone means this subscription is dead
// and should be forgotten.
type Result struct {
	Status int    `json:"status"`
	Reason string `json:"reason,omitempty"`
	Gone   bool   `json:"gone"`
}

// Send delivers one payload. The error is for failing to get an answer at all;
// a refusal from the push service is a Result.
func ( sender *Sender ) Send( subscription *models.PushSubscription , payload []byte , ttl time.Duration , urgency string ) ( result Result , err error ) {
	allow := sender.allow
	if allow == nil { allow = AllowedEndpoint }
	if allow( subscription.Endpoint ) == false {
		err = ErrUnknownService
		return
	}
	body , err := encryption.WebPushEncrypt( payload , subscription.P256dh , subscription.Auth )
	if err != nil { return }

	parsed , err := url.Parse( subscription.Endpoint )
	if err != nil { return }
	audience := parsed.Scheme + "://" + parsed.Host
	authorization , err := encryption.VAPIDAuthorization( sender.PublicKey , sender.PrivateKey , audience , sender.Subject , time.Now().Add( tokenLifetime ) )
	if err != nil { return }

	request , err := http.NewRequest( http.MethodPost , subscription.Endpoint , bytes.NewReader( body ) )
	if err != nil { return }
	request.Header.Set( "Authorization" , authorization )
	request.Header.Set( "Content-Encoding" , "aes128gcm" )
	request.Header.Set( "Content-Type" , "application/octet-stream" )
	request.Header.Set( "TTL" , strconv.Itoa( int( ttl.Seconds() ) ) )
	request.Header.Set( "Urgency" , urgency )

	response , err := sender.Client.Do( request )
	if err != nil { return }
	defer response.Body.Close()

	result.Status = response.StatusCode
	if response.StatusCode >= 300 {
		reason , _ := io.ReadAll( io.LimitReader( response.Body , reasonLimit ) )
		result.Reason = strings.TrimSpace( string( reason ) )
	}
	result.Gone = subscriptionGone( response.StatusCode , result.Reason )
	return
}

// subscriptionGone is true when a subscription can never work again: the
// standard 404 and 410, and Apple's 400 for a token it does not recognise.
func subscriptionGone( status int , reason string ) ( result bool ) {
	result = status == http.StatusNotFound || status == http.StatusGone ||
		( status == http.StatusBadRequest && strings.Contains( reason , "BadWebPushToken" ) )
	return
}
