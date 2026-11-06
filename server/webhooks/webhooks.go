// Package webhooks tells other systems that something happened.
//
// Emit writes one delivery per interested endpoint to the outbox bucket and
// returns; the webhooks job sends them. So a slow or dead receiver never holds
// up a request, and a restart loses nothing. Delivery is at least once: a crash
// between the send and writing down that it worked sends it again, so a
// receiver dedupes on the delivery id.
//
// This is the only code in the template that calls an address someone typed,
// which makes it the one place a server-side request forgery could start. The
// address is checked when it is saved and when it is used, and the check that
// counts is on the address actually dialled, after DNS: a name that resolves
// to something public today and 169.254.169.254 tomorrow gets nowhere.
package webhooks

import (
	context "context"
	errors "errors"
	fmt "fmt"
	io "io"
	log "log"
	net "net"
	http "net/http"
	netip "net/netip"
	url "net/url"
	strconv "strconv"
	strings "strings"
	syscall "syscall"
	time "time"

	config "ipb/server/config"
	db "ipb/server/db"
	encryption "ipb/server/encryption"
	models "ipb/server/models"
)

const (
	// JobName is what the send loop is registered as.
	JobName = "webhooks"
	// JobInterval is how often it looks for retries. A new event does not wait
	// for this: Emit asks for a run straight away.
	JobInterval = time.Minute

	// sendsPerRun caps one run, so a backlog against a dead receiver cannot
	// hold the job for hours. What is left goes in the next run.
	sendsPerRun = 50
	// responseReadLimit is how much of a reply is read before hanging up. The
	// reply is not used; reading a little lets the connection finish cleanly.
	responseReadLimit = 64 * 1024
)

var (
	ErrBadURL        = errors.New( "the url must be a full https address with no username or password" )
	ErrPrivateTarget = errors.New( "that address is private, and webhooks.allow_private_targets is off" )
)

// blockedPrefixes is everywhere a webhook may not go: this machine, private
// networks, link-local (cloud metadata lives there) and the rest of the ranges
// that are not the public internet. The Python template has the same list, and
// webhook_cases.json holds both to it.
var blockedPrefixes = parsePrefixes(
	"0.0.0.0/8" , "10.0.0.0/8" , "100.64.0.0/10" , "127.0.0.0/8" , "169.254.0.0/16" ,
	"172.16.0.0/12" , "192.0.0.0/24" , "192.0.2.0/24" , "192.168.0.0/16" , "198.18.0.0/15" ,
	"198.51.100.0/24" , "203.0.113.0/24" , "224.0.0.0/4" , "240.0.0.0/4" ,
	"::/128" , "::1/128" , "64:ff9b::/96" , "100::/64" , "2001:db8::/32" , "2002::/16" ,
	"fc00::/7" , "fe80::/10" , "ff00::/8" ,
)

func parsePrefixes( values ...string ) ( prefixes []netip.Prefix ) {
	for _ , value := range values {
		prefixes = append( prefixes , netip.MustParsePrefix( value ) )
	}
	return
}

// Blocked says whether an address is off limits. An IPv4 address written as
// IPv6 (::ffff:10.0.0.1) is judged as the IPv4 address it is.
func Blocked( address netip.Addr ) ( result bool ) {
	address = address.Unmap().WithZone( "" )
	for _ , prefix := range blockedPrefixes {
		if prefix.Contains( address ) {
			result = true
			return
		}
	}
	return
}

// CheckURL says whether an address can be used. It runs on save, for a clear
// answer, and again before each send, since allow_private_targets can change.
// A hostname passes here: what it resolves to is the dialer's check.
func CheckURL( raw string , allow_private bool ) ( err error ) {
	parsed , parse_err := url.Parse( raw )
	if parse_err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil {
		err = ErrBadURL
		return
	}
	if parsed.Scheme != "https" && ( allow_private == false || parsed.Scheme != "http" ) {
		err = ErrBadURL
		return
	}
	if allow_private { return }
	hostname := parsed.Hostname()
	if strings.EqualFold( hostname , "localhost" ) || strings.HasSuffix( strings.ToLower( hostname ) , ".localhost" ) {
		err = ErrPrivateTarget
		return
	}
	if address , addr_err := netip.ParseAddr( hostname ); addr_err == nil && Blocked( address ) {
		err = ErrPrivateTarget
	}
	return
}

// Sign is the signature a receiver checks: HMAC-SHA256 of "<timestamp>.<body>"
// with the endpoint's secret. The timestamp is in the signed text so a captured
// request cannot be replayed later as new.
func Sign( secret string , timestamp int64 , body string ) ( header string ) {
	stamp := strconv.FormatInt( timestamp , 10 )
	header = "t=" + stamp + ",v1=" + encryption.HMACSHA256Hex( secret , stamp + "." + body )
	return
}

// Dispatcher is the outbox's two ends. A nil *Dispatcher drops events, so code
// that emits needs no check and a test app needs no sender.
type Dispatcher struct {
	store    *db.Store
	settings *config.Holder
	// Nudge asks for a run now rather than at the next interval. main.go sets
	// it; the job may already be running, in which case the next run gets it.
	Nudge func()
}

func New( store *db.Store , settings *config.Holder ) ( dispatcher *Dispatcher ) {
	dispatcher = &Dispatcher{ store: store , settings: settings }
	return
}

// Emit queues an event for every endpoint that wants it. data is ids and names
// only: it leaves the server. A failure here is reported and goes no further,
// since whatever just happened did happen, and the caller's work is done.
func ( dispatcher *Dispatcher ) Emit( event string , data map[string]any ) {
	if dispatcher == nil { return }
	if dispatcher.settings.Get().Webhooks.Enabled == false { return }
	queued , err := models.EnqueueWebhookEvent( dispatcher.store , event , data )
	if err != nil {
		log.Printf( "[webhooks] could not queue %s: %v" , event , err )
		return
	}
	if queued > 0 {
		dispatcher.nudge()
	}
}

// SendTest queues a test event for one endpoint.
func ( dispatcher *Dispatcher ) SendTest( hook *models.Webhook ) ( err error ) {
	if err = models.EnqueueWebhookTest( dispatcher.store , hook ); err != nil { return }
	dispatcher.nudge()
	return
}

// Resend queues a failed delivery again. See models.ResendWebhookDelivery.
func ( dispatcher *Dispatcher ) Resend( webhook_id string , delivery_id string ) ( err error ) {
	if err = models.ResendWebhookDelivery( dispatcher.store , webhook_id , delivery_id ); err != nil { return }
	dispatcher.nudge()
	return
}

func ( dispatcher *Dispatcher ) nudge() {
	if dispatcher.Nudge != nil {
		dispatcher.Nudge()
	}
}

// client is built per run, so a change to the settings applies to the next one.
func client( settings config.WebhooksConfig ) ( result *http.Client ) {
	result = GuardedClient( settings.Timeout , settings.AllowPrivateTargets , false )
	return
}

// GuardedClient is an http client that refuses to dial anything internal,
// checked on the address actually dialled. Everything that sends to a URL
// someone else supplied goes through it: webhooks, and push endpoints.
func GuardedClient( timeout time.Duration , allow_private bool , keep_alive bool ) ( result *http.Client ) {
	dialer := &net.Dialer{ Timeout: timeout }
	if allow_private == false {
		// Control runs after DNS, with the address about to be dialled.
		dialer.Control = func( network string , address string , _ syscall.RawConn ) ( err error ) {
			host , _ , split_err := net.SplitHostPort( address )
			if split_err != nil {
				err = split_err
				return
			}
			parsed , parse_err := netip.ParseAddr( host )
			if parse_err != nil {
				err = parse_err
				return
			}
			if Blocked( parsed ) {
				err = ErrPrivateTarget
			}
			return
		}
	}
	result = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Proxy stays nil: HTTP_PROXY would otherwise send this around the
			// check above.
			DialContext:       dialer.DialContext,
			DisableKeepAlives: keep_alive == false,
			ForceAttemptHTTP2: keep_alive,
		},
		// A redirect is a second address nobody checked, so it counts as the
		// failure it is rather than being followed.
		CheckRedirect: func( *http.Request , []*http.Request ) error { return http.ErrUseLastResponse },
	}
	return
}

// send makes one attempt. failure is what to show the owner: an error from the
// http package quotes the whole URL, which may hold a token, so only the cause
// is kept.
func send( http_client *http.Client , hook *models.Webhook , secret string , delivery *models.WebhookDelivery ) ( status int , failure string ) {
	request , err := http.NewRequestWithContext( context.Background() , http.MethodPost , hook.URL , strings.NewReader( delivery.Body ) )
	if err != nil {
		failure = "the url could not be used"
		return
	}
	request.Header.Set( "Content-Type" , "application/json" )
	request.Header.Set( "User-Agent" , "webhooks" )
	request.Header.Set( "X-Webhook-Event" , delivery.Event )
	request.Header.Set( "X-Webhook-Delivery" , delivery.ID )
	request.Header.Set( "X-Webhook-Signature" , Sign( secret , time.Now().Unix() , delivery.Body ) )

	response , err := http_client.Do( request )
	if err != nil {
		var wrapped *url.Error
		if errors.As( err , &wrapped ) { err = wrapped.Err }
		failure = err.Error()
		return
	}
	defer response.Body.Close()
	io.CopyN( io.Discard , response.Body , responseReadLimit )
	status = response.StatusCode
	if status < 200 || status > 299 {
		failure = "status " + strconv.Itoa( status )
	}
	return
}

// Run is the job: send what is due and write down how each went. Only trouble
// with the database fails the run. A receiver being down is what the retries
// are for, and shows on the delivery.
func ( dispatcher *Dispatcher ) Run() ( note string , err error ) {
	cfg := dispatcher.settings.Get()
	if cfg.Webhooks.Enabled == false {
		note = "switched off"
		return
	}
	due , err := models.DueWebhookDeliveries( dispatcher.store , time.Now().UTC() , sendsPerRun )
	if err != nil { return }
	if len( due ) == 0 {
		note = "nothing to send"
		return
	}

	http_client := client( cfg.Webhooks )
	hooks := map[string]*models.Webhook{}
	sent , failed := 0 , 0
	for _ , delivery := range due {
		hook , known := hooks[ delivery.WebhookID ]
		if known == false {
			loaded , get_err := models.GetWebhook( dispatcher.store , delivery.WebhookID )
			if get_err != nil && errors.Is( get_err , db.ErrNotFound ) == false {
				err = get_err
				return
			}
			hook = loaded
			hooks[ delivery.WebhookID ] = hook
		}
		status , failure , retry := attempt( http_client , cfg , hook , delivery )
		if failure == "" { sent += 1 } else { failed += 1 }
		if err = models.RecordWebhookAttempt( dispatcher.store , delivery.ID , status , failure , retry ); err != nil { return }
	}
	note = fmt.Sprintf( "sent %d, failed %d" , sent , failed )
	return
}

// attempt decides whether a delivery can go at all, then sends it. retry is
// false for a failure that waiting will not fix.
func attempt( http_client *http.Client , cfg *config.Config , hook *models.Webhook , delivery *models.WebhookDelivery ) ( status int , failure string , retry bool ) {
	if hook == nil || hook.Deleted() || hook.Enabled == false {
		failure = "the endpoint is off"
		return
	}
	if check_err := CheckURL( hook.URL , cfg.Webhooks.AllowPrivateTargets ); check_err != nil {
		failure = check_err.Error()
		return
	}
	secret , open_err := models.OpenWebhookSecret( hook , cfg.SecretKey )
	if open_err != nil {
		failure = "the signing secret could not be read"
		return
	}
	retry = true
	status , failure = send( http_client , hook , secret , delivery )
	return
}
