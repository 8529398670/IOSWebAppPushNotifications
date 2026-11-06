package routes

import (
	errors "errors"
	url "net/url"
	strings "strings"
	time "time"
	utf8 "unicode/utf8"

	fiber "github.com/gofiber/fiber/v3"

	models "ipb/server/models"
)

// The limits Pushover documents, kept so a script written for it fits.
const (
	sendTitleMax    = 250
	sendMessageMax  = 1024
	sendURLMax      = 512
	sendURLTitleMax = 100

	repeatEveryDefault = 60 * time.Second
	repeatEveryMin     = 30 * time.Second
	repeatForDefault   = time.Hour
	repeatForMax       = 3 * time.Hour
)

// sendRequest takes Pushover's field names, as JSON or a form. Fields it does
// not know are ignored, so a script written for Pushover works as it stands.
type sendRequest struct {
	Token    string `json:"token" form:"token"`
	User     string `json:"user" form:"user"`
	Title    string `json:"title" form:"title"`
	Message  string `json:"message" form:"message"`
	URL      string `json:"url" form:"url"`
	URLTitle string `json:"url_title" form:"url_title"`
	Priority int    `json:"priority" form:"priority"`
	TTL      int    `json:"ttl" form:"ttl"`
	Retry    int    `json:"retry" form:"retry"`
	Expire   int    `json:"expire" form:"expire"`
}

// sendRefused answers in the shape Pushover's clients read.
func sendRefused( c fiber.Ctx , message string ) ( err error ) {
	err = c.Status( fiber.StatusBadRequest ).JSON( fiber.Map{ "status": 0 , "errors": []string{ message } } )
	return
}

func bearerToken( c fiber.Ctx ) ( token string ) {
	header := c.Get( fiber.HeaderAuthorization )
	if len( header ) > 7 && strings.EqualFold( header[ :7 ] , "Bearer " ) {
		token = strings.TrimSpace( header[ 7: ] )
	}
	return
}

func validLink( raw string ) ( ok bool ) {
	parsed , err := url.Parse( raw )
	ok = err == nil && ( parsed.Scheme == "http" || parsed.Scheme == "https" ) && parsed.Host != ""
	return
}

// outgoing checks a request's content; refusal is what to tell the caller.
func ( body *sendRequest ) outgoing() ( message models.OutgoingMessage , refusal string ) {
	text := strings.TrimSpace( body.Message )
	title := strings.TrimSpace( body.Title )
	switch {
	case text == "":
		refusal = "message cannot be blank"
	case utf8.RuneCountInString( text ) > sendMessageMax:
		refusal = "message is too long"
	case utf8.RuneCountInString( title ) > sendTitleMax:
		refusal = "title is too long"
	case utf8.RuneCountInString( body.URL ) > sendURLMax || ( body.URL != "" && validLink( body.URL ) == false ):
		refusal = "url must be a full http or https address"
	case utf8.RuneCountInString( body.URLTitle ) > sendURLTitleMax:
		refusal = "url_title is too long"
	case body.Priority < models.PriorityInboxOnly || body.Priority > models.PriorityRepeat:
		refusal = "priority must be from -2 to 2"
	case body.TTL < 0 || time.Duration( body.TTL ) * time.Second > models.MaxPushTTL:
		refusal = "ttl must be up to 28 days in seconds"
	}
	if refusal != "" { return }

	message = models.OutgoingMessage{
		Title:       title,
		Body:        text,
		URL:         body.URL,
		URLTitle:    body.URLTitle,
		Priority:    body.Priority,
		TTL:         models.DefaultPushTTL,
		RepeatEvery: repeatEveryDefault,
		RepeatFor:   repeatForDefault,
	}
	if body.TTL > 0 { message.TTL = time.Duration( body.TTL ) * time.Second }
	if body.Retry > 0 {
		message.RepeatEvery = max( time.Duration( body.Retry ) * time.Second , repeatEveryMin )
	}
	if body.Expire > 0 {
		message.RepeatFor = min( time.Duration( body.Expire ) * time.Second , repeatForMax )
	}
	return
}

// SendMessage is the notification API. Holding an app token and a user or group
// key is the whole permission, so it takes no session and no CSRF token: nothing
// about the request is ambient, and a forged one has neither to send.
func ( handlers *Handlers ) SendMessage( c fiber.Ctx ) ( err error ) {
	var body sendRequest
	if c.Bind().Body( &body ) != nil {
		err = sendRefused( c , "malformed request body" )
		return
	}
	token := strings.TrimSpace( body.Token )
	if token == "" { token = bearerToken( c ) }

	app , auth_err := models.AuthenticateAppToken( handlers.Store , token )
	if auth_err != nil {
		err = sendRefused( c , models.ErrAppToken.Error() )
		return
	}
	user_ids , recipient_err := models.ResolveRecipient( handlers.Store , strings.TrimSpace( body.User ) )
	if errors.Is( recipient_err , models.ErrRecipient ) {
		err = sendRefused( c , recipient_err.Error() )
		return
	}
	if recipient_err != nil {
		err = serverError( c , recipient_err )
		return
	}
	message , refusal := body.outgoing()
	if refusal != "" {
		err = sendRefused( c , refusal )
		return
	}

	request_id , reached , enqueue_err := models.EnqueueMessage( handlers.Store , app , user_ids , message )
	if enqueue_err != nil {
		err = serverError( c , enqueue_err )
		return
	}
	if handlers.Push != nil { handlers.Push.Nudge() }
	handlers.InboxStreams.Tell( reached )
	err = c.JSON( fiber.Map{ "status": 1 , "request": request_id } )
	return
}
