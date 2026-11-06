package routes

import (
	errors "errors"
	strings "strings"
	sync "sync"

	fiber "github.com/gofiber/fiber/v3"

	models "ipb/server/models"
	security "ipb/server/security"
	stream "ipb/server/stream"
)

// inboxStreamLimit is how many pages one person can have listening at once.
const inboxStreamLimit = 8

// InboxStreams is one hub per person, because a stream.Hub tells everyone on it,
// and a new message is nobody else's business. Hubs carry only "changed": the
// page asks for what is new the usual way, through the same checks as any read.
type InboxStreams struct {
	lock   sync.Mutex
	hubs   map[uint64]*stream.Hub
	closed bool
}

func NewInboxStreams() ( streams *InboxStreams ) {
	streams = &InboxStreams{ hubs: map[uint64]*stream.Hub{} }
	return
}

func ( streams *InboxStreams ) hub( user_id uint64 ) ( hub *stream.Hub ) {
	streams.lock.Lock()
	defer streams.lock.Unlock()
	hub = streams.hubs[ user_id ]
	if hub == nil {
		hub = stream.NewHub( inboxStreamLimit )
		if streams.closed { hub.Close() }
		streams.hubs[ user_id ] = hub
	}
	return
}

// Tell lets each person's open pages know their inbox changed.
func ( streams *InboxStreams ) Tell( user_ids []uint64 ) {
	for _ , user_id := range user_ids {
		streams.hub( user_id ).Publish( "changed" , "1" )
	}
}

// Close ends every stream, for shutdown.
func ( streams *InboxStreams ) Close() {
	streams.lock.Lock()
	defer streams.lock.Unlock()
	streams.closed = true
	for _ , hub := range streams.hubs {
		hub.Close()
	}
}

func inboxRow( item *models.InboxItem ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":         item.ID,
		"app_id":     item.AppID,
		"app_name":   item.AppName,
		"title":      item.Title,
		"body":       item.Body,
		"url":        item.URL,
		"url_title":  item.URLTitle,
		"priority":   item.Priority,
		"created_at": item.CreatedAt,
		"read":       item.ReadAt != nil,
	}
	return
}

// ListInbox is the caller's messages, newest first; ?app= narrows to one app.
func ( handlers *Handlers ) ListInbox( c fiber.Ctx ) ( err error ) {
	user_id := security.UserFrom( c ).ID
	items , list_err := models.ListInbox( handlers.Store , user_id , strings.Clone( c.Query( "app" ) ) )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	rows := []fiber.Map{}
	for _ , item := range items {
		rows = append( rows , inboxRow( item ) )
	}
	err = sendPage( c , "items" , rows )
	return
}

// GetInboxUnread is the number for the Home Screen icon.
func ( handlers *Handlers ) GetInboxUnread( c fiber.Ctx ) ( err error ) {
	unread , count_err := models.UnreadCount( handlers.Store , security.UserFrom( c ).ID )
	if count_err != nil {
		err = serverError( c , count_err )
		return
	}
	err = c.JSON( fiber.Map{ "unread": unread } )
	return
}

// StreamInbox is what makes a sound play while iPB is open.
func ( handlers *Handlers ) StreamInbox( c fiber.Ctx ) ( err error ) {
	credential , cookie_err := handlers.Guard.DecryptCookie( c.Cookies( handlers.cfg().CookieName ) )
	if cookie_err != nil {
		err = notFound( c , "not found" )
		return
	}
	user_id := security.UserFrom( c ).ID
	err = stream.Serve( c , handlers.InboxStreams.hub( user_id ) , func() bool {
		return handlers.Guard.StillUser( credential , user_id )
	} )
	return
}

func ( handlers *Handlers ) inboxAnswer( c fiber.Ctx , change_err error ) ( err error ) {
	switch {
	case change_err == nil:
		handlers.InboxStreams.Tell( []uint64{ security.UserFrom( c ).ID } )
		err = c.JSON( fiber.Map{ "ok": true } )
	case errors.Is( change_err , models.ErrInboxGone ):
		err = notFound( c , "no such message" )
	default:
		err = serverError( c , change_err )
	}
	return
}

func ( handlers *Handlers ) ReadInboxItem( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	err = handlers.inboxAnswer( c , models.MarkInboxRead( handlers.Store , security.UserFrom( c ).ID , strings.Clone( c.Params( "item_id" ) ) ) )
	return
}

func ( handlers *Handlers ) ReadAllInbox( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	err = handlers.inboxAnswer( c , models.MarkAllInboxRead( handlers.Store , security.UserFrom( c ).ID ) )
	return
}

func ( handlers *Handlers ) DeleteInboxItem( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	err = handlers.inboxAnswer( c , models.DeleteInboxItem( handlers.Store , security.UserFrom( c ).ID , strings.Clone( c.Params( "item_id" ) ) ) )
	return
}

func ( handlers *Handlers ) RestoreInboxItem( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	restore_err := models.RestoreInboxItem( handlers.Store , security.UserFrom( c ).ID , strings.Clone( c.Params( "item_id" ) ) )
	if errors.Is( restore_err , models.ErrInboxGone ) == false && restore_err != nil {
		err = restoreRefused( c , restore_err )
		return
	}
	err = handlers.inboxAnswer( c , restore_err )
	return
}
