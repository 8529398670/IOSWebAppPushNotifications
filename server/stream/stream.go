// Package stream is the helper for pushing live updates to a browser with
// server-sent events: an EventSource on the page, a Hub here, and Publish
// wherever something happens. See references/architecture.md for adding one.
//
// A stream outlives everything a normal request can rely on, so four things
// are handled here once rather than by each route:
//
//   - The server's WriteTimeout is a single deadline for a whole response, so
//     it would cut every stream off. Each write sets its own deadline instead,
//     which keeps the protection against a client that has stopped reading.
//   - Middleware runs once, at connect. A session revoked ten minutes later
//     would keep streaming, so the route's check runs again on every heartbeat.
//   - The writer runs on its own goroutine, where a panic would end the
//     process rather than one request.
//   - Connections do not drain by themselves, so a shutdown has to end them:
//     Hub.Close, from main.go.
package stream

import (
	bufio "bufio"
	errors "errors"
	log "log"
	net "net"
	strings "strings"
	sync "sync"
	time "time"

	fiber "github.com/gofiber/fiber/v3"
)

// Variables so a test can run them faster.
var (
	// heartbeat keeps proxies from closing a quiet stream, finds clients that
	// have gone, and paces the access check. It has to stay well under the
	// server's WriteTimeout: that deadline is still in force until the first
	// heartbeat replaces it.
	heartbeat = 15 * time.Second
	// writeWait is how long one write may take before the client counts as gone.
	writeWait = 30 * time.Second
)

// queueSize is how many events can wait for one slow client. Past that its
// events are dropped: one client must never hold up the rest, and the events
// here say "look again", not what changed, so losing some loses nothing.
const queueSize = 16

// retryFrame tells the browser how long to wait before reconnecting.
const retryFrame = "retry: 5000\n\n"

const pingFrame = ": ping\n\n"

// ErrFull is a hub at its limit of clients.
var ErrFull = errors.New( "too many live streams" )

// Format is one event as it goes on the wire. Each line of data gets its own
// prefix, and a line break in the name is dropped, so a value cannot start a
// field of its own.
func Format( event string , data string ) ( frame string ) {
	var built strings.Builder
	if event != "" {
		built.WriteString( "event: " + strings.NewReplacer( "\r" , "" , "\n" , "" ).Replace( event ) + "\n" )
	}
	for _ , line := range strings.Split( strings.ReplaceAll( data , "\r" , "" ) , "\n" ) {
		built.WriteString( "data: " + line + "\n" )
	}
	built.WriteString( "\n" )
	frame = built.String()
	return
}

type client struct {
	queue chan string
	gone  chan struct{}
}

// Hub is one topic: everyone connected to it gets everything published to it.
// It lives in this process, so it reaches nobody connected to another one.
type Hub struct {
	limit   int
	lock    sync.Mutex
	clients map[ *client ]struct{}
	closed  bool
}

// NewHub makes a hub for at most limit clients. A stream holds a connection
// and a goroutine for as long as a page is open, so this is what stops a pile
// of tabs from holding them all.
func NewHub( limit int ) ( hub *Hub ) {
	hub = &Hub{ limit: limit , clients: map[ *client ]struct{}{} }
	return
}

func ( hub *Hub ) subscribe() ( joined *client , err error ) {
	hub.lock.Lock()
	defer hub.lock.Unlock()
	if hub.closed || len( hub.clients ) >= hub.limit {
		err = ErrFull
		return
	}
	joined = &client{ queue: make( chan string , queueSize ) , gone: make( chan struct{} ) }
	hub.clients[ joined ] = struct{}{}
	return
}

func ( hub *Hub ) unsubscribe( leaving *client ) {
	hub.lock.Lock()
	defer hub.lock.Unlock()
	delete( hub.clients , leaving )
}

// Publish sends an event to everyone connected. It never blocks.
func ( hub *Hub ) Publish( event string , data string ) {
	frame := Format( event , data )
	hub.lock.Lock()
	defer hub.lock.Unlock()
	for connected := range hub.clients {
		select {
		case connected.queue <- frame:
		default:
		}
	}
}

// Clients is how many are connected.
func ( hub *Hub ) Clients() ( count int ) {
	hub.lock.Lock()
	defer hub.lock.Unlock()
	count = len( hub.clients )
	return
}

// Close ends every stream and refuses new ones.
func ( hub *Hub ) Close() {
	hub.lock.Lock()
	defer hub.lock.Unlock()
	if hub.closed { return }
	hub.closed = true
	for connected := range hub.clients {
		close( connected.gone )
	}
}

// Serve turns this request into a stream of hub's events. still is asked on
// every heartbeat whether the stream may go on; it runs after the request has
// ended, so it must not touch c, and anything it needs from the request has to
// be copied first.
//
// Everything used by the writer is taken here, before it starts: it runs on
// its own goroutine, and c is reused as soon as the handler returns.
func Serve( c fiber.Ctx , hub *Hub , still func() bool ) ( err error ) {
	c.Set( fiber.HeaderContentType , "text/event-stream" )
	c.Set( fiber.HeaderCacheControl , "no-store" )
	// Without this nginx holds events back to fill a buffer.
	c.Set( "X-Accel-Buffering" , "no" )
	if c.Method() == fiber.MethodHead { return }

	joined , subscribe_err := hub.subscribe()
	if subscribe_err != nil {
		c.Set( fiber.HeaderCacheControl , "" )
		c.Set( fiber.HeaderContentType , fiber.MIMEApplicationJSON )
		err = c.Status( fiber.StatusServiceUnavailable ).JSON( fiber.Map{ "error": ErrFull.Error() } )
		return
	}
	connection := c.RequestCtx().Conn()
	// The connection ends with the stream rather than going back to keep-alive.
	c.RequestCtx().SetConnectionClose()
	c.Response().SetBodyStreamWriter( func( writer *bufio.Writer ) {
		defer hub.unsubscribe( joined )
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf( "[stream] writer panicked: %v" , recovered )
			}
		}()
		pump( writer , connection , joined , still )
	} )
	return
}

// pump writes until the client goes, the hub closes, or still says no. The
// first event makes the page look once, covering whatever happened between its
// last read and this connection; it also gets the headers out, which fasthttp
// holds back until there is something to send.
func pump( writer *bufio.Writer , connection net.Conn , joined *client , still func() bool ) {
	if send( writer , connection , retryFrame + Format( "changed" , "1" ) ) == false { return }
	ticker := time.NewTicker( heartbeat )
	defer ticker.Stop()
	for {
		select {
		case <-joined.gone:
			return
		case frame := <-joined.queue:
			if send( writer , connection , frame ) == false { return }
		case <-ticker.C:
			if still != nil && still() == false { return }
			if send( writer , connection , pingFrame ) == false { return }
		}
	}
}

func send( writer *bufio.Writer , connection net.Conn , frame string ) ( ok bool ) {
	connection.SetWriteDeadline( time.Now().Add( writeWait ) )
	if _ , err := writer.WriteString( frame ); err != nil { return }
	ok = writer.Flush() == nil
	return
}
