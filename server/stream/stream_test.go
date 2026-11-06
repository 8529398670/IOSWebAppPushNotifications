package stream

import (
	bufio "bufio"
	fmt "fmt"
	io "io"
	net "net"
	http "net/http"
	strings "strings"
	atomic "sync/atomic"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"
)

// These need a real listener: an endless response would hang app.Test, and a
// write deadline only means anything on a real connection.

type server struct {
	app  *fiber.App
	addr string
}

func serve( t *testing.T , config fiber.Config , hub *Hub , still func() bool ) ( running *server ) {
	t.Helper()
	app := fiber.New( config )
	app.Get( "/stream" , func( c fiber.Ctx ) ( err error ) {
		err = Serve( c , hub , still )
		return
	} )
	listener , err := net.Listen( "tcp" , "127.0.0.1:0" )
	if err != nil { t.Fatal( err ) }
	go app.Listener( listener , fiber.ListenConfig{ DisableStartupMessage: true } )
	t.Cleanup( func() {
		hub.Close()
		app.ShutdownWithTimeout( 2 * time.Second )
	} )
	running = &server{ app: app , addr: listener.Addr().String() }
	return
}

func ( running *server ) open( t *testing.T ) ( response *http.Response , reader *bufio.Reader ) {
	t.Helper()
	response , err := http.Get( "http://" + running.addr + "/stream" )
	if err != nil { t.Fatal( err ) }
	t.Cleanup( func() { response.Body.Close() } )
	reader = bufio.NewReader( response.Body )
	return
}

// readUntil reads lines until one contains want, or fails after wait.
func readUntil( t *testing.T , reader *bufio.Reader , want string , wait time.Duration ) {
	t.Helper()
	found := make( chan error , 1 )
	go func() {
		for {
			line , err := reader.ReadString( '\n' )
			if err != nil {
				found <- err
				return
			}
			if strings.Contains( line , want ) {
				found <- nil
				return
			}
		}
	}()
	select {
	case err := <-found:
		if err != nil { t.Fatalf( "looking for %q: %v" , want , err ) }
	case <-time.After( wait ):
		t.Fatalf( "no %q within %v" , want , wait )
	}
}

func readsToTheEnd( t *testing.T , reader *bufio.Reader , wait time.Duration ) {
	t.Helper()
	ended := make( chan struct{} )
	go func() {
		io.Copy( io.Discard , reader )
		close( ended )
	}()
	select {
	case <-ended:
	case <-time.After( wait ):
		t.Fatalf( "the stream was still open after %v" , wait )
	}
}

func faster( t *testing.T , beat time.Duration , wait time.Duration ) {
	t.Helper()
	old_beat , old_wait := heartbeat , writeWait
	heartbeat , writeWait = beat , wait
	t.Cleanup( func() { heartbeat , writeWait = old_beat , old_wait } )
}

func waitFor( t *testing.T , check func() bool ) {
	t.Helper()
	for deadline := time.Now().Add( 3 * time.Second ); time.Now().Before( deadline ); time.Sleep( 10 * time.Millisecond ) {
		if check() { return }
	}
	t.Fatal( "the condition never came true" )
}

func TestDataCannotForgeAField( t *testing.T ) {
	frame := Format( "changed\nevent: forged" , "one\ndata: two\r\nevent: forged" )
	for _ , line := range strings.Split( strings.TrimRight( frame , "\n" ) , "\n" ) {
		if strings.HasPrefix( line , "event: " ) && line != "event: changedevent: forged" {
			t.Fatalf( "a forged field: %q in %q" , line , frame )
		}
		if strings.HasPrefix( line , "event: " ) == false && strings.HasPrefix( line , "data: " ) == false {
			t.Fatalf( "a line with no prefix: %q" , line )
		}
	}
	if strings.HasSuffix( frame , "\n\n" ) == false {
		t.Fatalf( "not terminated: %q" , frame )
	}
}

func TestStreamHeadersAndFirstEvent( t *testing.T ) {
	hub := NewHub( 2 )
	running := serve( t , fiber.Config{} , hub , nil )
	response , reader := running.open( t )
	if response.Header.Get( "Content-Type" ) != "text/event-stream" || response.Header.Get( "Cache-Control" ) != "no-store" || response.Header.Get( "X-Accel-Buffering" ) != "no" {
		t.Fatalf( "headers %v" , response.Header )
	}
	readUntil( t , reader , "retry: 5000" , 2 * time.Second )
	readUntil( t , reader , "event: changed" , 2 * time.Second )
	hub.Publish( "changed" , "1" )
	readUntil( t , reader , "event: changed" , 2 * time.Second )
}

func TestHeadDoesNotStream( t *testing.T ) {
	hub := NewHub( 1 )
	running := serve( t , fiber.Config{} , hub , nil )
	response , err := http.Head( "http://" + running.addr + "/stream" )
	if err != nil { t.Fatal( err ) }
	response.Body.Close()
	if response.StatusCode != http.StatusOK || hub.Clients() != 0 {
		t.Fatalf( "%d with %d clients" , response.StatusCode , hub.Clients() )
	}
}

func TestOverTheCapIsRefused( t *testing.T ) {
	hub := NewHub( 1 )
	running := serve( t , fiber.Config{} , hub , nil )
	_ , reader := running.open( t )
	readUntil( t , reader , "retry" , 2 * time.Second )
	response , err := http.Get( "http://" + running.addr + "/stream" )
	if err != nil { t.Fatal( err ) }
	defer response.Body.Close()
	body , _ := io.ReadAll( response.Body )
	if response.StatusCode != http.StatusServiceUnavailable || string( body ) != `{"error":"too many live streams"}` {
		t.Fatalf( "%d %s" , response.StatusCode , body )
	}
}

func TestPublishNeverBlocksOnASlowClient( t *testing.T ) {
	hub := NewHub( 1 )
	joined , err := hub.subscribe()
	if err != nil { t.Fatal( err ) }
	finished := make( chan struct{} )
	go func() {
		for count := 0; count < queueSize * 4; count += 1 {
			hub.Publish( "changed" , fmt.Sprint( count ) )
		}
		close( finished )
	}()
	select {
	case <-finished:
	case <-time.After( 2 * time.Second ):
		t.Fatal( "Publish blocked" )
	}
	if len( joined.queue ) != queueSize {
		t.Fatalf( "queue holds %d" , len( joined.queue ) )
	}
}

func TestCloseEndsStreamsAndRefusesNewOnes( t *testing.T ) {
	hub := NewHub( 2 )
	running := serve( t , fiber.Config{} , hub , nil )
	_ , reader := running.open( t )
	readUntil( t , reader , "retry" , 2 * time.Second )
	hub.Close()
	readsToTheEnd( t , reader , 2 * time.Second )
	waitFor( t , func() bool { return hub.Clients() == 0 } )
	if _ , err := hub.subscribe(); err == nil {
		t.Fatal( "a closed hub took a client" )
	}
	hub.Publish( "changed" , "1" )
}

func TestStreamEndsWhenAccessIsGone( t *testing.T ) {
	faster( t , 50 * time.Millisecond , time.Second )
	var allowed atomic.Bool
	allowed.Store( true )
	hub := NewHub( 2 )
	running := serve( t , fiber.Config{} , hub , allowed.Load )
	_ , reader := running.open( t )
	readUntil( t , reader , ": ping" , 2 * time.Second )
	allowed.Store( false )
	readsToTheEnd( t , reader , 2 * time.Second )
	waitFor( t , func() bool { return hub.Clients() == 0 } )
}

func TestAPanicInTheWriterDoesNotKillTheServer( t *testing.T ) {
	faster( t , 50 * time.Millisecond , time.Second )
	hub := NewHub( 2 )
	running := serve( t , fiber.Config{} , hub , func() bool { panic( "boom" ) } )
	_ , reader := running.open( t )
	readsToTheEnd( t , reader , 2 * time.Second )
	waitFor( t , func() bool { return hub.Clients() == 0 } )
	_ , again := running.open( t )
	readUntil( t , again , "retry" , 2 * time.Second )
}

func TestDisconnectFreesTheSlot( t *testing.T ) {
	faster( t , 50 * time.Millisecond , time.Second )
	hub := NewHub( 1 )
	running := serve( t , fiber.Config{} , hub , nil )
	response , reader := running.open( t )
	readUntil( t , reader , "retry" , 2 * time.Second )
	response.Body.Close()
	waitFor( t , func() bool { return hub.Clients() == 0 } )
}

func TestStreamOutlivesTheWriteTimeout( t *testing.T ) {
	faster( t , 100 * time.Millisecond , 400 * time.Millisecond )
	hub := NewHub( 2 )
	running := serve( t , fiber.Config{ WriteTimeout: 300 * time.Millisecond } , hub , nil )
	_ , reader := running.open( t )
	readUntil( t , reader , "retry" , 2 * time.Second )
	time.Sleep( 1200 * time.Millisecond )
	hub.Publish( "changed" , "after-the-timeout" )
	readUntil( t , reader , "after-the-timeout" , 2 * time.Second )
}
