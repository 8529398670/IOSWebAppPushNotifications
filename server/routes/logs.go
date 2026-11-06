package routes

import (
	bufio "bufio"
	json "encoding/json"
	errors "errors"
	strconv "strconv"
	sync "sync"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	logs "ipb/server/logs"
	middleware "ipb/server/middleware"
	models "ipb/server/models"
	security "ipb/server/security"
	stream "ipb/server/stream"
)

// The activity log's endpoints (see server/logs). Reading it is the owner's
// alone, under /api/owner/logs (Guard.RequireOwner); writing to it from the
// page -- what track.js sends -- is any signed-in user's, at
// /api/logs/events, since what they do is what gets logged.

const (
	// Page events a browser may send per call, and per session per minute.
	logEventsPerCall   = 50
	logEventsPerMinute = 600
	logDetailMaxBytes  = 2048
)

// The page actions track.js sends. Anything else is refused, so the log
// cannot be filled with made-up kinds.
var logUIActions = map[string]bool{
	"session_start": true , "nav": true , "click": true , "submit": true ,
	"undo": true , "redo": true , "error": true , "fetch_fail": true ,
}

func ( handlers *Handlers ) logSettings() ( settings fiber.Map ) {
	current := handlers.Logs.Settings()
	settings = fiber.Map{
		"enabled":             current.Enabled,
		"retention_days":      current.RetentionDays,
		"max_total_mb":        current.MaxTotalBytes / 1024 / 1024,
		"max_file_mb":         current.MaxFileBytes / 1024 / 1024,
		"compress_after_days": current.CompressAfterDays,
		"static_assets":       current.StaticAssets,
		"ui_clicks":           current.UIClicks,
		"encrypted":           handlers.Logs.Encrypted(),
	}
	return
}

func ( handlers *Handlers ) ListLogDays( c fiber.Ctx ) ( err error ) {
	days , total , list_err := handlers.Logs.Days( logs.ParseQuery( c.Query( "q" ) ) )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	err = c.JSON( fiber.Map{
		"days":        days,
		"total_bytes": total,
		"dropped":     handlers.Logs.Dropped(),
		"settings":    handlers.logSettings(),
	} )
	return
}

func ( handlers *Handlers ) GetLogDay( c fiber.Ctx ) ( err error ) {
	day := c.Params( "date" )
	if logs.ValidDay( day ) == false {
		err = badRequest( c , "bad_day" )
		return
	}
	before := -1
	if raw := c.Query( "before" ); raw != "" {
		parsed , parse_err := strconv.Atoi( raw )
		if parse_err != nil || parsed < 0 {
			err = badRequest( c , "before must be a line number" )
			return
		}
		before = parsed
	}
	limit := pageDefault
	if raw := c.Query( "limit" ); raw != "" {
		parsed , parse_err := strconv.Atoi( raw )
		if parse_err != nil || parsed < 1 || parsed > pageMax {
			err = badRequest( c , pageLimitMessage )
			return
		}
		limit = parsed
	}
	records , next , read_err := handlers.Logs.ReadDay( day , logs.ParseQuery( c.Query( "q" ) ) , before , limit )
	if read_err != nil {
		err = serverError( c , read_err )
		return
	}
	err = c.JSON( fiber.Map{ "date": day , "entries": records , "next": next } )
	return
}

// DownloadLogDay streams a day as plain JSON lines, decrypted: the file a
// person can grep, or hand to whatever reads logs.
func ( handlers *Handlers ) DownloadLogDay( c fiber.Ctx ) ( err error ) {
	day := c.Params( "date" )
	if logs.ValidDay( day ) == false {
		err = badRequest( c , "bad_day" )
		return
	}
	c.Set( fiber.HeaderContentType , "application/x-ndjson" )
	c.Set( fiber.HeaderContentDisposition , `attachment; filename="logs-`+day+`.jsonl"` )
	c.Response().SetBodyStreamWriter( func( writer *bufio.Writer ) {
		handlers.Logs.Download( day , writer )
		writer.Flush()
	} )
	return
}

// StreamLogs tells the Logs screen when there is something new, so Live needs
// no timer. It sends a nudge, not the entries: the page reads them the way it
// always does, which is what keeps its search, paging and decryption in one
// place. Watching cannot feed itself, since nothing under /api/owner/logs is
// logged.
func ( handlers *Handlers ) StreamLogs( c fiber.Ctx ) ( err error ) {
	credential , cookie_err := handlers.Guard.DecryptCookie( c.Cookies( handlers.cfg().CookieName ) )
	if cookie_err != nil {
		err = notFound( c , "not found" )
		return
	}
	err = stream.Serve( c , handlers.LogStream , func() bool {
		return handlers.Guard.StillOwner( credential )
	} )
	return
}

func ( handlers *Handlers ) DeleteLogDay( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	day := c.Params( "date" )
	delete_err := handlers.Logs.DeleteDay( day )
	switch {
	case errors.Is( delete_err , logs.ErrBadDay ):
		err = badRequest( c , "bad_day" )
	case errors.Is( delete_err , logs.ErrToday ):
		err = conflict( c , logs.ErrToday.Error() , nil )
	case delete_err != nil:
		err = serverError( c , delete_err )
	default:
		handlers.audit( c , logs.KindAdmin , "log day deleted" , fiber.Map{ "date": day } )
		err = c.JSON( fiber.Map{ "deleted": true } )
	}
	return
}

func ( handlers *Handlers ) PruneLogs( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	result , prune_err := handlers.Logs.Prune()
	if prune_err != nil {
		err = serverError( c , prune_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "logs pruned" , fiber.Map{ "compressed": result.Compressed , "deleted": result.Deleted } )
	err = c.JSON( result )
	return
}

// uiEvent is one thing track.js saw. Everything in it came from a browser,
// so every field is capped before it is written.
type uiEvent struct {
	Action string         `json:"action"`
	Screen string         `json:"screen"`
	Target string         `json:"target"`
	Fields []string       `json:"fields"`
	Detail map[string]any `json:"detail"`
	At     string         `json:"at"`
	Client map[string]any `json:"client"`
}

type uiEventsRequest struct {
	Tab       string    `json:"tab"`
	Events    []uiEvent `json:"events"`
	CSRFToken string    `json:"csrf_token"`
}

// RecordUIEvents takes a batch from track.js. The server stamps each with
// its own time, the signed-in account, the address and the user agent, so a
// browser can describe what it did but not who did it or when it arrived.
func ( handlers *Handlers ) RecordUIEvents( c fiber.Ctx ) ( err error ) {
	var body uiEventsRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if len( body.Events ) > logEventsPerCall {
		body.Events = body.Events[ :logEventsPerCall ]
	}
	actor := security.ActorFrom( c )
	allowed := handlers.uiEventBudget.take( actor.User.ID , len( body.Events ) )
	tab := logs.Truncate( body.Tab , 32 )
	accepted := 0
	for index , event := range body.Events {
		if index >= allowed || logUIActions[ event.Action ] == false { continue }
		entry := logs.Entry{
			Kind:  logs.KindUI,
			Level: logs.LevelInfo,
			Actor: security.LogActor( actor ),
			IP:    c.IP(),
			UA:    logs.Truncate( c.Get( fiber.HeaderUserAgent ) , 300 ),
			UI: &logs.UI{
				Action: event.Action,
				Screen: logs.Truncate( event.Screen , 120 ),
				Target: logs.Truncate( event.Target , 120 ),
				Fields: capFields( event.Fields ),
				Detail: capMap( event.Detail ),
				At:     logs.Truncate( event.At , 40 ),
			},
			Client: map[string]any{ "tab": tab },
		}
		if event.Action == "error" || event.Action == "fetch_fail" {
			entry.Level = logs.LevelError
		}
		if event.Action == "session_start" {
			for name , value := range capMap( event.Client ) {
				entry.Client[ name ] = value
			}
		}
		handlers.Logs.Log( entry )
		accepted += 1
	}
	err = c.JSON( fiber.Map{ "accepted": accepted } )
	return
}

func capFields( fields []string ) ( result []string ) {
	for _ , field := range fields {
		if len( result ) == 30 { break }
		result = append( result , logs.Truncate( field , 60 ) )
	}
	return
}

// capMap keeps a browser-sent object only if it is small, with its strings
// capped. Too big, and it is dropped whole rather than cut mid-structure.
func capMap( value map[string]any ) ( result map[string]any ) {
	if len( value ) == 0 { return }
	for name , item := range value {
		if text , ok := item.( string ); ok {
			value[ name ] = logs.Truncate( text , 200 )
		}
	}
	encoded , err := json.Marshal( value )
	if err != nil || len( encoded ) > logDetailMaxBytes { return }
	result = value
	return
}

// eventBudget is the per-account cap on page events: a minute's worth, in a
// sliding window, so a stuck loop in a browser cannot fill the disk.
type eventBudget struct {
	lock sync.Mutex
	seen map[uint64][]time.Time
}

func ( budget *eventBudget ) take( user_id uint64 , wanted int ) ( allowed int ) {
	budget.lock.Lock()
	defer budget.lock.Unlock()
	if budget.seen == nil {
		budget.seen = map[uint64][]time.Time{}
	}
	now := time.Now()
	recent := budget.seen[ user_id ][ :0 ]
	for _ , at := range budget.seen[ user_id ] {
		if now.Sub( at ) < time.Minute {
			recent = append( recent , at )
		}
	}
	allowed = logEventsPerMinute - len( recent )
	if allowed > wanted { allowed = wanted }
	if allowed < 0 { allowed = 0 }
	for index := 0; index < allowed; index += 1 {
		recent = append( recent , now )
	}
	if len( recent ) == 0 {
		delete( budget.seen , user_id )
	} else {
		budget.seen[ user_id ] = recent
	}
	return
}

// logUser is the Actor for an account named by id, for an entry made before
// the request has an actor of its own (a sign-in).
func ( handlers *Handlers ) logUser( user_id uint64 , method string ) ( actor *logs.Actor ) {
	actor = &logs.Actor{ UserID: user_id , Method: method }
	if user , err := models.GetUser( handlers.Store , user_id ); err == nil {
		actor.Name = user.DisplayName
		actor.Role = user.Role
	}
	return
}

// audit logs an auth or admin action by whoever made this request. detail
// says what it touched: ids and names, never a credential.
func ( handlers *Handlers ) audit( c fiber.Ctx , kind string , message string , detail fiber.Map ) {
	handlers.auditAs( c , security.LogActor( security.ActorFrom( c ) ) , kind , logs.LevelInfo , message , detail )
}

// auditAs is audit for a request whose actor is not the signed-in one: a
// sign-in (nobody yet), or a failed one.
func ( handlers *Handlers ) auditAs( c fiber.Ctx , actor *logs.Actor , kind string , level string , message string , detail fiber.Map ) {
	if handlers.Logs.Enabled() == false { return }
	handlers.Logs.Log( logs.Entry{
		Kind:   kind,
		Level:  level,
		RequestID: middleware.RequestIDFrom( c ),
		Actor:  actor,
		IP:     c.IP(),
		UA:     logs.Truncate( c.Get( fiber.HeaderUserAgent ) , 300 ),
		Msg:    message,
		Detail: detail,
	} )
}
