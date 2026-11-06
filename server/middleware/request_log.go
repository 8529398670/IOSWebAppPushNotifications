package middleware

import (
	fmt "fmt"
	log "log"
	url "net/url"
	path "path"
	strings "strings"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
	logs "ipb/server/logs"
	security "ipb/server/security"
)

// RequestLog writes one activity-log entry per request: who (once
// Guard.LoadUser has run further down the chain, which is why the entry is
// built after c.Next returns), from where, what was asked, how it ended and
// how long it took. A 5xx is logged as kind "error" with the handler's error
// text, which never reaches the client (see main.go's ErrorHandler) but is
// what the owner needs.
//
// It sits after RateLimit in main.go, so a flood of refused requests costs a
// 429 and nothing else. Skipped: the log's own endpoints (reading the log
// would fill it; page events arrive as kind "ui" entries of their own),
// /api/health, /api/ready and /metrics (something polling every few seconds is
// noise), and, unless logs.static_assets is on, the page's scripts, styles and images.
//
// The settings are read on every request, not once here: logs.static_assets
// and logs.echo can change while the server runs (see config.Holder).
func RequestLog( logger *logs.Logger ) ( handler fiber.Handler ) {
	handler = func( c fiber.Ctx ) ( err error ) {
		if logger.Enabled() == false {
			err = c.Next()
			return
		}
		settings := logger.Settings()
		if skipRequestLog( c , settings ) {
			err = c.Next()
			return
		}
		started := time.Now()
		// A panic goes on up to Recover, but is logged on its way through.
		defer func() {
			if recovered := recover(); recovered != nil {
				recordRequest( c , logger , settings , started , fiber.StatusInternalServerError , fmt.Sprint( "panic: " , recovered ) )
				panic( recovered )
			}
		}()
		err = c.Next()
		status := c.Response().StatusCode()
		message := ""
		if err != nil {
			// The ErrorHandler has not written the response yet: work out
			// the status it will, the same way.
			status = errorStatus( err )
			if status >= 500 {
				message = err.Error()
			}
		}
		recordRequest( c , logger , settings , started , status , message )
		return
	}
	return
}

func skipRequestLog( c fiber.Ctx , settings config.LogsConfig ) ( skip bool ) {
	request_path := c.Path()
	switch {
	case request_path == "/api/logs/events" , request_path == "/api/health" , request_path == "/api/ready" , request_path == "/metrics":
		skip = true
	case strings.HasPrefix( request_path , "/api/owner/logs" ):
		skip = true
	case settings.StaticAssets == false && staticAsset( c.Method() , request_path ):
		skip = true
	}
	return
}

// staticAsset is a file the page loads (/js/app.js, /vendor/...), as opposed
// to the page itself, an API call, or a login or invite link -- whose
// credential can contain a dot, which is why those are ruled out first.
func staticAsset( method string , request_path string ) ( result bool ) {
	if method != fiber.MethodGet && method != fiber.MethodHead { return }
	for _ , prefix := range []string{ "/api/" , "/login/" , "/join/" , "/mcp" } {
		if strings.HasPrefix( request_path , prefix ) { return }
	}
	result = path.Ext( request_path ) != ""
	return
}

func recordRequest( c fiber.Ctx , logger *logs.Logger , settings config.LogsConfig , started time.Time , status int , message string ) {
	elapsed := float64( time.Since( started ).Microseconds() ) / 1000
	bytes_out := c.Response().Header.ContentLength()
	if bytes_out < 0 {
		bytes_out = 0
	}
	entry := logs.Entry{
		Kind:  logs.KindRequest,
		Level: logs.LevelInfo,
		RequestID: RequestIDFrom( c ),
		Actor: security.LogActor( security.ActorFrom( c ) ),
		IP:    c.IP(),
		UA:    logs.Truncate( c.Get( fiber.HeaderUserAgent ) , 300 ),
		Request: &logs.Request{
			Method:   c.Method(),
			Path:     logs.Redact( c.Path() , string( c.Request().URI().QueryString() ) ),
			Status:   status,
			MS:       float64( int( elapsed * 100 ) ) / 100,
			BytesOut: bytes_out,
			Referer:  redactReferer( c.Get( fiber.HeaderReferer ) ),
		},
		Msg: logs.Truncate( message , 500 ),
	}
	switch {
	case status >= 500:
		entry.Kind = logs.KindError
		entry.Level = logs.LevelError
	case status >= 400:
		entry.Level = logs.LevelWarn
	}
	logger.Log( entry )
	if settings.Echo {
		name := "-"
		if entry.Actor.Name != "" {
			name = entry.Actor.Name
		}
		log.Printf( "[req] %s %s %d %.1fms %s %s" , entry.Request.Method , entry.Request.Path , status , entry.Request.MS , entry.IP , name )
	}
}

// redactReferer keeps where a visitor came from without keeping a login or
// invite link they came from.
func redactReferer( value string ) ( result string ) {
	if value == "" { return }
	parsed , err := url.Parse( value )
	if err != nil { return }
	result = logs.Truncate( parsed.Scheme + "://" + parsed.Host + logs.Redact( parsed.Path , parsed.RawQuery ) , 300 )
	return
}
