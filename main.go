// Command iPB is the web server entry point.
//
// This file only wires things together -- load config, open the database,
// build the app, register routes, start and stop cleanly. Every decision of
// substance lives in a package under server/. If you find yourself adding
// business logic here, it belongs in server/routes/ or a new package instead.
//
// The same binary is also the admin CLI:
//
//	ipb                     run the server
//	ipb manage list-users   account administration
//	ipb config check        create, check, or read config/config.yaml
//	ipb health              the container's healthcheck
//	ipb version             build information
package main

import (
	context "context"
	embed "embed"
	errors "errors"
	fmt "fmt"
	fs "io/fs"
	log "log"
	os "os"
	signal "os/signal"
	runtime "runtime"
	syscall "syscall"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	assets "ipb/server/assets"
	bootstrap "ipb/server/bootstrap"
	config "ipb/server/config"
	control "ipb/server/control"
	db "ipb/server/db"
	errorpage "ipb/server/errorpage"
	healthcheck "ipb/server/healthcheck"
	jobs "ipb/server/jobs"
	language "ipb/server/language"
	logs "ipb/server/logs"
	manage "ipb/server/manage"
	metrics "ipb/server/metrics"
	models "ipb/server/models"
	push "ipb/server/push"
	middleware "ipb/server/middleware"
	routes "ipb/server/routes"
	security "ipb/server/security"
	static "ipb/server/static"
	webhooks "ipb/server/webhooks"
	stream "ipb/server/stream"
)

// How long a shutdown waits, first for requests to finish and then for
// background jobs. Together they have to fit inside what scripts/lib.sh and
// `docker stop` allow before they kill the process (--stop-timeout in
// docker/run.sh).
const (
	drainWait   = 10 * time.Second
	jobStopWait = 5 * time.Second
	// A few browsers with the Logs screen open is all there should ever be.
	logStreamLimit = 8
)

// The frontend and every shipped YAML file, compiled into the binary.
//
// This is what makes scripts/build.sh able to produce one file that runs
// anywhere: no ./static directory to ship alongside it, no language.yaml to
// forget, and the defaults a missing config key falls back to always present.
// The directives have to live in a package at the module root, because
// go:embed cannot reference paths outside its own package directory -- which
// is why they are here rather than in server/assets or server/config.
//
// "all:" includes files whose names begin with "." or "_", which a normal
// embed pattern skips.
var (
	//go:embed all:static
	embeddedStaticRoot embed.FS

	//go:embed config/language.yaml
	embeddedLanguage []byte

	// Embedded only, unlike language.yaml: it describes the routes compiled
	// into this binary, so a copy on disk could only disagree with them.
	//go:embed config/openapi.json
	embeddedOpenAPI []byte

	//go:embed config/defaults.yaml
	embeddedDefaults []byte

	//go:embed config/example_header.yaml
	embeddedExampleHeader []byte
)

// The config package needs the defaults before anything else runs -- every
// subcommand, including `config init`, starts from them.
func init() {
	config.UseEmbedded( embeddedDefaults , embeddedExampleHeader )
}

// embeddedStatic re-roots the embedded tree at ./static, so a request for
// "css/style.css" does not have to know it lives at "static/css/style.css"
// inside the binary. This makes it interchangeable with the os.Root
// filesystem server/assets opens for ./static on disk.
func embeddedStatic() ( fsys fs.FS , err error ) {
	fsys , err = fs.Sub( embeddedStaticRoot , "static" )
	return
}

// Stamped by scripts/build.sh via -ldflags. The defaults are what you get from a
// plain `go build`, which is a useful signal in itself.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	// Subcommands before anything else: `manage` must work on a database the
	// server cannot currently open, which is exactly when you need it.
	if len( os.Args ) > 1 {
		switch os.Args[ 1 ] {
		case "manage":
			if err := manage.Run( os.Args[ 2: ] ); err != nil {
				fmt.Fprintf( os.Stderr , "error: %v\n" , err )
				os.Exit( 1 )
			}
			return
		case "config":
			if err := config.RunCommand( os.Args[ 2: ] ); err != nil {
				fmt.Fprintf( os.Stderr , "error: %v\n" , err )
				os.Exit( 1 )
			}
			return
		case "health":
			if err := healthcheck.Run(); err != nil {
				fmt.Fprintf( os.Stderr , "unhealthy: %v\n" , err )
				os.Exit( 1 )
			}
			return
		case "version" , "-version" , "--version":
			fmt.Printf( "iPB %s (commit %s, built %s, %s/%s, %s)\n" ,
				version , commit , buildDate , runtime.GOOS , runtime.GOARCH , runtime.Version() )
			return
		case "-h" , "--help" , "help":
			fmt.Printf( "iPB %s\n\nUsage:\n  ipb                 run the web server\n  ipb manage <cmd>    account administration\n  ipb config <cmd>    create, check, or read config.yaml\n  ipb health          exit 0 if the local server answers\n  ipb version         build information\n\n" , version )
			manage.Usage()
			fmt.Println( "" )
			config.CommandUsage()
			return
		}
	}

	if err := run(); err != nil {
		log.Fatalf( "[fatal] %v" , err )
	}
}

func run() ( err error ) {
	cfg , err := config.Load()
	if err != nil { return }
	if cfg.RotationPending {
		err = config.ErrRotationPending
		return
	}
	if cfg.RotationFinished {
		log.Printf( "[secret] finished a key rotation that had been cut short; the new key is in %s" , cfg.SecretFile )
	}

	embedded , err := embeddedStatic()
	if err != nil { return }

	// Disk when it exists, the embedded copy otherwise. See server/assets.
	bundle , err := assets.Resolve( cfg.StaticDir , cfg.LanguageFile , embedded , embeddedLanguage )
	if err != nil { return }

	store , err := db.Open( cfg )
	if err != nil { return }
	defer store.Close()

	lang , err := language.Parse( bundle.LanguageYAML )
	if err != nil { return }

	error_pages := errorpage.New( lang )

	static_server , err := static.New( bundle.Static )
	if err != nil { return }
	static_server.NotFound = error_pages.NotFound( static_server.NotFound )

	if err = bootstrap.EnsureFirstAdmin( store , cfg , "Admin" ); err != nil { return }

	// The running configuration. config.yaml can change while the server
	// runs -- from the owner's Settings screen, or by hand -- and everything
	// that reads a setting per request reads it from here. cfg stays what
	// the server started with: the listener, the database, the control
	// socket and every [restart] setting.
	settings := config.NewHolder( cfg )

	// The control socket is what lets `manage` run against a live server.
	// bolt hands the database to exactly one process, so without it every
	// admin command would need the server stopped first. It is started after
	// the database opens, which means the socket existing is itself proof
	// that a live process holds the lock.
	control_server , err := control.Listen( store , settings )
	if err != nil { return }
	defer control_server.Close()

	// The activity log writes from its own goroutine; Close, deferred here,
	// runs after the server has stopped, so the last requests make it to disk.
	logger := logs.New( cfg.Logs , cfg.SecretKey , cfg.EncryptAtRest )
	log_stream := stream.NewHub( logStreamLimit )
	logger.OnFlushed( func() { log_stream.Publish( "changed" , "1" ) } )
	logger.Start()
	defer logger.Close()
	logger.System( logs.LevelInfo , "server started" , map[string]any{ "version": version } )
	defer logger.System( logs.LevelInfo , "server stopped" , nil )
	if cfg.SecretMigrated {
		logger.System( logs.LevelWarn , "secret key moved to secret.key" , map[string]any{ "config": cfg.ConfigFile , "secret": cfg.SecretFile } )
	}

	// A change to config.yaml reaches the activity log's own settings, and
	// is reported on stdout and in the log itself.
	settings.OnChange( func( _ *config.Config , next *config.Config ) {
		logger.Apply( next.Logs )
	} )
	settings.Report = func( level string , message string , detail map[string]any ) {
		log.Printf( "[config] %s" , message )
		logger.System( level , message , detail )
	}
	stop_watching := settings.Watch( 2 * time.Second )
	defer close( stop_watching )

	guard := security.New( store , settings )
	handlers := routes.New( store , settings , guard , lang , static_server , version )
	handlers.Logs = logger
	registry := jobs.New( store , logger )
	jobs.Housekeeping( registry , store , logger , settings )
	handlers.Jobs = registry
	dispatcher := webhooks.New( store , settings )
	registry.Register( webhooks.JobName , webhooks.JobInterval , dispatcher.Run )
	dispatcher.Nudge = func() { registry.RunNow( webhooks.JobName ) }
	registry.OnFailure = func( name string ) {
		// Not its own failure: that would queue a delivery about being unable
		// to deliver.
		if name != webhooks.JobName {
			dispatcher.Emit( models.EventJobFailed , map[string]any{ "job": name } )
		}
	}
	handlers.Webhooks = dispatcher
	push_dispatcher := push.New( store , settings )
	registry.Register( push.JobName , push.JobInterval , push_dispatcher.Run )
	push_dispatcher.RunNow = func() { registry.RunNow( push.JobName ) }
	handlers.Push = push_dispatcher
	registry.Register( "inbox" , time.Hour , func() ( note string , err error ) {
		removed , err := models.PurgeInbox( store , settings.Get().Push.InboxKeep )
		apps , apps_err := models.PurgeDeadPushApps( store )
		groups , groups_err := models.PurgeDeadPushGroups( store )
		note = fmt.Sprintf( "removed %d messages, %d apps, %d groups" , removed , apps , groups )
		err = errors.Join( err , apps_err , groups_err )
		return
	} )
	recorder := metrics.New()
	handlers.Metrics = recorder
	handlers.ErrorPages = error_pages
	handlers.OpenAPI = embeddedOpenAPI
	handlers.LogStream = log_stream

	app := fiber.New( fiber.Config{
		AppName: cfg.ProjectName,
		// An empty Server header keeps the response from advertising which
		// framework and version is running -- free reconnaissance otherwise.
		ServerHeader: "",
		BodyLimit:    cfg.BodyLimit,
		// Timeouts are what stop a handful of slow or stalled connections
		// from holding sockets open until the process runs out of them.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  75 * time.Second,
		// Forwarded headers are believed only from the configured proxies,
		// and only once validated as IP addresses -- see server.trust_proxy
		// in config.yaml. Without the allowlist fiber trusts no proxy at all.
		TrustProxy:         cfg.TrustProxy,
		TrustProxyConfig:   fiber.TrustProxyConfig{ Proxies: cfg.TrustedProxies },
		EnableIPValidation: true,
		ProxyHeader:        proxyHeader( cfg ),
		ErrorHandler:       middleware.NewErrorHandler( error_pages ),
	} )

	// RequestID and Metrics come first, outside Recover: a panic still has to
	// carry a reference and be counted, and neither depends on the activity
	// log being on.
	app.Use( middleware.RequestID() )
	app.Use( middleware.Metrics( recorder ) )
	app.Use( middleware.Recover( settings ) )
	app.Use( middleware.SecurityHeaders( settings ) )
	app.Use( middleware.RateLimit( settings ) )
	app.Use( middleware.RequestLog( logger ) )

	handlers.Register( app )

	// Background work: see server/jobs. Stop is deferred after the logger and
	// the store, so it runs before they close, and a job finishing during the
	// wait can still write to both.
	registry.Start()
	defer registry.Stop( jobStopWait )
	// After Stop, so it runs first: a run waiting on a retry lets go at once.
	defer push_dispatcher.Close()

	// Shut down on a signal rather than being killed, so in-flight requests
	// finish and bolt closes cleanly instead of leaving a locked file behind.
	// Listen only waits for that drain when it is given a context to watch:
	// without one it returns as the listener closes, and the deferred closes
	// above would run underneath requests still being answered.
	draining , drain := context.WithCancel( context.Background() )
	defer drain()
	shutdown := make( chan os.Signal , 1 )
	signal.Notify( shutdown , os.Interrupt , syscall.SIGTERM )
	go func() {
		<-shutdown
		log.Println( "[shutdown] draining connections..." )
		// Close the control socket first: it is the door other processes
		// come through, and letting a manage command start against a
		// database that is about to close would fail confusingly.
		control_server.Close()
		// Streams never finish by themselves, so the drain would wait out its
		// whole timeout for any page left open.
		log_stream.Close()
		handlers.InboxStreams.Close()
		drain()
	}()

	log.Printf( "[start] %s %s listening on %s (secure cookies: %v)" , cfg.ProjectName , version , cfg.ListenAddress() , cfg.SecureCookies )
	log.Printf( "[url]    %s  (from %s)" , cfg.URL , cfg.URLSource )
	if cfg.ConfigCreated {
		log.Printf( "[config] %s (created; edits apply while the server runs)" , cfg.ConfigFile )
	} else {
		log.Printf( "[config] %s (edits apply while the server runs)" , cfg.ConfigFile )
	}
	switch {
	case cfg.SecretMigrated:
		log.Printf( "[secret] %s" , cfg.SecretFile )
		log.Printf( "[secret] ================================================================" )
		log.Printf( "[secret] MOVED server.secret_key out of %s" , cfg.ConfigFile )
		log.Printf( "[secret] into %s (mode 0600). config.yaml holds no secret now." , cfg.SecretFile )
		log.Printf( "[secret] Back secret.key up with the database: nothing else can read it." )
		log.Printf( "[secret] ================================================================" )
	case cfg.SecretCreated:
		log.Printf( "[secret] %s (created, with a new key -- back it up)" , cfg.SecretFile )
	default:
		log.Printf( "[secret] %s" , cfg.SecretFile )
	}
	if cfg.ConfigWarning != "" {
		log.Printf( "[config] warning: %s" , cfg.ConfigWarning )
	}
	log.Printf( "[state]  %s" , cfg.AppDir )
	if logger.Enabled() {
		log.Printf( "[logs]   %s (keeping %d days, up to %d MB)" , cfg.Logs.Dir , cfg.Logs.RetentionDays , cfg.Logs.MaxTotalBytes / 1024 / 1024 )
	}
	log.Printf( "[assets] %s" , bundle.Source )
	log.Printf( "[control] %s" , control_server.Path() )
	err = app.Listen( cfg.ListenAddress() , fiber.ListenConfig{
		DisableStartupMessage: true,
		GracefulContext:       draining,
		ShutdownTimeout:       drainWait,
	} )
	return
}

func proxyHeader( cfg *config.Config ) ( result string ) {
	if cfg.TrustProxy {
		result = cfg.ProxyHeader
	}
	return
}
