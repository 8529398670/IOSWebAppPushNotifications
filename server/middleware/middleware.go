// Package middleware holds the cross-cutting protections that apply to every
// request no matter which route answers it. Keeping them here means a route
// handler never has to remember a header or a throttle -- if it is registered
// on the app, it is covered.
package middleware

import (
	strings "strings"
	time "time"

	fiber "github.com/gofiber/fiber/v3"
	helmet "github.com/gofiber/fiber/v3/middleware/helmet"
	limiter "github.com/gofiber/fiber/v3/middleware/limiter"
	recoverer "github.com/gofiber/fiber/v3/middleware/recover"

	config "ipb/server/config"
)

// robotsPolicy keeps every response out of search results.
const robotsPolicy = "noindex, nofollow"

// SecurityHeaders assumes everything the page needs is same-origin, which is
// true for this template on purpose: libraries are downloaded once and served
// from static/vendor/ rather than pulled from a CDN at runtime. That is what
// lets the CSP stay this tight, and it is why adding a <script src> pointing
// at some other origin will visibly break -- the fix is to vendor the file,
// not to loosen the policy.
//
// server.secure_cookies decides HSTS and can change while the server runs,
// so both variants are built here and the current setting picks one per
// request.
func SecurityHeaders( settings *config.Holder ) ( handler fiber.Handler ) {
	secure , plain := securityHeaders( true ) , securityHeaders( false )
	handler = func( c fiber.Ctx ) ( err error ) {
		// helmet has no field for this one. Every app built from this template
		// is private, and robots.txt only asks: this covers a crawler that
		// reaches a page anyway.
		c.Set( fiber.HeaderXRobotsTag , robotsPolicy )
		if settings.Get().SecureCookies {
			err = secure( c )
			return
		}
		err = plain( c )
		return
	}
	return
}

func securityHeaders( secure_cookies bool ) ( handler fiber.Handler ) {
	content_security_policy := "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"

	hsts_max_age := 0
	if secure_cookies {
		// Only claim HTTPS-only when the deployment actually is. Sending HSTS
		// from a local http:// run would pin the browser to https for
		// localhost and break every other project on that port.
		hsts_max_age = 63072000
	}

	handler = helmet.New( helmet.Config{
		ContentSecurityPolicy:     content_security_policy,
		XFrameOptions:             "DENY",
		ContentTypeNosniff:        "nosniff",
		ReferrerPolicy:            "same-origin",
		PermissionPolicy:          "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
		XDNSPrefetchControl:       "off",
		HSTSMaxAge:                hsts_max_age,
		HSTSExcludeSubdomains:     false,
	} )
	return
}

// rateBudget is which limit a request counts against.
type rateBudget int

const (
	budgetGeneral rateBudget = iota
	budgetSignIn
	budgetUpload
	budgetSend
	budgetNone
)

// sendPaths are the notification API. A script can send far more often than a
// person clicks, and should not spend the budget that serves the app's pages.
var sendPaths = map[string]bool{
	"/api/v1/messages":   true,
	"/1/messages.json":   true,
}

// signInPaths are the exact POSTs that try a credential. Joining through an
// invite link counts: each of those calls takes a PIN or mints an account.
var signInPaths = map[string]bool{
	"/api/login":            true,
	"/api/login/two-factor": true,
	"/api/login/password":   true,
	"/api/join/info":        true,
	"/api/join/match":       true,
	"/api/join/claim":       true,
	"/api/join/create":      true,
}

// uploadChunk is exactly POST /api/files/<id>/chunks/<index>. A file arrives as
// many of these, so they have a budget of their own: on the general one a big
// upload would use up what the page needs and still crawl.
func uploadChunk( method string , normalised string ) ( result bool ) {
	parts := strings.Split( normalised , "/" )
	result = method == fiber.MethodPost && len( parts ) == 6 && parts[ 1 ] == "api" && parts[ 2 ] == "files" && parts[ 4 ] == "chunks"
	return
}

// budgetFor sorts a request.
//
// The path is normalised first because fiber's routing is not strict: it
// ignores case and a trailing slash, so /API/LOGIN/ reaches the same handler
// as /api/login. Comparing the raw path would let a caller pick a spelling
// that skips the sign-in budget, or one that passes for a static file.
//
// Static files are exempt because index.html alone pulls in more than twenty,
// all no-store, so counting them meant about five reloads a minute hit a 429.
// Serving one touches no database and no credential. The page itself is not
// exempt, and neither is anything under /api.
func budgetFor( method string , request_path string ) ( budget rateBudget ) {
	normalised := strings.ToLower( request_path )
	if len( normalised ) > 1 {
		normalised = strings.TrimRight( normalised , "/" )
	}
	switch {
	case method == fiber.MethodPost && signInPaths[ normalised ]:
		budget = budgetSignIn
	case uploadChunk( method , normalised ):
		budget = budgetUpload
	case method == fiber.MethodPost && sendPaths[ normalised ]:
		budget = budgetSend
	case staticAsset( method , normalised ):
		budget = budgetNone
	}
	return
}

// RateLimit is a per-process, in-memory limiter. That is exactly right for
// the single container docker/run.sh builds. Run more than one replica and the
// counters stop being shared, so each replica would allow the full budget --
// move to a shared store (limiter.Config.Storage) at that point rather than
// assuming the limit still holds.
//
// Each address has three budgets over the same window: one for signing in, one
// for the chunks of an upload, and one for everything else. Keeping them apart
// means a page full of API calls cannot lock someone out of signing in, and
// guessing at sign-in does not get the budget the rest of the app has.
//
// The budgets and the window are read per request, so an edit to any of
// server.rate_limit_max, rate_limit_signin_max, rate_limit_upload_max or
// rate_limit_window_seconds applies at once.
func RateLimit( settings *config.Holder ) ( handler fiber.Handler ) {
	limited := func( prefix string , limit func( cfg *config.Config ) int ) ( result fiber.Handler ) {
		result = limiter.New( limiter.Config{
			MaxFunc: func( fiber.Ctx ) ( max int ) {
				max = limit( settings.Get() )
				return
			},
			ExpirationFunc: func( fiber.Ctx ) ( window time.Duration ) {
				window = settings.Get().RateLimitWindow
				return
			},
			KeyGenerator: func( c fiber.Ctx ) ( key string ) {
				key = prefix + c.IP()
				return
			},
			LimitReached: func( c fiber.Ctx ) ( err error ) {
				// Through the ErrorHandler: a page load gets the error page,
				// and everything else the usual JSON.
				err = fiber.ErrTooManyRequests
				return
			},
		} )
		return
	}
	general := limited( "general:" , func( cfg *config.Config ) int { return cfg.RateLimitMax } )
	sign_in := limited( "sign-in:" , func( cfg *config.Config ) int { return cfg.RateLimitSignInMax } )
	upload := limited( "upload:" , func( cfg *config.Config ) int { return cfg.RateLimitUploadMax } )
	send := limited( "send:" , func( cfg *config.Config ) int { return cfg.RateLimitSendMax } )

	handler = func( c fiber.Ctx ) ( err error ) {
		switch budgetFor( c.Method() , c.Path() ) {
		case budgetNone:
			err = c.Next()
		case budgetSignIn:
			err = sign_in( c )
		case budgetUpload:
			err = upload( c )
		case budgetSend:
			err = send( c )
		default:
			err = general( c )
		}
		return
	}
	return
}

// Recover keeps one panicking handler from taking the process down with it.
// Stack traces stay off by default: they are enormously useful in a terminal
// and a gift to an attacker if they ever reach a response body.
func Recover( settings *config.Holder ) ( handler fiber.Handler ) {
	traced := recoverer.New( recoverer.Config{ EnableStackTrace: true } )
	quiet := recoverer.New( recoverer.Config{ EnableStackTrace: false } )
	handler = func( c fiber.Ctx ) ( err error ) {
		if settings.Get().SecureCookies {
			err = quiet( c )
			return
		}
		err = traced( c )
		return
	}
	return
}
