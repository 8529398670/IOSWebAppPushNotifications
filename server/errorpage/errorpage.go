// Package errorpage is the page a person sees when a page load fails. Scripts
// and the app's own API calls never see it: Wanted keeps them on the plain
// answers they already get.
//
// The server renders it rather than the browser app, for two reasons. The app
// needs /api/language to find any words at all, and that call is rate limited,
// so it cannot be relied on while answering a 429. And it has nothing to
// bootstrap: a broken app can still show this.
//
// The CSP allows no inline styles or scripts, so the page only links the files
// the app already serves, which the rate limiter exempts. theme.js applies a
// saved dark theme; with none saved the page is light.
package errorpage

import (
	html "html"
	strings "strings"

	fiber "github.com/gofiber/fiber/v3"

	language "ipb/server/language"
)

const template = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="color-scheme" content="light" />
  <title>%TITLE%</title>
  <link rel="icon" href="/favicon.ico" />
  <script src="/js/theme.js"></script>
  <link rel="stylesheet" href="/vendor/bootstrap.min.css" />
  <link rel="stylesheet" href="/css/style.css" />
</head>
<body>
  <main class="container py-5 text-center">
    <h1 class="h3">%TITLE%</h1>
    <p class="text-body-secondary">%MESSAGE%</p>%REFERENCE%
    <a class="btn btn-primary" href="/">%HOME%</a>
  </main>
</body>
</html>
`

// Pages renders the page from language.yaml. A nil *Pages is valid and wants
// nothing, so a test app can run without one.
type Pages struct {
	lang *language.Language
}

func New( lang *language.Language ) ( pages *Pages ) {
	pages = &Pages{ lang: lang }
	return
}

// Wanted says whether this request should get the page: a browser loading a
// page, rather than a script, a fetch from the app, or a stylesheet.
func ( pages *Pages ) Wanted( c fiber.Ctx ) ( result bool ) {
	if pages == nil { return }
	if c.Method() != fiber.MethodGet && c.Method() != fiber.MethodHead { return }
	request_path := c.Path()
	if request_path == "/api" || strings.HasPrefix( request_path , "/api/" ) { return }
	if request_path == "/mcp" || request_path == "/metrics" { return }
	result = strings.Contains( c.Get( fiber.HeaderAccept ) , "text/html" )
	return
}

// section is the language.yaml prefix for a status.
func section( status int ) ( result string ) {
	switch {
	case status == fiber.StatusNotFound:
		result = "not_found"
	case status == fiber.StatusMethodNotAllowed:
		result = "method_not_allowed"
	case status == fiber.StatusTooManyRequests:
		result = "rate_limited"
	case status == fiber.StatusServiceUnavailable:
		result = "maintenance"
	case status >= 500:
		result = "server_error"
	default:
		result = "other"
	}
	return
}

// Render is the page for a status. reference is the request id, shown on a
// 5xx so a person has something to quote; empty leaves the line out.
func ( pages *Pages ) Render( status int , reference string ) ( body string ) {
	name := section( status )
	reference_line := ""
	if reference != "" && status >= 500 {
		text := strings.ReplaceAll( pages.lang.Get( "error_page.reference" ) , "{reference}" , reference )
		reference_line = "\n    <p class=\"small text-body-secondary\">" + html.EscapeString( text ) + "</p>"
	}
	body = strings.NewReplacer(
		"%TITLE%" , html.EscapeString( pages.lang.Get( "error_page." + name + "_title" ) ),
		"%MESSAGE%" , html.EscapeString( pages.lang.Get( "error_page." + name + "_message" ) ),
		"%REFERENCE%" , reference_line,
		"%HOME%" , html.EscapeString( pages.lang.Get( "error_page.home" ) ),
	).Replace( template )
	return
}

// Send answers with the page. Never cached: the same URL may work next time.
func ( pages *Pages ) Send( c fiber.Ctx , status int , reference string ) ( err error ) {
	c.Set( fiber.HeaderContentType , fiber.MIMETextHTMLCharsetUTF8 )
	c.Set( fiber.HeaderCacheControl , "no-store" )
	err = c.Status( status ).SendString( pages.Render( status , reference ) )
	return
}

// NotFound wraps the answer a static 404 gives a script, so a browser gets the
// page instead.
func ( pages *Pages ) NotFound( plain fiber.Handler ) ( handler fiber.Handler ) {
	handler = func( c fiber.Ctx ) ( err error ) {
		if pages.Wanted( c ) {
			err = pages.Send( c , fiber.StatusNotFound , "" )
			return
		}
		err = plain( c )
		return
	}
	return
}
