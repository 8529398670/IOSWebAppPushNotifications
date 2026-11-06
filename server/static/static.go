// Package static implements this project's one opinionated serving rule:
// markup and code are never cached, images are cached hard.
//
// Text assets (.html/.css/.js/...) are read and gzipped on every request with
// Cache-Control: no-store. A deploy is therefore live on the next refresh,
// with no content hashing, no ?v=123 query strings, and no cache-busting
// build step to keep in sync. Gzip is what makes that affordable -- the bytes
// on the wire are a fraction of the file.
//
// Images and other binaries get the opposite treatment. Gzip does nothing for
// already-compressed formats, and nobody wants a photo re-downloaded on every
// page view, so those get a long max-age.
//
// The source is an fs.FS rather than a directory path, which is what lets the
// same code serve a live ./static during development and the copy embedded in
// a single-file binary in production. See server/assets.
package static

import (
	bytes "bytes"
	gzip "compress/gzip"
	fs "io/fs"
	mime "mime"
	path "path"
	strings "strings"

	fiber "github.com/gofiber/fiber/v3"
)

// Extensions that are text, change often, and must never go stale.
var alwaysFreshExtensions = map[string]bool{
	".html": true, ".htm": true, ".css": true, ".js": true, ".mjs": true,
	".json": true, ".svg": true, ".txt": true, ".map": true,
	".xml": true, ".webmanifest": true, ".yaml": true, ".yml": true,
}

const binaryCacheSeconds = 60 * 60 * 24 * 7 // 7 days

// Go's built-in MIME table has no web fonts, and the OS one it consults (if
// any) varies by machine. The vendored icon font needs these.
func init() {
	mime.AddExtensionType( ".woff2" , "font/woff2" )
	mime.AddExtensionType( ".woff" , "font/woff" )
}

type Server struct {
	// NotFound answers a path with nothing behind it. main.go wraps it so a
	// browser gets the error page; a stylesheet or script tag keeps this plain
	// text, which is what makes a missing asset easy to read in the console.
	NotFound fiber.Handler

	fsys      fs.FS
	indexFile string
}

func New( fsys fs.FS ) ( server *Server , err error ) {
	server = &Server{ NotFound: plainNotFound , fsys: fsys , indexFile: "index.html" }
	return
}

func plainNotFound( c fiber.Ctx ) ( err error ) {
	err = c.Status( fiber.StatusNotFound ).SendString( "Not found" )
	return
}

// hasDotDot spots a parent-directory segment in the raw request.
//
// fs.FS already refuses these -- fs.ValidPath rejects any path containing a
// ".." element. That stops a request *naming* a path outside the root; what
// stops a symlink inside the root from *pointing* outside it is the os.Root
// that server/assets opens for the disk case. This check is here so the intent
// is stated rather than left as a property of the standard library.
func hasDotDot( request_path string ) ( result bool ) {
	normalised := strings.ReplaceAll( request_path , "\\" , "/" )
	for _ , segment := range strings.Split( normalised , "/" ) {
		if segment == ".." {
			result = true
			return
		}
	}
	return
}

// resolve turns a request path into an fs.FS name: forward slashes, no
// leading slash, no "." or ".." elements.
func resolve( request_path string ) ( result string , ok bool ) {
	if hasDotDot( request_path ) { return }
	cleaned := path.Clean( "/" + strings.ReplaceAll( request_path , "\\" , "/" ) )
	cleaned = strings.TrimPrefix( cleaned , "/" )
	if cleaned == "" || fs.ValidPath( cleaned ) == false { return }
	result , ok = cleaned , true
	return
}

func ( server *Server ) isFile( name string ) ( result bool ) {
	info , err := fs.Stat( server.fsys , name )
	result = err == nil && info.Mode().IsRegular()
	return
}

func contentType( name string ) ( result string ) {
	result = mime.TypeByExtension( strings.ToLower( path.Ext( name ) ) )
	if result == "" {
		result = "application/octet-stream"
	}
	return
}

// Handler serves whatever is in the filesystem. Register it last: it matches
// everything, so any route declared after it is unreachable.
func ( server *Server ) Handler( c fiber.Ctx ) ( err error ) {
	request_path := c.Params( "*" )
	if request_path == "" || strings.HasSuffix( request_path , "/" ) {
		request_path = path.Join( request_path , server.indexFile )
	}

	// No fallback to index.html. The app navigates by hash, and the two paths
	// it does read have their own routes (/login/*, /join/*), so anything else
	// is a real 404. An app that adds a path-routed page registers it with
	// ServeIndex, before this handler.
	name , ok := resolve( request_path )
	if ok == false || server.isFile( name ) == false {
		err = server.NotFound( c )
		return
	}

	if alwaysFreshExtensions[ strings.ToLower( path.Ext( name ) ) ] == false {
		c.Set( fiber.HeaderVary , "Accept-Encoding" )
		err = c.SendFile( name , fiber.SendFile{
			FS:        server.fsys,
			MaxAge:    binaryCacheSeconds,
			ByteRange: true,
		} )
		return
	}

	err = server.sendText( c , name )
	return
}

// ServeIndex answers with index.html whatever the path, for routes the
// browser app handles itself (the login link's confirmation page).
func ( server *Server ) ServeIndex( c fiber.Ctx ) ( err error ) {
	if server.isFile( server.indexFile ) == false {
		err = server.NotFound( c )
		return
	}
	err = server.sendText( c , server.indexFile )
	return
}

// sendText is the always-fresh half of the serving rule: read on every
// request, never cached, gzipped when the client accepts it.
func ( server *Server ) sendText( c fiber.Ctx , name string ) ( err error ) {
	body , read_err := fs.ReadFile( server.fsys , name )
	if read_err != nil {
		err = server.NotFound( c )
		return
	}

	c.Set( fiber.HeaderContentType , contentType( name ) )
	c.Set( fiber.HeaderCacheControl , "no-store, no-cache, must-revalidate" )
	c.Set( fiber.HeaderVary , "Accept-Encoding" )

	if strings.Contains( c.Get( fiber.HeaderAcceptEncoding ) , "gzip" ) == false {
		err = c.Send( body )
		return
	}

	var compressed bytes.Buffer
	writer , _ := gzip.NewWriterLevel( &compressed , gzip.BestSpeed )
	if _ , write_err := writer.Write( body ); write_err != nil {
		writer.Close()
		err = c.Send( body )
		return
	}
	if close_err := writer.Close(); close_err != nil {
		err = c.Send( body )
		return
	}

	c.Set( fiber.HeaderContentEncoding , "gzip" )
	err = c.Send( compressed.Bytes() )
	return
}
