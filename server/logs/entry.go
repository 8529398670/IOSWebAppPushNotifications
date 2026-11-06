// Package logs is the activity log: every request the server answers, every
// sign-in and admin action, and what people did on the page (sent by
// static/js/track.js). Only the owner reads it, on the Logs screen.
//
// It is kept in plain files rather than in bolt, one per UTC day under
// <app_dir>/logs/ (2026-11-02.jsonl, then 2026-11-02.1.jsonl once a day
// passes logs.max_file_mb, and .jsonl.gz once it is compressed). A log grows
// all the time and is read a day at a time, which files do well and a single
// key-value bucket does badly: retention is deleting a file, not a scan of
// every record, and the database stays the size of the app's actual data.
//
// Each line is one Entry as JSON or, with server.encrypt_at_rest on, that
// JSON encrypted with the server key and base64'd -- so a copy of the logs
// directory alone reads as nothing, the same as a copy of app.db. Lines of
// both kinds can sit in one file (the setting was changed); the reader tells
// them apart by the first character.
//
// What is never written: request bodies, cookies, the Authorization header,
// the secret half of an API key, a login or invite credential in a path, and
// anything typed into the page. See Redact and track.js.
package logs

import (
	url "net/url"
	strings "strings"
	time "time"
	utf8 "unicode/utf8"
)

// Kinds. The Logs screen has a filter button for each.
const (
	KindRequest = "request" // every HTTP request (middleware/request_log.go)
	KindUI      = "ui"      // what someone did on the page (track.js)
	KindAuth    = "auth"    // sign-in, sign-out, joining through an invite link
	KindAdmin   = "admin"   // accounts, keys and invite links being changed
	KindError   = "error"   // a request that ended in a 5xx
	KindSystem  = "system"  // start, stop, prune, dropped entries
)

const (
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Entry is one line of the log. Everything but TS, Kind and Level is
// optional; a request entry has Request, a page entry has UI.
type Entry struct {
	TS      time.Time      `json:"ts"`
	Kind    string         `json:"kind"`
	Level   string         `json:"level"`
	// RequestID is the reference a person sees on an error page, so what they
	// quote can be found here. See server/middleware/request_id.go.
	RequestID string       `json:"request_id,omitempty"`
	Actor   *Actor         `json:"actor,omitempty"`
	IP      string         `json:"ip,omitempty"`
	UA      string         `json:"ua,omitempty"`
	Request *Request       `json:"request,omitempty"`
	UI      *UI            `json:"ui,omitempty"`
	Client  map[string]any `json:"client,omitempty"`
	Msg     string         `json:"msg,omitempty"`
	// Detail is what an auth or admin entry is about: the account, key or
	// link it touched. Ids and names only, never a credential.
	Detail map[string]any `json:"detail,omitempty"`
}

// Actor is who an entry belongs to. Method is "session", "api_key" or "anon".
type Actor struct {
	UserID uint64 `json:"user_id,omitempty"`
	Name   string `json:"name,omitempty"`
	Role   string `json:"role,omitempty"`
	Method string `json:"method"`
	// KeyID is the public half of an API key, never the secret.
	KeyID string `json:"key_id,omitempty"`
}

type Request struct {
	Method   string  `json:"method"`
	Path     string  `json:"path"`
	Status   int     `json:"status"`
	MS       float64 `json:"ms"`
	BytesOut int     `json:"bytes_out"`
	Referer  string  `json:"referer,omitempty"`
}

type UI struct {
	Action string         `json:"action"`
	Screen string         `json:"screen,omitempty"`
	Target string         `json:"target,omitempty"`
	Fields []string       `json:"fields,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`
	// At is the browser's clock when it happened; TS is the server's when
	// the batch arrived.
	At string `json:"at,omitempty"`
}

// owned is the entry with its own copy of every string a request could have
// lent it. A line is written after the request ends, and fiber's strings view a
// buffer it reuses for the next request, so a line that kept them could hold
// that request's bytes: its headers, cookie included. Copying here covers every
// caller, so a route need not remember to. Actor comes from the database and UI
// from a decoded body, so neither views the buffer.
func ( entry Entry ) owned() ( result Entry ) {
	result = entry
	result.RequestID = strings.Clone( entry.RequestID )
	result.IP = strings.Clone( entry.IP )
	result.UA = strings.Clone( entry.UA )
	result.Msg = strings.Clone( entry.Msg )
	if entry.Request != nil {
		request := *entry.Request
		request.Method = strings.Clone( request.Method )
		request.Path = strings.Clone( request.Path )
		request.Referer = strings.Clone( request.Referer )
		result.Request = &request
	}
	if entry.Detail != nil {
		result.Detail = make( map[string]any , len( entry.Detail ) )
		for name , value := range entry.Detail {
			if text , is_text := value.( string ); is_text {
				value = strings.Clone( text )
			}
			result.Detail[ name ] = value
		}
	}
	return
}

// Anonymous is the Actor of a request nobody signed in made.
func Anonymous() ( actor *Actor ) {
	actor = &Actor{ Method: "anon" }
	return
}

// The path prefixes whose next segment is a credential: a login link, an
// invite link. Opening one is logged; the credential is not.
var secretPathPrefixes = []string{ "/login/" , "/join/" , "/i/" }

// Query parameters whose values are never written, whatever route they are on.
var secretQueryKeys = map[string]bool{
	"token": true , "key": true , "secret": true , "code": true ,
	"credential": true , "csrf_token": true , "pin": true , "password": true ,
	"password_digest": true , "challenge": true , "recovery_code": true ,
}

const maxPathLength = 300

// Redact makes a request path safe to keep: the credential in a login or
// invite link becomes "…", secret-looking query values become "…", and the
// whole is capped so a pathological URL cannot bloat a line.
func Redact( path string , raw_query string ) ( result string ) {
	result = path
	for _ , prefix := range secretPathPrefixes {
		if strings.HasPrefix( result , prefix ) && len( result ) > len( prefix ) {
			result = prefix + "…"
			break
		}
	}
	if raw_query != "" {
		values , err := url.ParseQuery( raw_query )
		if err != nil {
			result += "?…"
		} else {
			for name := range values {
				if secretQueryKeys[ strings.ToLower( name ) ] {
					values.Set( name , "…" )
				}
			}
			result += "?" + values.Encode()
		}
	}
	if len( result ) > maxPathLength {
		result = result[ :maxPathLength ] + "…"
	}
	return
}

// Truncate caps a string from a browser or a header at max bytes, on a rune
// boundary.
func Truncate( value string , max int ) ( result string ) {
	result = value
	if len( result ) <= max { return }
	result = result[ :max ]
	for len( result ) > 0 && utf8.ValidString( result ) == false {
		result = result[ :len( result ) - 1 ]
	}
	return
}
