// Package language loads every piece of user-facing text from language.yaml.
//
// The point is that changing what the UI says -- translating it, softening it,
// or removing a label entirely -- is a config edit, not a code change. A key
// that is absent or empty is a deliberate signal: the frontend hides that
// element rather than rendering a blank or a raw key name, which is how you
// turn a whole section off without touching the HTML.
//
// It parses bytes rather than opening a path, because the YAML may come from
// disk during development or from the copy embedded in a single-file binary.
// Deciding which is server/assets' job, not this package's.
package language

import (
	json "encoding/json"
	fmt "fmt"
	strings "strings"
	sync "sync"

	yaml "gopkg.in/yaml.v3"
)

type Language struct {
	mutex  sync.RWMutex
	values map[string]any
	asJSON []byte
}

func Parse( raw []byte ) ( lang *Language , err error ) {
	lang = &Language{ values: map[string]any{} , asJSON: []byte( "{}" ) }
	if err = lang.Replace( raw ); err != nil { lang = nil }
	return
}

func ( lang *Language ) Replace( raw []byte ) ( err error ) {
	parsed := map[string]any{}
	if err = yaml.Unmarshal( raw , &parsed ); err != nil {
		err = fmt.Errorf( "could not parse language.yaml: %w" , err )
		return
	}

	// Serialise once at load time -- /api/language is hit on every page load
	// and re-encoding identical data per request is pure waste.
	encoded , err := json.Marshal( parsed )
	if err != nil { return }

	lang.mutex.Lock()
	lang.values , lang.asJSON = parsed , encoded
	lang.mutex.Unlock()
	return
}

// JSON is what the browser receives. Handing the whole tree over at once
// means the frontend can render text without a round trip per label.
func ( lang *Language ) JSON() ( result []byte ) {
	lang.mutex.RLock()
	defer lang.mutex.RUnlock()
	result = lang.asJSON
	return
}

// Get resolves a dotted path like "admin.create_button". It returns "" for a
// missing key rather than an error, because "this text is intentionally
// absent" and "this key is misspelled" should both end up showing nothing
// instead of leaking an internal key name into the UI.
func ( lang *Language ) Get( dotted_key string ) ( result string ) {
	lang.mutex.RLock()
	defer lang.mutex.RUnlock()

	var cursor any = lang.values
	for _ , part := range strings.Split( dotted_key , "." ) {
		node , ok := cursor.( map[string]any )
		if ok == false { return }
		cursor , ok = node[ part ]
		if ok == false { return }
	}
	if text , ok := cursor.( string ); ok {
		result = text
	}
	return
}
