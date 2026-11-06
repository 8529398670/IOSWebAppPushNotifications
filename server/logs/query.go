package logs

import (
	strconv "strconv"
	strings "strings"
)

// Query is the Logs screen's search box, parsed. Every term must hold (AND):
//
//	ana                free text: anywhere in the entry's JSON, any case
//	"sign in"          a quoted phrase is one free-text term
//	kind:auth,admin    key:value -- a comma means any of these (OR)
//	-kind:request      a leading minus means the term must NOT hold
//
// Keys:
//
//	kind    request ui auth admin error system
//	level   info warn error
//	user    the actor's name (substring) or id (exact)
//	status  a status code, or a class: 5xx, 4xx
//	method  GET, POST, ...
//	path    the start of the request path
//	ip      the start of the address
//	action  a page action: click nav submit undo redo error fetch_fail session_start
//	screen  the screen a page action happened on
//
// An unknown key is free text, so pasting "a:b" from an entry still finds it.
type Query struct {
	terms []term
}

type term struct {
	key    string
	values []string
	negate bool
}

var queryKeys = map[string]bool{
	"kind": true , "level": true , "user": true , "status": true , "method": true ,
	"path": true , "ip": true , "action": true , "screen": true ,
}

// ParseQuery never fails: anything it does not understand is free text.
func ParseQuery( text string ) ( query Query ) {
	for _ , word := range splitWords( text ) {
		item := term{}
		if strings.HasPrefix( word , "-" ) && len( word ) > 1 {
			item.negate = true
			word = word[ 1: ]
		}
		key , value , found := strings.Cut( word , ":" )
		key = strings.ToLower( key )
		if found && queryKeys[ key ] && value != "" {
			item.key = key
			for _ , part := range strings.Split( value , "," ) {
				if part = strings.TrimSpace( part ); part != "" {
					item.values = append( item.values , strings.ToLower( part ) )
				}
			}
		} else {
			item.values = []string{ strings.ToLower( word ) }
		}
		if len( item.values ) > 0 {
			query.terms = append( query.terms , item )
		}
	}
	return
}

// splitWords splits on spaces, keeping "a quoted phrase" (quotes removed) as
// one word.
func splitWords( text string ) ( words []string ) {
	var current strings.Builder
	quoted := false
	for _ , character := range text {
		switch {
		case character == '"':
			quoted = !quoted
		case ( character == ' ' || character == '\t' ) && quoted == false:
			if current.Len() > 0 {
				words = append( words , current.String() )
				current.Reset()
			}
		default:
			current.WriteRune( character )
		}
	}
	if current.Len() > 0 {
		words = append( words , current.String() )
	}
	return
}

func ( query Query ) Empty() ( result bool ) {
	result = len( query.terms ) == 0
	return
}

// Match tests one entry. text is the entry's JSON, lowercased.
func ( query Query ) Match( entry *Entry , text []byte ) ( result bool ) {
	lowered := string( text )
	for _ , item := range query.terms {
		if item.holds( entry , lowered ) == item.negate {
			return
		}
	}
	result = true
	return
}

func ( item term ) holds( entry *Entry , text string ) ( result bool ) {
	for _ , value := range item.values {
		if item.matches( entry , text , value ) {
			result = true
			return
		}
	}
	return
}

func ( item term ) matches( entry *Entry , text string , value string ) ( result bool ) {
	switch item.key {
	case "":
		result = strings.Contains( text , value )
	case "kind":
		result = strings.ToLower( entry.Kind ) == value
	case "level":
		result = strings.ToLower( entry.Level ) == value
	case "user":
		if entry.Actor == nil || entry.Actor.UserID == 0 { return }
		result = strings.Contains( strings.ToLower( entry.Actor.Name ) , value ) ||
			strconv.FormatUint( entry.Actor.UserID , 10 ) == value
	case "status":
		if entry.Request == nil { return }
		status := strconv.Itoa( entry.Request.Status )
		if len( value ) == 3 && strings.HasSuffix( value , "xx" ) {
			result = status[ :1 ] == value[ :1 ]
		} else {
			result = status == value
		}
	case "method":
		result = entry.Request != nil && strings.ToLower( entry.Request.Method ) == value
	case "path":
		result = entry.Request != nil && strings.HasPrefix( strings.ToLower( entry.Request.Path ) , value )
	case "ip":
		result = strings.HasPrefix( strings.ToLower( entry.IP ) , value )
	case "action":
		result = entry.UI != nil && strings.ToLower( entry.UI.Action ) == value
	case "screen":
		result = entry.UI != nil && strings.ToLower( entry.UI.Screen ) == value
	}
	return
}
