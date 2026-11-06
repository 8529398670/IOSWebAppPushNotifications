package config

// EditYAML changes single values in a config.yaml without re-serialising it.
//
// Decoding into a struct and encoding it back would lose every comment, and
// the comments are the documentation: config.yaml starts as a copy of
// defaults.yaml precisely so that each setting explains itself where it is
// set. So instead the file is parsed only to find where each value sits
// (yaml.v3 gives every node a line and column), and the text there is
// replaced. Everything else -- comments, blank lines, ordering, quoting
// elsewhere -- comes out byte for byte as it went in.
//
// What it handles:
//
//	a scalar on its key's line   replaced in place; a trailing comment stays
//	an empty value (key:)        the value is written after the colon
//	a flow list [a, b]           replaced with a flow list
//	a block list (- a lines)     its item lines are rewritten at the same
//	                             indentation; an emptied one becomes []
//	a key the file lacks         added at the end of its section, with the
//	                             comment defaults.yaml has above it
//	a section the file lacks     added at the end of the file
//
// What it refuses, asking for a hand edit: anchors and aliases, explicit
// tags, | and > block scalars, a value spread over several lines, and a
// section written as a {flow: mapping}. None of these appear in a file that
// started from defaults.yaml.
//
// app/core/yaml_edit.py is the same algorithm for the Python template, and
// the two are tested against the same cases.

import (
	errors "errors"
	fmt "fmt"
	regexp "regexp"
	sort "sort"
	strconv "strconv"
	strings "strings"
	utf8 "unicode/utf8"

	yaml "gopkg.in/yaml.v3"
)

// Edit sets one value: Path is "section.key", Value is a bool, int, string
// or []string, as Flatten gives them.
type Edit struct {
	Path  string
	Value any
}

// CommentsFunc returns, for a key EditYAML has to add, the comment lines to
// put above it (each starting with "#", no indentation) and a trailing
// comment for its line ("# ..." or ""). Nil adds the bare key.
type CommentsFunc func( path string ) ( above []string , inline string )

// ErrHandEdit is wrapped by every refusal: the value is written in a way this
// editor does not rewrite, and the message says which key.
var ErrHandEdit = errors.New( "edit it by hand" )

// legacySecretMarker identifies the comment that used to sit above
// server.secret_key, so deleting the key can take its explanation with it.
const legacySecretMarker = "64 hex characters"

// EditYAML applies edits, then removes the keys in deletes (used only to take
// server.secret_key out of an older config.yaml). It works on the text as it
// was given: positions all come from one parse, and the replacements are
// applied from the end of the file backwards so none moves another.
func EditYAML( raw []byte , edits []Edit , deletes []string , comments CommentsFunc ) ( result []byte , err error ) {
	text := newYAMLText( raw )
	var doc yaml.Node
	if err = yaml.Unmarshal( []byte( text.body ) , &doc ); err != nil {
		err = fmt.Errorf( "config.yaml is not valid YAML (%w) -- %w" , err , ErrHandEdit )
		return
	}
	var root *yaml.Node
	if doc.Kind == yaml.DocumentNode && len( doc.Content ) > 0 {
		root = doc.Content[ 0 ]
		if root.Kind != yaml.MappingNode || root.Style & yaml.FlowStyle != 0 {
			err = fmt.Errorf( "config.yaml's top level must be a block mapping of sections -- %w" , ErrHandEdit )
			return
		}
	}

	editor := &yamlEditor{ text: text , root: root , comments: comments }
	for _ , edit := range edits {
		if err = editor.set( edit ); err != nil { return }
	}
	for _ , path := range deletes {
		if err = editor.remove( path ); err != nil { return }
	}
	editor.flushInsertions()
	result , err = editor.apply()
	return
}

// ---------------------------------------------------------------------------
// the text, with offsets for yaml.v3's 1-based line/column positions
// ---------------------------------------------------------------------------

type yamlText struct {
	body  string
	bom   bool
	eol   string
	lines [][2]int // [start, end) of each line, line ending excluded
}

func newYAMLText( raw []byte ) ( text *yamlText ) {
	body := string( raw )
	text = &yamlText{ eol: "\n" }
	if strings.HasPrefix( body , "\uFEFF" ) {
		text.bom = true
		body = strings.TrimPrefix( body , "\uFEFF" )
	}
	if strings.Contains( body , "\r\n" ) {
		text.eol = "\r\n"
	}
	text.body = body
	start := 0
	for index := 0; index < len( body ); index++ {
		if body[ index ] != '\n' { continue }
		end := index
		if end > start && body[ end - 1 ] == '\r' {
			end--
		}
		text.lines = append( text.lines , [2]int{ start , end } )
		start = index + 1
	}
	if start < len( body ) {
		text.lines = append( text.lines , [2]int{ start , len( body ) } )
	}
	return
}

func ( text *yamlText ) line( number int ) ( content string ) {
	if number < 1 || number > len( text.lines ) { return }
	span := text.lines[ number - 1 ]
	content = text.body[ span[ 0 ]:span[ 1 ] ]
	return
}

// offset turns a 1-based line and column into a byte offset. yaml.v3 counts
// columns in characters, so a multibyte character earlier on the line has to
// be walked over rather than assumed to be one byte.
func ( text *yamlText ) offset( line int , column int ) ( offset int ) {
	if line < 1 || line > len( text.lines ) {
		offset = len( text.body )
		return
	}
	span := text.lines[ line - 1 ]
	offset = span[ 0 ]
	for counted := 1; counted < column && offset < span[ 1 ]; counted++ {
		_ , size := utf8.DecodeRuneInString( text.body[ offset: ] )
		offset += size
	}
	return
}

func decodeRune( value string ) ( r rune , size int ) {
	for size , r = range value {
		_ = size
		break
	}
	size = len( string( r ) )
	if r == '�' && len( value ) > 0 && value[ 0 ] != 0xEF {
		size = 1
	}
	return
}

// lineAt is the 1-based line holding a byte offset.
func ( text *yamlText ) lineAt( offset int ) ( number int ) {
	number = sort.Search( len( text.lines ) , func( index int ) bool { return text.lines[ index ][ 1 ] >= offset } ) + 1
	return
}

// ---------------------------------------------------------------------------
// the editor
// ---------------------------------------------------------------------------

type textOp struct {
	start int
	end   int
	text  string
}

type yamlEditor struct {
	text     *yamlText
	root     *yaml.Node
	comments CommentsFunc
	ops      []textOp

	// Keys to add, gathered per section so several land together and in
	// order: into an existing section, or a new one at the end of the file.
	pending      map[string][]Edit
	pendingOrder []string
}

func splitPath( path string ) ( section string , key string , err error ) {
	parts := strings.Split( path , "." )
	if len( parts ) != 2 || parts[ 0 ] == "" || parts[ 1 ] == "" {
		err = fmt.Errorf( "%q is not a section.key path" , path )
		return
	}
	section , key = parts[ 0 ] , parts[ 1 ]
	return
}

func mappingGet( mapping *yaml.Node , name string ) ( key *yaml.Node , value *yaml.Node ) {
	if mapping == nil || mapping.Kind != yaml.MappingNode { return }
	for index := 0; index + 1 < len( mapping.Content ); index += 2 {
		if mapping.Content[ index ].Value == name {
			key , value = mapping.Content[ index ] , mapping.Content[ index + 1 ]
			return
		}
	}
	return
}

func refuse( path string , why string ) ( err error ) {
	err = fmt.Errorf( "%s is %s -- %w" , path , why , ErrHandEdit )
	return
}

func checkPlainNode( path string , node *yaml.Node ) ( err error ) {
	switch {
	case node.Kind == yaml.AliasNode || node.Anchor != "":
		err = refuse( path , "written with an anchor or alias" )
	case node.Style & yaml.TaggedStyle != 0:
		err = refuse( path , "written with an explicit tag" )
	case node.Style & ( yaml.LiteralStyle | yaml.FoldedStyle ) != 0:
		err = refuse( path , "a | or > block scalar" )
	}
	return
}

func ( editor *yamlEditor ) set( edit Edit ) ( err error ) {
	section_name , key_name , err := splitPath( edit.Path )
	if err != nil { return }
	section_key , section := mappingGet( editor.root , section_name )
	switch {
	case section_key == nil:
		editor.queue( section_name , edit )
		return
	case section.Kind == yaml.ScalarNode && section.Tag == "!!null":
		editor.queue( section_name , edit )
		return
	case section.Kind != yaml.MappingNode:
		err = refuse( section_name , "not a mapping" )
		return
	case section.Style & yaml.FlowStyle != 0:
		err = refuse( section_name , "written as a {flow: mapping}" )
		return
	}
	key , value := mappingGet( section , key_name )
	if key == nil {
		editor.queue( section_name , edit )
		return
	}
	if err = checkPlainNode( edit.Path , value ); err != nil { return }

	colon , err := editor.colonEnd( edit.Path , key )
	if err != nil { return }
	empty := editor.restIsEmpty( colon , key.Line )

	if items , is_list := edit.Value.( []string ); is_list {
		err = editor.setList( edit.Path , key , value , colon , empty , items )
		return
	}

	encoded , err := encodeScalar( edit.Value , value.Style )
	if err != nil {
		err = fmt.Errorf( "%s: %w" , edit.Path , err )
		return
	}
	if empty {
		if value.Kind != yaml.ScalarNode || value.Tag != "!!null" {
			err = refuse( edit.Path , "written on the lines below its key" )
			return
		}
		editor.ops = append( editor.ops , textOp{ start: colon , end: colon , text: " " + encoded } )
		return
	}
	if value.Kind != yaml.ScalarNode {
		err = refuse( edit.Path , "not a single value" )
		return
	}
	start , end , err := editor.scalarSpan( edit.Path , value )
	if err != nil { return }
	editor.ops = append( editor.ops , textOp{ start: start , end: end , text: encoded } )
	return
}

func ( editor *yamlEditor ) setList( path string , key *yaml.Node , value *yaml.Node , colon int , empty bool , items []string ) ( err error ) {
	switch {
	case value.Kind == yaml.ScalarNode && value.Tag == "!!null":
		if empty == false {
			start , end , span_err := editor.scalarSpan( path , value )
			if span_err != nil {
				err = span_err
				return
			}
			editor.ops = append( editor.ops , textOp{ start: start , end: end , text: encodeFlowList( items ) } )
			return
		}
		editor.ops = append( editor.ops , textOp{ start: colon , end: colon , text: " " + encodeFlowList( items ) } )
	case value.Kind != yaml.SequenceNode:
		err = refuse( path , "not a list" )
	case value.Style & yaml.FlowStyle != 0:
		start := editor.text.offset( value.Line , value.Column )
		end , scan_err := scanFlowEnd( editor.text.body , start )
		if scan_err != nil {
			err = refuse( path , scan_err.Error() )
			return
		}
		editor.ops = append( editor.ops , textOp{ start: start , end: end , text: encodeFlowList( items ) } )
	default:
		first , last := 0 , 0
		for _ , item := range value.Content {
			if item.Kind != yaml.ScalarNode {
				err = refuse( path , "a list with items that are not single values" )
				return
			}
			if err = checkPlainNode( path , item ); err != nil { return }
			if _ , _ , err = editor.scalarSpan( path , item ); err != nil { return }
			if first == 0 {
				first = item.Line
			}
			last = item.Line
		}
		first_line := editor.text.line( first )
		dash := strings.Index( first_line , "-" )
		if first == 0 || dash < 0 {
			err = refuse( path , "a list this editor cannot find the items of" )
			return
		}
		prefix := first_line[ :dash ]
		start := editor.text.lines[ first - 1 ][ 0 ]
		end := editor.text.lines[ last - 1 ][ 1 ]
		if len( items ) == 0 {
			// Drop the item lines, line endings included, and write [] on
			// the key's line instead.
			end = editor.nextLineStart( last )
			editor.ops = append( editor.ops , textOp{ start: start , end: end , text: "" } )
			editor.ops = append( editor.ops , textOp{ start: colon , end: colon , text: " []" } )
			return
		}
		lines := make( []string , 0 , len( items ) )
		for _ , item := range items {
			lines = append( lines , prefix + "- " + encodeString( item , 0 ) )
		}
		editor.ops = append( editor.ops , textOp{ start: start , end: end , text: strings.Join( lines , editor.text.eol ) } )
	}
	return
}

// remove takes a key's line out, and with it the comment above it when that
// comment is the one that described server.secret_key. A short note goes in
// its place, so a reader of an older file learns where the key went.
func ( editor *yamlEditor ) remove( path string ) ( err error ) {
	section_name , key_name , err := splitPath( path )
	if err != nil { return }
	_ , section := mappingGet( editor.root , section_name )
	key , value := mappingGet( section , key_name )
	if key == nil { return }
	if value.Kind != yaml.ScalarNode || value.Line != key.Line {
		err = refuse( path , "not a single value on its key's line" )
		return
	}
	if _ , _ , err = editor.scalarSpan( path , value ); err != nil { return }

	first := key.Line
	above := key.Line - 1
	for above >= 1 && strings.HasPrefix( strings.TrimSpace( editor.text.line( above ) ) , "#" ) {
		above--
	}
	block := make( []string , 0 )
	for number := above + 1; number < key.Line; number++ {
		block = append( block , editor.text.line( number ) )
	}
	if strings.Contains( strings.Join( block , "\n" ) , legacySecretMarker ) {
		first = above + 1
	}
	key_line := editor.text.line( key.Line )
	indent := key_line[ :len( key_line ) - len( strings.TrimLeft( key_line , " \t" ) ) ]
	note := []string{
		indent + "# The secret key moved to secret.key, beside this file. Back the two up",
		indent + "# together with the app directory: nothing else can read the database.",
	}
	editor.ops = append( editor.ops , textOp{
		start: editor.text.lines[ first - 1 ][ 0 ],
		end:   editor.text.lines[ key.Line - 1 ][ 1 ],
		text:  strings.Join( note , editor.text.eol ),
	} )
	return
}

func ( editor *yamlEditor ) queue( section string , edit Edit ) {
	if editor.pending == nil {
		editor.pending = map[string][]Edit{}
	}
	if _ , seen := editor.pending[ section ]; seen == false {
		editor.pendingOrder = append( editor.pendingOrder , section )
	}
	editor.pending[ section ] = append( editor.pending[ section ] , edit )
}

// flushInsertions turns the queued missing keys into text: appended to the
// end of their section, after its last value line, or as a new section at
// the end of the file.
func ( editor *yamlEditor ) flushInsertions() {
	var appended []string
	for _ , section_name := range editor.pendingOrder {
		edits := editor.pending[ section_name ]
		section_key , section := mappingGet( editor.root , section_name )
		indent := "  "
		at := -1
		switch {
		case section_key == nil:
		case section.Kind == yaml.MappingNode && len( section.Content ) > 0:
			first_key := editor.text.line( section.Content[ 0 ].Line )
			indent = first_key[ :len( first_key ) - len( strings.TrimLeft( first_key , " \t" ) ) ]
			at = editor.text.lines[ editor.lastContentLine( section_key ) - 1 ][ 1 ]
		default:
			// "section:" or "section: ~": drop an explicit null, add below.
			if section.Line == section_key.Line && section.Value != "" {
				if colon , colon_err := editor.colonEnd( section_name , section_key ); colon_err == nil {
					start := editor.text.offset( section.Line , section.Column )
					end := scanPlainEnd( editor.text.body , start , editor.text.lines[ section.Line - 1 ][ 1 ] )
					editor.ops = append( editor.ops , textOp{ start: colon , end: end , text: "" } )
				}
			}
			at = editor.text.lines[ section_key.Line - 1 ][ 1 ]
		}
		lines := editor.renderKeys( section_name , edits , indent )
		if at < 0 {
			appended = append( appended , "" , section_name + ":" )
			appended = append( appended , lines... )
			continue
		}
		editor.ops = append( editor.ops , textOp{ start: at , end: at , text: editor.text.eol + strings.Join( lines , editor.text.eol ) } )
	}
	if len( appended ) == 0 { return }
	end := len( editor.text.body )
	prefix := ""
	if end > 0 && strings.HasSuffix( editor.text.body , "\n" ) == false {
		prefix = editor.text.eol
	}
	if end == 0 {
		appended = appended[ 1: ]
	}
	editor.ops = append( editor.ops , textOp{ start: end , end: end , text: prefix + strings.Join( appended , editor.text.eol ) + editor.text.eol } )
}

func ( editor *yamlEditor ) renderKeys( section string , edits []Edit , indent string ) ( lines []string ) {
	for _ , edit := range edits {
		_ , key_name , _ := splitPath( edit.Path )
		var above []string
		inline := ""
		if editor.comments != nil {
			above , inline = editor.comments( edit.Path )
		}
		for _ , comment := range above {
			lines = append( lines , indent + comment )
		}
		var encoded string
		if items , is_list := edit.Value.( []string ); is_list {
			encoded = encodeFlowList( items )
		} else {
			encoded , _ = encodeScalar( edit.Value , 0 )
		}
		line := indent + key_name + ": " + encoded
		if inline != "" {
			line += "  " + inline
		}
		lines = append( lines , line )
	}
	return
}

// lastContentLine is the last line of a section that is neither blank nor a
// comment: comments just above the next section describe that section.
func ( editor *yamlEditor ) lastContentLine( section_key *yaml.Node ) ( last int ) {
	next := len( editor.text.lines ) + 1
	for index := 0; index + 1 < len( editor.root.Content ); index += 2 {
		line := editor.root.Content[ index ].Line
		if line > section_key.Line && line < next {
			next = line
		}
	}
	for last = next - 1; last > section_key.Line; last-- {
		trimmed := strings.TrimSpace( editor.text.line( last ) )
		if trimmed != "" && strings.HasPrefix( trimmed , "#" ) == false {
			return
		}
	}
	return
}

func ( editor *yamlEditor ) nextLineStart( line int ) ( offset int ) {
	if line < len( editor.text.lines ) {
		offset = editor.text.lines[ line ][ 0 ]
		return
	}
	offset = len( editor.text.body )
	return
}

// colonEnd is the offset just past the ":" after a key.
func ( editor *yamlEditor ) colonEnd( path string , key *yaml.Node ) ( offset int , err error ) {
	start := editor.text.offset( key.Line , key.Column )
	line_end := editor.text.lines[ key.Line - 1 ][ 1 ]
	end := start + len( key.Value )
	if key.Style & ( yaml.DoubleQuotedStyle | yaml.SingleQuotedStyle ) != 0 {
		if end , err = scanQuotedEnd( editor.text.body , start , line_end ); err != nil {
			err = refuse( path , "a key this editor cannot read" )
			return
		}
	}
	for end < line_end && ( editor.text.body[ end ] == ' ' || editor.text.body[ end ] == '\t' ) {
		end++
	}
	if end >= line_end || editor.text.body[ end ] != ':' {
		err = refuse( path , "a key this editor cannot read" )
		return
	}
	offset = end + 1
	return
}

// restIsEmpty is true when nothing but a comment follows the colon.
func ( editor *yamlEditor ) restIsEmpty( colon int , line int ) ( empty bool ) {
	rest := strings.TrimSpace( editor.text.body[ colon:editor.text.lines[ line - 1 ][ 1 ] ] )
	empty = rest == "" || strings.HasPrefix( rest , "#" )
	return
}

// scalarSpan is where a single-line scalar's text starts and ends.
func ( editor *yamlEditor ) scalarSpan( path string , node *yaml.Node ) ( start int , end int , err error ) {
	start = editor.text.offset( node.Line , node.Column )
	line_end := editor.text.lines[ node.Line - 1 ][ 1 ]
	if node.Style & ( yaml.DoubleQuotedStyle | yaml.SingleQuotedStyle ) != 0 {
		if end , err = scanQuotedEnd( editor.text.body , start , line_end ); err != nil {
			err = refuse( path , "a quoted value spread over several lines" )
		}
		return
	}
	end = scanPlainEnd( editor.text.body , start , line_end )
	if strings.TrimSpace( editor.text.body[ start:end ] ) != node.Value {
		err = refuse( path , "a value spread over several lines" )
	}
	return
}

func ( editor *yamlEditor ) apply() ( result []byte , err error ) {
	sort.SliceStable( editor.ops , func( a , b int ) bool {
		if editor.ops[ a ].start != editor.ops[ b ].start {
			return editor.ops[ a ].start > editor.ops[ b ].start
		}
		return editor.ops[ a ].end > editor.ops[ b ].end
	} )
	body := editor.text.body
	limit := len( body ) + 1
	for _ , op := range editor.ops {
		if op.end > limit {
			err = errors.New( "two edits overlap in config.yaml" )
			return
		}
		body = body[ :op.start ] + op.text + body[ op.end: ]
		limit = op.start
		if op.start == op.end {
			// An insertion may share its offset with the next op's end.
			limit = op.start + 1
		}
	}
	if editor.text.bom {
		body = "\uFEFF" + body
	}
	result = []byte( body )
	return
}

// ---------------------------------------------------------------------------
// scanning value text
// ---------------------------------------------------------------------------

// scanQuotedEnd finds the closing quote of a "..." or '...' scalar starting
// at start, on the same line.
func scanQuotedEnd( body string , start int , line_end int ) ( end int , err error ) {
	quote := body[ start ]
	for index := start + 1; index < line_end; index++ {
		switch {
		case quote == '"' && body[ index ] == '\\':
			index++
		case body[ index ] == quote && quote == '\'' && index + 1 < line_end && body[ index + 1 ] == '\'':
			index++
		case body[ index ] == quote:
			end = index + 1
			return
		}
	}
	err = errors.New( "no closing quote on the same line" )
	return
}

// scanPlainEnd is where a plain scalar ends: before a " #" comment, or at
// the end of the line, trailing spaces trimmed.
func scanPlainEnd( body string , start int , line_end int ) ( end int ) {
	end = line_end
	for index := start; index < line_end; index++ {
		if body[ index ] == '#' && index > start && ( body[ index - 1 ] == ' ' || body[ index - 1 ] == '\t' ) {
			end = index
			break
		}
	}
	for end > start && ( body[ end - 1 ] == ' ' || body[ end - 1 ] == '\t' ) {
		end--
	}
	return
}

// scanFlowEnd finds the "]" that closes the "[" at start, skipping quoted
// strings and comments; a flow list may run over several lines.
func scanFlowEnd( body string , start int ) ( end int , err error ) {
	depth := 0
	for index := start; index < len( body ); index++ {
		switch character := body[ index ]; {
		case character == '"' || character == '\'':
			line_end := strings.IndexByte( body[ index: ] , '\n' )
			if line_end < 0 {
				line_end = len( body ) - index
			}
			closing , scan_err := scanQuotedEnd( body , index , index + line_end )
			if scan_err != nil {
				err = scan_err
				return
			}
			index = closing - 1
		case character == '#' && index > start && ( body[ index - 1 ] == ' ' || body[ index - 1 ] == '\t' || body[ index - 1 ] == '\n' ):
			for index < len( body ) && body[ index ] != '\n' {
				index++
			}
		case character == '[' || character == '{':
			depth++
		case character == ']' || character == '}':
			depth--
			if depth == 0 {
				end = index + 1
				return
			}
		}
	}
	err = errors.New( "a [list] with no closing bracket" )
	return
}

// ---------------------------------------------------------------------------
// writing values
// ---------------------------------------------------------------------------

// plainPattern is what may be written without quotes: enough for addresses
// (127.0.0.1, 10.0.0.0/8), paths (./static), names and os/arch pairs, and
// nothing YAML would read as anything but a string. See plainSafe.
var (
	plainPattern   = regexp.MustCompile( `^[A-Za-z0-9_./][A-Za-z0-9_./-]*$` )
	numericPattern = regexp.MustCompile( `^[-+]?(\.?[0-9][0-9_]*)(\.[0-9_]*)?([eE][-+]?[0-9]+)?$` )
	yamlWords      = map[string]bool{
		"y": true , "yes": true , "n": true , "no": true , "on": true , "off": true ,
		"true": true , "false": true , "null": true , "~": true ,
	}
)

// plainSafe is true when value can be written bare and read back as the same
// string by both YAML 1.1 and 1.2 parsers -- so "yes", "1.5", "0x1F" and
// ".inf" are quoted even though some parsers would leave them alone.
func plainSafe( value string ) ( result bool ) {
	if plainPattern.MatchString( value ) == false || yamlWords[ strings.ToLower( value ) ] || numericPattern.MatchString( value ) {
		return
	}
	var check map[string]any
	if yaml.Unmarshal( []byte( "v: " + value ) , &check ) != nil {
		return
	}
	text , is_string := check[ "v" ].( string )
	result = is_string && text == value
	return
}

// encodeString keeps the value's original quoting where that is still safe:
// single quotes stay single, double stay double, bare stays bare when it can.
func encodeString( value string , style yaml.Style ) ( encoded string ) {
	switch {
	case style & yaml.SingleQuotedStyle != 0 && strings.IndexFunc( value , func( r rune ) bool { return r < 0x20 || r == 0x7f } ) < 0:
		encoded = "'" + strings.ReplaceAll( value , "'" , "''" ) + "'"
	case style & yaml.DoubleQuotedStyle == 0 && plainSafe( value ):
		encoded = value
	default:
		// Go's quoting escapes are all valid YAML double-quoted escapes.
		encoded = strconv.Quote( value )
	}
	return
}

func encodeScalar( value any , style yaml.Style ) ( encoded string , err error ) {
	switch typed := value.( type ) {
	case bool:
		encoded = strconv.FormatBool( typed )
	case int:
		encoded = strconv.Itoa( typed )
	case string:
		encoded = encodeString( typed , style )
	default:
		err = fmt.Errorf( "cannot write a %T" , value )
	}
	return
}

func encodeFlowList( items []string ) ( encoded string ) {
	parts := make( []string , 0 , len( items ) )
	for _ , item := range items {
		parts = append( parts , encodeString( item , 0 ) )
	}
	encoded = "[" + strings.Join( parts , ", " ) + "]"
	return
}
