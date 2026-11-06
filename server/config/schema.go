package config

// The schema: every key config.yaml can hold, in defaults.yaml's order, with
// its type, default, help and apply mode. The Settings screen is built from
// it, and Holder.Save checks submitted values against it.
//
// None of it is written down twice. The keys and types come from the File
// struct, the defaults and the order from defaults.yaml, and the help and
// apply mode from defaults.yaml's comments -- so the text a person reads in
// config.yaml is the text the Settings screen shows, and the tag that says a
// key applies live is the one the server acts on.
//
// Apply modes are tags in those comments:
//
//	[live]     the running server picks it up (see liveConfig)
//	[restart]  saved, but only read at startup
//	[scripts]  read by docker/run.sh or scripts/build.sh, never the server
//
// A tag at the end of a key's line wins; then one in the comment above the
// key (or above the run of keys it belongs to); then one in the comment
// above its section. An untagged key is treated as [restart], the safe
// answer, and schema_test.go fails until it is tagged.

import (
	json "encoding/json"
	fmt "fmt"
	reflect "reflect"
	regexp "regexp"
	strconv "strconv"
	strings "strings"
	sync "sync"

	yaml "gopkg.in/yaml.v3"
)

const (
	ModeLive    = "live"
	ModeRestart = "restart"
	ModeScripts = "scripts"
)

// KeySchema describes one setting.
type KeySchema struct {
	Path    string // "server.port"
	Section string
	Name    string
	Type    string // bool, int, string or list
	Default any
	Help    string
	Mode    string
	// Tagged is false when no comment gave Mode and it fell back to restart.
	Tagged bool

	// The raw comment lines above the key in defaults.yaml and the comment at
	// the end of its line, for EditYAML when it adds the key to a file.
	commentAbove  []string
	commentInline string
}

// SectionSchema is one top-level section and its keys.
type SectionSchema struct {
	Name string
	Help string
	Keys []KeySchema
}

var (
	schemaOnce     sync.Once
	schemaSections []SectionSchema
	schemaByPath   map[string]KeySchema
	schemaErr      error

	tagPattern = regexp.MustCompile( `\[(live|restart|scripts)\]` )
)

// Schema is worked out once, from the embedded defaults.
func Schema() ( sections []SectionSchema , err error ) {
	schemaOnce.Do( func() {
		schemaSections , schemaErr = buildSchema( defaultsYAML )
		schemaByPath = map[string]KeySchema{}
		for _ , section := range schemaSections {
			for _ , key := range section.Keys {
				schemaByPath[ key.Path ] = key
			}
		}
	} )
	sections , err = schemaSections , schemaErr
	return
}

// SchemaKey looks one key up.
func SchemaKey( path string ) ( key KeySchema , found bool , err error ) {
	if _ , err = Schema(); err != nil { return }
	key , found = schemaByPath[ path ]
	return
}

// schemaComments is EditYAML's CommentsFunc: what defaults.yaml says about a
// key, so a key added to a sparse config.yaml arrives documented.
func schemaComments( path string ) ( above []string , inline string ) {
	if key , found , _ := SchemaKey( path ); found {
		above , inline = key.commentAbove , key.commentInline
	}
	return
}

func buildSchema( raw []byte ) ( sections []SectionSchema , err error ) {
	defaults , err := Defaults()
	if err != nil { return }
	values := Flatten( defaults )
	types := fieldTypes()

	text := newYAMLText( raw )
	var doc yaml.Node
	if err = yaml.Unmarshal( []byte( text.body ) , &doc ); err != nil { return }
	if len( doc.Content ) == 0 || doc.Content[ 0 ].Kind != yaml.MappingNode {
		err = fmt.Errorf( "defaults.yaml must be a mapping of sections" )
		return
	}
	root := doc.Content[ 0 ]
	editor := &yamlEditor{ text: text , root: root }

	for index := 0; index + 1 < len( root.Content ); index += 2 {
		section_key , section := root.Content[ index ] , root.Content[ index + 1 ]
		section_comment := commentBlock( text , section_key.Line - 1 , 0 )
		section_tag := findTag( section_comment )
		entry := SectionSchema{ Name: section_key.Value , Help: helpText( section_comment , "" ) }

		for key_index := 0; key_index + 1 < len( section.Content ); key_index += 2 {
			key_node , value_node := section.Content[ key_index ] , section.Content[ key_index + 1 ]
			path := section_key.Value + "." + key_node.Value
			kind , known := types[ path ]
			if known == false {
				err = fmt.Errorf( "defaults.yaml has %s, which config.go's File does not" , path )
				return
			}

			own := commentBlock( text , key_node.Line - 1 , section_key.Line )
			paragraph := own
			if len( paragraph ) == 0 {
				// A key in a run of keys under one comment shares it.
				above := key_node.Line - 1
				for above > section_key.Line && isContentLine( text.line( above ) ) {
					above--
				}
				paragraph = commentBlock( text , above , section_key.Line )
			}
			inline := ""
			if colon , colon_err := editor.colonEnd( path , key_node ); colon_err == nil {
				rest := text.body[ colon:text.lines[ key_node.Line - 1 ][ 1 ] ]
				if value_node.Kind == yaml.ScalarNode && value_node.Line == key_node.Line {
					if _ , end , span_err := editor.scalarSpan( path , value_node ); span_err == nil {
						rest = text.body[ end:text.lines[ key_node.Line - 1 ][ 1 ] ]
					}
				} else if value_node.Kind == yaml.SequenceNode && value_node.Style & yaml.FlowStyle != 0 {
					start := text.offset( value_node.Line , value_node.Column )
					if end , scan_err := scanFlowEnd( text.body , start ); scan_err == nil && end <= text.lines[ key_node.Line - 1 ][ 1 ] {
						rest = text.body[ end:text.lines[ key_node.Line - 1 ][ 1 ] ]
					}
				}
				if at := strings.Index( rest , "#" ); at >= 0 {
					inline = strings.TrimSpace( rest[ at: ] )
				}
			}

			mode := findTag( []string{ inline } )
			if mode == "" {
				mode = findTag( paragraph )
			}
			if mode == "" {
				mode = section_tag
			}
			key := KeySchema{
				Path:          path,
				Section:       section_key.Value,
				Name:          key_node.Value,
				Type:          kind,
				Default:       values[ path ],
				Help:          helpText( paragraph , inline ),
				Mode:          mode,
				Tagged:        mode != "",
				commentAbove:  own,
				commentInline: inline,
			}
			if key.Mode == "" {
				key.Mode = ModeRestart
			}
			entry.Keys = append( entry.Keys , key )
		}
		sections = append( sections , entry )
	}
	return
}

func isContentLine( line string ) ( result bool ) {
	trimmed := strings.TrimSpace( line )
	result = trimmed != "" && strings.HasPrefix( trimmed , "#" ) == false
	return
}

// commentBlock is the run of comment lines ending at line `last`, going up
// no further than line `floor` (exclusive). Trimmed, "#" kept.
func commentBlock( text *yamlText , last int , floor int ) ( block []string ) {
	first := last
	for first > floor && strings.HasPrefix( strings.TrimSpace( text.line( first ) ) , "#" ) {
		first--
	}
	for number := first + 1; number <= last; number++ {
		block = append( block , strings.TrimSpace( text.line( number ) ) )
	}
	return
}

func findTag( lines []string ) ( mode string ) {
	for _ , line := range lines {
		if match := tagPattern.FindStringSubmatch( line ); match != nil {
			mode = match[ 1 ]
			return
		}
	}
	return
}

// helpText turns comment lines into what the Settings screen shows: "#" and
// tags removed, and the lines of each paragraph joined, since they were only
// wrapped to fit the file. An indented line (an example) keeps a line of its
// own, and the comment at the end of the key's line goes last, on its own.
func helpText( lines []string , inline string ) ( help string ) {
	var out []string
	for _ , line := range lines {
		line = strings.TrimPrefix( strings.TrimPrefix( line , "#" ) , " " )
		line = strings.TrimRight( tagPattern.ReplaceAllString( line , "" ) , " " )
		last := len( out ) - 1
		switch {
		case strings.TrimSpace( line ) == "":
			out = append( out , "" )
		case last < 0 || out[ last ] == "" || strings.HasPrefix( line , " " ) || strings.HasPrefix( out[ last ] , " " ):
			out = append( out , line )
		default:
			out[ last ] += " " + line
		}
	}
	inline = strings.TrimSpace( tagPattern.ReplaceAllString( strings.TrimPrefix( inline , "#" ) , "" ) )
	if inline != "" {
		out = append( out , inline )
	}
	help = strings.Trim( strings.Join( out , "\n" ) , "\n " )
	for strings.Contains( help , "\n\n\n" ) {
		help = strings.ReplaceAll( help , "\n\n\n" , "\n\n" )
	}
	return
}

// ---------------------------------------------------------------------------
// values
// ---------------------------------------------------------------------------

// walkFile visits every key File holds, in struct order, with its value.
// server.secret_key is left out everywhere: it is not a setting any more,
// only something to migrate.
func walkFile( file *File , visit func( path string , field reflect.Value ) ) {
	file_value := reflect.ValueOf( file ).Elem()
	file_type := file_value.Type()
	for index := 0; index < file_type.NumField(); index++ {
		section_name := yamlName( file_type.Field( index ) )
		section := file_value.Field( index )
		section_type := section.Type()
		for key_index := 0; key_index < section_type.NumField(); key_index++ {
			path := section_name + "." + yamlName( section_type.Field( key_index ) )
			if path == "server.secret_key" { continue }
			visit( path , section.Field( key_index ) )
		}
	}
}

func yamlName( field reflect.StructField ) ( name string ) {
	name , _ , _ = strings.Cut( field.Tag.Get( "yaml" ) , "," )
	return
}

func fieldTypes() ( types map[string]string ) {
	types = map[string]string{}
	walkFile( &File{} , func( path string , field reflect.Value ) {
		switch field.Kind() {
		case reflect.Bool:
			types[ path ] = "bool"
		case reflect.Int:
			types[ path ] = "int"
		case reflect.String:
			types[ path ] = "string"
		case reflect.Slice:
			types[ path ] = "list"
		}
	} )
	return
}

// Flatten is a File as "section.key" -> value: bool, int, string or
// []string (never nil, so an empty list compares and encodes as []).
func Flatten( file *File ) ( values map[string]any ) {
	values = map[string]any{}
	walkFile( file , func( path string , field reflect.Value ) {
		if field.Kind() == reflect.Slice {
			items := append( []string{} , field.Interface().( []string )... )
			values[ path ] = items
			return
		}
		values[ path ] = field.Interface()
	} )
	return
}

// Change is one key that differs between two Files.
type Change struct {
	Key  string `json:"key"`
	Old  any    `json:"old"`
	New  any    `json:"new"`
	Mode string `json:"apply"`
}

// Diff lists what changed from old to next, in schema order.
func Diff( old *File , next *File ) ( changes []Change ) {
	sections , _ := Schema()
	before , after := Flatten( old ) , Flatten( next )
	for _ , section := range sections {
		for _ , key := range section.Keys {
			if reflect.DeepEqual( before[ key.Path ] , after[ key.Path ] ) { continue }
			changes = append( changes , Change{ Key: key.Path , Old: before[ key.Path ] , New: after[ key.Path ] , Mode: key.Mode } )
		}
	}
	return
}

// KeysInFile is which keys a config.yaml sets itself, as opposed to leaving
// to defaults.yaml.
func KeysInFile( raw []byte ) ( present map[string]bool ) {
	present = map[string]bool{}
	var doc yaml.Node
	if yaml.Unmarshal( raw , &doc ) != nil || len( doc.Content ) == 0 { return }
	root := doc.Content[ 0 ]
	if root.Kind != yaml.MappingNode { return }
	for index := 0; index + 1 < len( root.Content ); index += 2 {
		section := root.Content[ index + 1 ]
		if section.Kind != yaml.MappingNode { continue }
		for key_index := 0; key_index + 1 < len( section.Content ); key_index += 2 {
			present[ root.Content[ index ].Value + "." + section.Content[ key_index ].Value ] = true
		}
	}
	return
}

// Limits on a submitted value, before Validate has its say. They keep a
// request from writing an enormous config.yaml.
const (
	maxStringLength = 1000
	maxListItems    = 100
)

// Coerce checks a value as decoded from JSON (with json.Decoder.UseNumber)
// against a key's type, and returns it typed the way Flatten types it.
func Coerce( key KeySchema , value any ) ( typed any , err error ) {
	bad := func( want string ) error { return fmt.Errorf( "%s must be %s" , key.Path , want ) }
	switch key.Type {
	case "bool":
		flag , ok := value.( bool )
		if ok == false {
			err = bad( "true or false" )
			return
		}
		typed = flag
	case "int":
		var number int64
		switch raw := value.( type ) {
		case json.Number:
			parsed , parse_err := raw.Int64()
			if parse_err != nil {
				err = bad( "a whole number" )
				return
			}
			number = parsed
		case float64:
			if raw != float64( int64( raw ) ) {
				err = bad( "a whole number" )
				return
			}
			number = int64( raw )
		case int:
			number = int64( raw )
		default:
			err = bad( "a whole number" )
			return
		}
		if number < -1 << 31 || number > 1 << 31 - 1 {
			err = bad( "a whole number in range" )
			return
		}
		typed = int( number )
	case "string":
		text , ok := value.( string )
		if ok == false || len( text ) > maxStringLength {
			err = bad( fmt.Sprintf( "text of at most %d characters" , maxStringLength ) )
			return
		}
		typed = text
	case "list":
		var items []string
		switch raw := value.( type ) {
		case []string:
			items = raw
		case []any:
			for _ , item := range raw {
				text , ok := item.( string )
				if ok == false {
					err = bad( "a list of text" )
					return
				}
				items = append( items , text )
			}
		default:
			err = bad( "a list of text" )
			return
		}
		if len( items ) > maxListItems {
			err = bad( fmt.Sprintf( "a list of at most %d items" , maxListItems ) )
			return
		}
		cleaned := []string{}
		for _ , item := range items {
			if len( item ) > maxStringLength {
				err = bad( fmt.Sprintf( "a list of items of at most %d characters" , maxStringLength ) )
				return
			}
			if item = strings.TrimSpace( item ); item != "" {
				cleaned = append( cleaned , item )
			}
		}
		typed = cleaned
	default:
		err = fmt.Errorf( "%s has unknown type %q" , key.Path , key.Type )
	}
	return
}

// ParseValue reads a value typed on a command line (`config set`): true or
// false, a number, text, or a list written as [a, b] or a,b ("" or [] for
// an empty one).
func ParseValue( key KeySchema , text string ) ( typed any , err error ) {
	switch key.Type {
	case "bool":
		flag , parse_err := strconv.ParseBool( text )
		if parse_err != nil {
			err = fmt.Errorf( "%s must be true or false" , key.Path )
			return
		}
		typed = flag
	case "int":
		number , parse_err := strconv.Atoi( strings.TrimSpace( text ) )
		if parse_err != nil {
			err = fmt.Errorf( "%s must be a whole number" , key.Path )
			return
		}
		typed = number
	case "list":
		trimmed := strings.TrimSpace( text )
		var items []any
		if strings.HasPrefix( trimmed , "[" ) {
			var parsed []string
			if yaml.Unmarshal( []byte( trimmed ) , &parsed ) != nil {
				err = fmt.Errorf( "%s must be a list like [a, b]" , key.Path )
				return
			}
			for _ , item := range parsed {
				items = append( items , item )
			}
		} else if trimmed != "" {
			for _ , item := range strings.Split( trimmed , "," ) {
				items = append( items , item )
			}
		}
		if items == nil {
			items = []any{}
		}
		typed , err = Coerce( key , items )
	default:
		typed , err = Coerce( key , text )
	}
	return
}
