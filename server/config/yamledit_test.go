package config

import (
	json "encoding/json"
	errors "errors"
	os "os"
	reflect "reflect"
	strings "strings"
	testing "testing"
)

// testdata/yaml_edit_cases.json is shared with the Python template
// (app/tests/yaml_edit_cases.json): both editors must turn the same input
// into the same bytes.
type editCase struct {
	Name    string `json:"name"`
	Input   string `json:"input"`
	Edits   []struct {
		Path  string `json:"path"`
		Value any    `json:"value"`
	} `json:"edits"`
	Deletes []string `json:"deletes"`
	Output  string   `json:"output"`
	Error   bool     `json:"error"`
}

func typedValue( value any ) ( typed any ) {
	switch raw := value.( type ) {
	case float64:
		typed = int( raw )
	case []any:
		items := []string{}
		for _ , item := range raw {
			items = append( items , item.( string ) )
		}
		typed = items
	default:
		typed = raw
	}
	return
}

func TestEditYAMLCases( t *testing.T ) {
	useTestDefaults( t )
	raw , err := os.ReadFile( "testdata/yaml_edit_cases.json" )
	if err != nil { t.Fatal( err ) }
	var cases []editCase
	if err = json.Unmarshal( raw , &cases ); err != nil { t.Fatal( err ) }
	for _ , test := range cases {
		t.Run( test.Name , func( t *testing.T ) {
			var edits []Edit
			for _ , edit := range test.Edits {
				edits = append( edits , Edit{ Path: edit.Path , Value: typedValue( edit.Value ) } )
			}
			result , err := EditYAML( []byte( test.Input ) , edits , test.Deletes , nil )
			if test.Error {
				if err == nil {
					t.Fatalf( "expected a refusal, got %q" , result )
				}
				if errors.Is( err , ErrHandEdit ) == false {
					t.Fatalf( "refusal does not wrap ErrHandEdit: %v" , err )
				}
				return
			}
			if err != nil { t.Fatal( err ) }
			if string( result ) != test.Output {
				t.Fatalf( "got:\n%q\nwant:\n%q" , result , test.Output )
			}
		} )
	}
}

// Every key in the schema, set to a different valid value in a copy of
// defaults.yaml, must read back as that value with every other key as it was
// -- and every comment line must survive.
func TestEditYAMLEveryKeyRoundTrip( t *testing.T ) {
	useTestDefaults( t )
	sections , err := Schema()
	if err != nil { t.Fatal( err ) }
	for _ , section := range sections {
		for _ , key := range section.Keys {
			value := sampleValue( key )
			changes := map[string]any{ key.Path: value }
			if key.Path == "server.trust_proxy" {
				// Validate refuses one without the other.
				changes[ "server.trusted_proxies" ] = []string{ "127.0.0.1" }
			}
			edited , _ , err := EditChanges( defaultsYAML , changes , "defaults.yaml" , false )
			if err != nil {
				t.Fatalf( "%s: %v" , key.Path , err )
			}
			after , err := Parse( edited , "edited" )
			if err != nil {
				t.Fatalf( "%s: %v" , key.Path , err )
			}
			if got := Flatten( after )[ key.Path ]; reflect.DeepEqual( got , value ) == false {
				t.Fatalf( "%s: got %#v, want %#v" , key.Path , got , value )
			}
			if comments( edited ) != comments( defaultsYAML ) {
				t.Fatalf( "%s: comments changed" , key.Path )
			}
		}
	}
}

func comments( raw []byte ) ( result string ) {
	var kept []string
	for _ , line := range strings.Split( string( raw ) , "\n" ) {
		if at := strings.Index( line , "#" ); at >= 0 {
			kept = append( kept , line[ at: ] )
		}
	}
	result = strings.Join( kept , "\n" )
	return
}

// sampleValue is a valid value different from the default.
func sampleValue( key KeySchema ) ( value any ) {
	special := map[string]any{
		"server.public_url":      "https://app.example.com",
		"push.vapid_subject":     "mailto:ops@example.com",
		"server.trusted_proxies": []string{ "10.0.0.0/8" },
		"server.proxy_header":    "X-Real-IP",
		"server.maintenance":     "read_only",
		"server.host":            "0.0.0.0",
		"server.port":            9999,
		"logs.max_file_mb":       10,
		"docker.image":           "other-image",
		"docker.container":       "other-container",
		"docker.bind_address":    "0.0.0.0",
		"docker.restart":         "always",
		"docker.memory":          "512m",
		"docker.cpus":            "2",
		"docker.tmpfs_size":      "32m",
		"build.binary_name":      "other",
		"build.targets":          []string{ "linux/amd64" },
	}
	if special_value , found := special[ key.Path ]; found {
		value = special_value
		return
	}
	switch key.Type {
	case "bool":
		value = key.Default.( bool ) == false
	case "int":
		value = key.Default.( int ) + 1
	case "string":
		value = key.Default.( string ) + "-changed"
	case "list":
		value = []string{ "x" }
	}
	return
}
