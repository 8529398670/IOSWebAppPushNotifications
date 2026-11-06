package config

import (
	reflect "reflect"
	testing "testing"
)

// Every key must say how it applies. An untagged key falls back to restart,
// which is safe, but it is a decision nobody made.
func TestEveryKeyIsTagged( t *testing.T ) {
	useTestDefaults( t )
	sections , err := Schema()
	if err != nil { t.Fatal( err ) }
	seen := map[string]bool{}
	for _ , section := range sections {
		for _ , key := range section.Keys {
			seen[ key.Path ] = true
			if key.Tagged == false {
				t.Errorf( "%s has no [live], [restart] or [scripts] tag in defaults.yaml" , key.Path )
			}
		}
	}
	for path := range fieldTypes() {
		if seen[ path ] == false {
			t.Errorf( "%s is in File but not in defaults.yaml" , path )
		}
	}
}

// The tags and liveConfig must agree: changing a [live] key changes the
// running Config, and changing any other key does not. A new live key that
// liveConfig forgets to copy fails here.
func TestLiveTagsMatchLiveConfig( t *testing.T ) {
	useTestDefaults( t )
	defaults , err := Defaults()
	if err != nil { t.Fatal( err ) }
	paths := ResolvePaths( defaults , "/project/config/config.yaml" )
	boot := build( defaults , "/project/config/config.yaml" , paths , GenerateSecret() )

	sections , _ := Schema()
	for _ , section := range sections {
		for _ , key := range section.Keys {
			changes := map[string]any{ key.Path: sampleValue( key ) }
			if key.Path == "server.trust_proxy" {
				changes[ "server.trusted_proxies" ] = []string{ "127.0.0.1" }
			}
			edited , _ , err := EditChanges( defaultsYAML , changes , "defaults.yaml" , false )
			if err != nil { t.Fatalf( "%s: %v" , key.Path , err ) }
			file , err := Parse( edited , "edited" )
			if err != nil { t.Fatalf( "%s: %v" , key.Path , err ) }

			next := liveConfig( boot , defaults , file )
			next.file = boot.file
			changed := reflect.DeepEqual( next , boot ) == false
			if key.Mode == ModeLive && changed == false {
				t.Errorf( "%s is tagged [live] but liveConfig does not apply it" , key.Path )
			}
			if key.Mode != ModeLive && changed {
				t.Errorf( "%s is tagged [%s] but liveConfig applies it" , key.Path , key.Mode )
			}
		}
	}
}

func TestSchemaHelpComesFromComments( t *testing.T ) {
	useTestDefaults( t )
	key , found , err := SchemaKey( "server.language_file" )
	if err != nil || found == false { t.Fatal( "server.language_file missing" , err ) }
	if key.Help == "" || key.Mode != ModeRestart {
		t.Fatalf( "language_file should share static_dir's comment: %+v" , key )
	}
	key , _ , _ = SchemaKey( "server.rate_limit_max" )
	if key.Mode != ModeLive {
		t.Fatalf( "rate_limit_max: the tag on its own line wins, got %s" , key.Mode )
	}
	key , _ , _ = SchemaKey( "docker.memory" )
	if key.Mode != ModeScripts {
		t.Fatalf( "docker.memory: the section tag applies, got %s" , key.Mode )
	}
	if _ , found , _ = SchemaKey( "server.secret_key" ); found {
		t.Fatal( "server.secret_key must not be a setting" )
	}
}
