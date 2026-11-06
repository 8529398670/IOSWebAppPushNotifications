package config

import (
	os "os"
	testing "testing"
)

// useTestDefaults registers the project's real defaults.yaml, as main.go's
// init() does for the binary.
func useTestDefaults( t *testing.T ) {
	t.Helper()
	if len( defaultsYAML ) > 0 { return }
	defaults , err := os.ReadFile( "../../config/defaults.yaml" )
	if err != nil { t.Fatal( err ) }
	header , err := os.ReadFile( "../../config/example_header.yaml" )
	if err != nil { t.Fatal( err ) }
	UseEmbedded( defaults , header )
}

// inContainer makes InContainer true for one test, with the image's layout
// pointed at dir.
func inContainer( t *testing.T , config_file string , app_dir string ) {
	t.Helper()
	saved := pinned
	pinned = layout{ ConfigFile: config_file , AppDir: app_dir , Host: "0.0.0.0" }
	t.Cleanup( func() { pinned = saved } )
}
