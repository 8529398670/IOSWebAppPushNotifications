package control

import (
	os "os"
	filepath "path/filepath"
	strings "strings"
	testing "testing"
)

// The socket has no credential, so this directory is all that guards it in
// the container. Every case here is something that could be waiting in /tmp.
func TestPrivateDir( t *testing.T ) {
	t.Run( "made when missing" , func( t *testing.T ) {
		dir := filepath.Join( t.TempDir() , "control" )
		if err := privateDir( dir ); err != nil { t.Fatal( err ) }
		info , err := os.Lstat( dir )
		if err != nil { t.Fatal( err ) }
		if info.Mode().Perm() != 0o700 { t.Fatalf( "mode %v, want 0700" , info.Mode().Perm() ) }
	} )

	t.Run( "accepted when already private" , func( t *testing.T ) {
		dir := filepath.Join( t.TempDir() , "control" )
		if err := os.Mkdir( dir , 0o700 ); err != nil { t.Fatal( err ) }
		if err := privateDir( dir ); err != nil { t.Fatal( err ) }
	} )

	t.Run( "refused when others can enter" , func( t *testing.T ) {
		dir := filepath.Join( t.TempDir() , "control" )
		if err := os.Mkdir( dir , 0o700 ); err != nil { t.Fatal( err ) }
		if err := os.Chmod( dir , 0o755 ); err != nil { t.Fatal( err ) }
		err := privateDir( dir )
		if err == nil || strings.Contains( err.Error() , "not private" ) == false {
			t.Fatalf( "got %v" , err )
		}
	} )

	t.Run( "refused when a symlink" , func( t *testing.T ) {
		base := t.TempDir()
		target := filepath.Join( base , "target" )
		if err := os.Mkdir( target , 0o700 ); err != nil { t.Fatal( err ) }
		dir := filepath.Join( base , "control" )
		if err := os.Symlink( target , dir ); err != nil { t.Fatal( err ) }
		err := privateDir( dir )
		if err == nil || strings.Contains( err.Error() , "not private" ) == false {
			t.Fatalf( "got %v" , err )
		}
	} )

	t.Run( "refused when a file" , func( t *testing.T ) {
		dir := filepath.Join( t.TempDir() , "control" )
		if err := os.WriteFile( dir , nil , 0o600 ); err != nil { t.Fatal( err ) }
		err := privateDir( dir )
		if err == nil || strings.Contains( err.Error() , "not private" ) == false {
			t.Fatalf( "got %v" , err )
		}
	} )
}
