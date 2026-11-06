package config

import (
	os "os"
	filepath "path/filepath"
	strings "strings"
	testing "testing"
)

const legacyConfig = `server:
  port: 8080
  # Encrypts session cookies and, with encrypt_at_rest, every database value.
  # 64 hex characters. Generated when this file is created.
  secret_key: "%s"
  encrypt_at_rest: true
`

func writeLegacy( t *testing.T , key string ) ( config_path string ) {
	t.Helper()
	dir := t.TempDir()
	config_path = filepath.Join( dir , "config.yaml" )
	if err := os.WriteFile( config_path , []byte( strings.Replace( legacyConfig , "%s" , key , 1 ) ) , 0o600 ); err != nil {
		t.Fatal( err )
	}
	return
}

func TestMigrateMovesTheKey( t *testing.T ) {
	useTestDefaults( t )
	key := GenerateSecret()
	path := writeLegacy( t , key )

	result , err := MigrateLegacySecret( path )
	if err != nil { t.Fatal( err ) }
	if result.Moved == false || result.Removed == false {
		t.Fatalf( "expected moved and removed: %+v" , result )
	}
	written , err := ReadSecret( SecretPathFor( path ) )
	if err != nil || written != key {
		t.Fatalf( "secret.key = %q, %v" , written , err )
	}
	info , _ := os.Stat( SecretPathFor( path ) )
	if info.Mode().Perm() != 0o600 {
		t.Fatalf( "secret.key mode %o" , info.Mode().Perm() )
	}
	after , _ := os.ReadFile( path )
	if strings.Contains( string( after ) , key ) || strings.Contains( string( after ) , "secret_key:" ) {
		t.Fatalf( "key still in config.yaml:\n%s" , after )
	}
	if strings.Contains( string( after ) , "encrypt_at_rest: true" ) == false || strings.Contains( string( after ) , "port: 8080" ) == false {
		t.Fatalf( "other settings lost:\n%s" , after )
	}

	// Running it again does nothing.
	again , err := MigrateLegacySecret( path )
	if err != nil || again.Moved || again.Removed {
		t.Fatalf( "second run: %+v %v" , again , err )
	}
}

func TestMigrateFinishesAnInterruptedMove( t *testing.T ) {
	useTestDefaults( t )
	key := GenerateSecret()
	path := writeLegacy( t , key )
	if err := WriteSecret( SecretPathFor( path ) , key ); err != nil { t.Fatal( err ) }
	result , err := MigrateLegacySecret( path )
	if err != nil || result.Moved || result.Removed == false {
		t.Fatalf( "%+v %v" , result , err )
	}
}

func TestMigrateRefusesTwoDifferentKeys( t *testing.T ) {
	useTestDefaults( t )
	path := writeLegacy( t , GenerateSecret() )
	if err := WriteSecret( SecretPathFor( path ) , GenerateSecret() ); err != nil { t.Fatal( err ) }
	before , _ := os.ReadFile( path )
	if _ , err := MigrateLegacySecret( path ); err == nil || strings.Contains( err.Error() , "different key" ) == false {
		t.Fatalf( "expected a refusal, got %v" , err )
	}
	after , _ := os.ReadFile( path )
	if string( before ) != string( after ) {
		t.Fatal( "config.yaml was changed" )
	}
}

func TestMigrateRefusesAMalformedKey( t *testing.T ) {
	useTestDefaults( t )
	path := writeLegacy( t , "not-a-key" )
	if _ , err := MigrateLegacySecret( path ); err == nil {
		t.Fatal( "expected an error" )
	}
	if isFile( SecretPathFor( path ) ) {
		t.Fatal( "secret.key written from a bad key" )
	}
}

func TestResolveSecretInContainer( t *testing.T ) {
	useTestDefaults( t )
	path := writeLegacy( t , GenerateSecret() )
	inContainer( t , path , t.TempDir() )
	file , err := ReadFile( path )
	if err != nil { t.Fatal( err ) }
	_ , err = resolveSecret( file , path , filepath.Join( t.TempDir() , "app.db" ) )
	if err == nil || strings.Contains( err.Error() , "docker/run.sh" ) == false {
		t.Fatalf( "expected a pointer to docker/run.sh, got %v" , err )
	}
}

func TestFreshInstallGetsAKeyButExistingDataDoesNot( t *testing.T ) {
	useTestDefaults( t )
	dir := t.TempDir()
	path := filepath.Join( dir , "config.yaml" )
	os.WriteFile( path , defaultsYAML , 0o600 )
	file , _ := ReadFile( path )

	database := filepath.Join( dir , "app.db" )
	os.WriteFile( database , []byte( "x" ) , 0o600 )
	if _ , err := resolveSecret( file , path , database ); err == nil || strings.Contains( err.Error() , "Restore secret.key" ) == false {
		t.Fatalf( "expected a refusal, got %v" , err )
	}
	os.Remove( database )
	state , err := resolveSecret( file , path , database )
	if err != nil || state.Created == false || len( state.Key ) != 64 {
		t.Fatalf( "%+v %v" , state , err )
	}
}

func TestDefaultsCarryNoSecret( t *testing.T ) {
	useTestDefaults( t )
	for _ , produce := range []func() ( []byte , error ){ NewFileContent , ExampleFileContent } {
		content , err := produce()
		if err != nil { t.Fatal( err ) }
		if strings.Contains( string( content ) , "secret_key:" ) {
			t.Fatal( "secret_key in generated config" )
		}
	}
}
