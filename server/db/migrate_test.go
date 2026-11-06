package db

import (
	errors "errors"
	os "os"
	filepath "path/filepath"
	strings "strings"
	testing "testing"

	config "ipb/server/config"
	encryption "ipb/server/encryption"
)

// What these pin down: a database built before versions existed upgrades, a
// failed step changes nothing and is tried again, a newer database is refused,
// and a new one skips the steps entirely.

func migrationConfig( t *testing.T ) ( cfg *config.Config ) {
	t.Helper()
	cfg = &config.Config{
		DatabasePath:  filepath.Join( t.TempDir() , "app.db" ),
		SecretKey:     encryption.GenerateKeyHex(),
		EncryptAtRest: true,
	}
	return
}

type legacyUser struct {
	Name string `json:"name"`
}

type splitUser struct {
	First string `json:"first"`
	Last  string `json:"last"`
}

var splitName = Migration{
	Name: "split name",
	Up: func( tx *Tx ) ( err error ) {
		err = tx.EachRecord( BucketUsers , func( key []byte , record map[string]any ) ( changed bool , each_err error ) {
			first , last , _ := strings.Cut( record[ "name" ].( string ) , " " )
			delete( record , "name" )
			record[ "first" ] , record[ "last" ] = first , last
			changed = true
			return
		} )
		return
	},
}

// oldDatabase writes a database at version 0 holding one old-shaped user.
func oldDatabase( t *testing.T , cfg *config.Config ) {
	t.Helper()
	store , err := openWith( cfg , nil )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	if err := store.Put( BucketUsers , []byte( "1" ) , legacyUser{ Name: "Ada Lovelace" } ); err != nil { t.Fatal( err ) }
}

func kept( t *testing.T , cfg *config.Config ) ( names []string ) {
	t.Helper()
	found , err := filepath.Glob( cfg.DatabasePath + ".before-migration-*" )
	if err != nil { t.Fatal( err ) }
	names = found
	return
}

func TestAnOldDatabaseUpgradesAndIsKept( t *testing.T ) {
	cfg := migrationConfig( t )
	oldDatabase( t , cfg )

	store , err := openWith( cfg , []Migration{ splitName } )
	if err != nil { t.Fatal( err ) }
	version , _ := store.SchemaVersion()
	if version != 1 { t.Fatalf( "version %d" , version ) }
	user := splitUser{}
	if err := store.Get( BucketUsers , []byte( "1" ) , &user ); err != nil { t.Fatal( err ) }
	if user.First != "Ada" || user.Last != "Lovelace" { t.Fatalf( "migrated to %+v" , user ) }
	store.Close()

	saved := kept( t , cfg )
	if len( saved ) != 1 || strings.Contains( saved[ 0 ] , "-v0-" ) == false { t.Fatalf( "kept %v" , saved ) }
	if err := CheckFile( saved[ 0 ] , cfg.SecretKey , true ); err != nil { t.Fatalf( "the kept copy does not read: %v" , err ) }

	// Already there: nothing runs, nothing more is kept.
	store , err = openWith( cfg , []Migration{ { Name: "split name" , Up: func( *Tx ) error { t.Fatal( "ran twice" ); return nil } } } )
	if err != nil { t.Fatal( err ) }
	store.Close()
	if len( kept( t , cfg ) ) != 1 { t.Fatal( "a copy was kept with nothing to do" ) }
}

func TestAFailedStepChangesNothingAndIsTriedAgain( t *testing.T ) {
	cfg := migrationConfig( t )
	oldDatabase( t , cfg )
	broken := Migration{
		Name: "breaks half way",
		Up: func( tx *Tx ) ( err error ) {
			if err = tx.Put( BucketUsers , []byte( "2" ) , legacyUser{ Name: "Should not survive" } ); err != nil { return }
			err = errors.New( "something went wrong" )
			return
		},
	}
	second := Migration{ Name: "never reached" , Up: func( *Tx ) error { t.Fatal( "ran past a failure" ); return nil } }
	if _ , err := openWith( cfg , []Migration{ splitName , broken , second } ); err == nil || strings.Contains( err.Error() , "breaks half way" ) == false {
		t.Fatalf( "failed migration: %v" , err )
	}

	// The step before it stands, and the one that failed left no trace.
	store , err := openWith( cfg , []Migration{ splitName } )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	version , _ := store.SchemaVersion()
	if version != 1 { t.Fatalf( "version %d after a failure at step 2" , version ) }
	if err := store.Get( BucketUsers , []byte( "2" ) , &legacyUser{} ); errors.Is( err , ErrNotFound ) == false {
		t.Fatalf( "half a migration survived: %v" , err )
	}
}

func TestANewerDatabaseIsRefused( t *testing.T ) {
	cfg := migrationConfig( t )
	store , err := openWith( cfg , []Migration{ splitName , splitName } )
	if err != nil { t.Fatal( err ) }
	store.Close()
	if _ , err := openWith( cfg , []Migration{ splitName } ); err == nil || strings.Contains( err.Error() , "newer" ) == false {
		t.Fatalf( "newer database: %v" , err )
	}
}

func TestANewDatabaseIsStampedWithoutRunningAnything( t *testing.T ) {
	cfg := migrationConfig( t )
	store , err := openWith( cfg , []Migration{ { Name: "must not run" , Up: func( *Tx ) error { t.Fatal( "ran on a new database" ); return nil } } } )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	if version , _ := store.SchemaVersion(); version != 1 { t.Fatalf( "version %d" , version ) }
	if len( kept( t , cfg ) ) != 0 { t.Fatal( "a new database was copied" ) }
}

// A database from before versions existed has no version at all, and with no
// migrations shipped it must open exactly as it always did.
func TestNoMigrationsChangesNothingForADeployedDatabase( t *testing.T ) {
	cfg := migrationConfig( t )
	oldDatabase( t , cfg )
	store , err := Open( cfg )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	if len( kept( t , cfg ) ) != 0 { t.Fatal( "a copy was made with nothing to migrate" ) }
	if _ , err := os.Stat( cfg.DatabasePath ); err != nil { t.Fatal( err ) }
}

// The version bucket is raw, so the checks that decode every record must
// leave it alone.
func TestTheVersionSurvivesARekey( t *testing.T ) {
	cfg := migrationConfig( t )
	store , err := openWith( cfg , []Migration{ splitName } )
	if err != nil { t.Fatal( err ) }
	store.Put( BucketUsers , []byte( "1" ) , splitUser{ First: "Ada" } )
	store.Close()
	if err := CheckFile( cfg.DatabasePath , cfg.SecretKey , true ); err != nil { t.Fatal( err ) }

	new_key := encryption.GenerateKeyHex()
	same := func( _ string , plain []byte ) ( []byte , error ) { return plain , nil }
	if err := Rekey( cfg.DatabasePath , cfg.SecretKey , new_key , true , same ); err != nil { t.Fatal( err ) }
	cfg.SecretKey = new_key
	store , err = openWith( cfg , []Migration{ splitName } )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	if version , _ := store.SchemaVersion(); version != 1 { t.Fatalf( "version %d" , version ) }
}
