package rotate

import (
	compress "compress/gzip"
	base64 "encoding/base64"
	json "encoding/json"
	errors "errors"
	io "io"
	os "os"
	filepath "path/filepath"
	strings "strings"
	testing "testing"
	time "time"

	backup "ipb/server/backup"
	config "ipb/server/config"
	db "ipb/server/db"
	encryption "ipb/server/encryption"
	logs "ipb/server/logs"
	models "ipb/server/models"
)

// What these pin down: everything the key protects comes through a rotation
// still readable, a failure before the marker changes nothing, and a stop at
// any point after it ends with the key and the data matching.

type deployment struct {
	cfg    *config.Config
	path   string
	userID uint64
	secret string
}

// newDeployment is a real config.yaml and secret.key, so that LoadPath can do
// what it does after a crash, with a database holding a two-factor user and a
// log with one plain day, one gzipped day and a broken line.
func newDeployment( t *testing.T ) ( result *deployment ) {
	t.Helper()
	directory := t.TempDir()
	config.UseEmbedded( defaultsForTest( t ) , nil )
	path := filepath.Join( directory , "config.yaml" )
	if _ , err := config.WriteNew( path ); err != nil { t.Fatal( err ) }
	raw , err := os.ReadFile( path )
	if err != nil { t.Fatal( err ) }
	edited := strings.Replace( string( raw ) , `app_dir: ""` , `app_dir: "` + filepath.Join( directory , "data" ) + `"` , 1 )
	if err := os.WriteFile( path , []byte( edited ) , 0o600 ); err != nil { t.Fatal( err ) }
	cfg , err := config.LoadPath( path , true )
	if err != nil { t.Fatal( err ) }

	store , err := db.Open( cfg )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	user , err := models.CreateUser( store , "Second factor" , models.RoleUser )
	if err != nil { t.Fatal( err ) }
	secret , err := models.StartTwoFactorSetup( store , user.ID , cfg.SecretKey )
	if err != nil { t.Fatal( err ) }

	line := func( text string ) ( encoded string ) {
		sealed , seal_err := encryption.ChaChaEncryptBytes( cfg.SecretKey , []byte( `{"msg":"` + text + `"}` ) )
		if seal_err != nil { t.Fatal( seal_err ) }
		encoded = base64.StdEncoding.EncodeToString( sealed ) + "\n"
		return
	}
	plain_day := line( "plain day" ) + "this line was cut sho"
	if err := os.WriteFile( filepath.Join( cfg.Logs.Dir , "2026-11-01.jsonl" ) , []byte( plain_day ) , 0o600 ); err != nil { t.Fatal( err ) }
	zipped_file , err := os.Create( filepath.Join( cfg.Logs.Dir , "2026-10-31.jsonl.gz" ) )
	if err != nil { t.Fatal( err ) }
	zipped := compress.NewWriter( zipped_file )
	zipped.Write( []byte( line( "gzipped day" ) ) )
	zipped.Close()
	zipped_file.Close()

	result = &deployment{ cfg: cfg , path: path , userID: user.ID , secret: secret }
	return
}

func defaultsForTest( t *testing.T ) ( raw []byte ) {
	t.Helper()
	raw , err := os.ReadFile( filepath.Join( "..", ".." , "config" , "defaults.yaml" ) )
	if err != nil { t.Fatal( err ) }
	return
}

// assertWhole checks the deployment as a fresh process would find it: the key
// on disk opens the database, the two-factor secret and the log.
func ( d *deployment ) assertWhole( t *testing.T ) ( cfg *config.Config ) {
	t.Helper()
	cfg , err := config.LoadPath( d.path , true )
	if err != nil { t.Fatal( err ) }
	store , err := db.Open( cfg )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	user , err := models.GetUser( store , d.userID )
	if err != nil { t.Fatalf( "the key does not open the database: %v" , err ) }
	opened , err := encryption.ChaChaDecryptBase64String( cfg.SecretKey , user.TOTPPending )
	if err != nil || opened != d.secret { t.Fatalf( "two-factor secret: %q %v" , opened , err ) }

	reader := logs.New( cfg.Logs , cfg.SecretKey , cfg.EncryptAtRest )
	for day , wanted := range map[string]string{ "2026-11-01": "plain day" , "2026-10-31": "gzipped day" } {
		records , _ , err := reader.ReadDay( day , logs.ParseQuery( "" ) , -1 , 10 )
		if err != nil { t.Fatal( err ) }
		encoded , _ := json.Marshal( records )
		if len( records ) != 1 || strings.Contains( string( encoded ) , wanted ) == false {
			t.Fatalf( "%s after rotation: %s" , day , encoded )
		}
	}
	if config.RotationPending( cfg.AppDir ) { t.Fatal( "the marker is still there" ) }
	if _ , err := os.Stat( config.RotationDir( cfg.AppDir ) ); err == nil { t.Fatal( "the staging folder is still there" ) }
	return
}

func TestRotationKeepsEverythingReadable( t *testing.T ) {
	d := newDeployment( t )
	old_key := d.cfg.SecretKey
	result , err := Run( d.cfg , Options{} )
	if err != nil { t.Fatal( err ) }
	if result.LogFiles != 2 { t.Fatalf( "log files: %d" , result.LogFiles ) }

	cfg := d.assertWhole( t )
	if cfg.SecretKey == old_key { t.Fatal( "the key did not change" ) }
	if encryption.KeyFingerprint( cfg.SecretKey ) != result.NewFingerprint { t.Fatal( "secret.key is not the key reported" ) }

	retired , err := config.ReadSecret( result.RetiredKey )
	if err != nil || retired != old_key { t.Fatalf( "retired key: %v" , err ) }
	info , err := os.Stat( result.RetiredKey )
	if err != nil || info.Mode().Perm() != 0o600 { t.Fatalf( "retired key mode: %v %v" , info.Mode() , err ) }

	// A line nothing could read stays, rather than being dropped.
	raw , err := os.ReadFile( filepath.Join( cfg.Logs.Dir , "2026-11-01.jsonl" ) )
	if err != nil || strings.HasSuffix( string( raw ) , "this line was cut sho" ) == false { t.Fatalf( "broken line: %q %v" , raw , err ) }
}

// storeFile uploads into the deployment, and assertFile reads it back as a fresh
// process would: the file's bytes never move, so only its sealed key changes.
func ( d *deployment ) storeFile( t *testing.T ) ( file_id string ) {
	t.Helper()
	store , err := db.Open( d.cfg )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	file , err := models.CreateFile( store , d.cfg , d.userID , "a.txt" , "" , 5 )
	if err != nil { t.Fatal( err ) }
	if err = models.WriteFileChunk( store , d.cfg , file , 0 , []byte( "hello" ) ); err != nil { t.Fatal( err ) }
	if file , err = models.GetFile( store , file.ID ); err != nil { t.Fatal( err ) }
	if _ , err = models.FinishFile( store , d.cfg , file ); err != nil { t.Fatal( err ) }
	file_id = file.ID
	return
}

func ( d *deployment ) assertFile( t *testing.T , file_id string ) {
	t.Helper()
	cfg , err := config.LoadPath( d.path , true )
	if err != nil { t.Fatal( err ) }
	store , err := db.Open( cfg )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	file , err := models.GetFile( store , file_id )
	if err != nil { t.Fatal( err ) }
	reader , err := models.OpenFile( cfg , file )
	if err != nil { t.Fatal( err ) }
	defer reader.Close()
	content , err := io.ReadAll( reader )
	if err != nil || string( content ) != "hello" { t.Fatalf( "%q %v" , content , err ) }
}

func TestAFileSurvivesRotationWithRecordEncryptionOnOrOff( t *testing.T ) {
	for _ , encrypted := range []bool{ true , false } {
		d := newDeployment( t )
		if encrypted == false {
			raw , err := os.ReadFile( d.path )
			if err != nil { t.Fatal( err ) }
			edited := strings.Replace( string( raw ) , "encrypt_at_rest: true" , "encrypt_at_rest: false" , 1 )
			if err := os.WriteFile( d.path , []byte( edited ) , 0o600 ); err != nil { t.Fatal( err ) }
			// The database was made with it on: start this one again.
			if err := os.Remove( d.cfg.DatabasePath ); err != nil { t.Fatal( err ) }
			if d.cfg , err = config.LoadPath( d.path , true ); err != nil { t.Fatal( err ) }
			store , err := db.Open( d.cfg )
			if err != nil { t.Fatal( err ) }
			user , err := models.CreateUser( store , "Plain" , models.RoleUser )
			if err != nil { t.Fatal( err ) }
			d.userID = user.ID
			store.Close()
		}
		file_id := d.storeFile( t )
		if _ , err := Run( d.cfg , Options{} ); err != nil { t.Fatal( err ) }
		d.assertFile( t , file_id )
	}
}

func TestAFileSurvivesARestoreOntoANewKey( t *testing.T ) {
	d := newDeployment( t )
	file_id := d.storeFile( t )
	store , err := db.Open( d.cfg )
	if err != nil { t.Fatal( err ) }
	made , err := backup.Create( store , d.cfg , backup.Options{} )
	store.Close()
	if err != nil { t.Fatal( err ) }
	time.Sleep( 1100 * time.Millisecond )
	result , err := Run( d.cfg , Options{} )
	if err != nil { t.Fatal( err ) }
	cfg , err := config.LoadPath( d.path , true )
	if err != nil { t.Fatal( err ) }
	if _ , err = backup.Restore( cfg , backup.RestoreOptions{ From: made.Path , KeyFile: result.RetiredKey } ); err != nil { t.Fatal( err ) }
	d.assertFile( t , file_id )
}

func TestRotationRefusesARunningServer( t *testing.T ) {
	d := newDeployment( t )
	store , err := db.Open( d.cfg )
	if err != nil { t.Fatal( err ) }
	defer store.Close()
	if _ , err := Run( d.cfg , Options{} ); errors.Is( err , ErrServerRunning ) == false {
		t.Fatalf( "with the database open: %v" , err )
	}
}

// A failure while staging leaves the old key working and nothing behind.
func TestAFailureBeforeTheMarkerChangesNothing( t *testing.T ) {
	d := newDeployment( t )
	stolen := *d.cfg
	stolen.SecretKey = encryption.GenerateKeyHex()
	if _ , err := Run( &stolen , Options{} ); err == nil { t.Fatal( "rotated from the wrong key" ) }
	if _ , err := os.Stat( d.cfg.SecretFile + config.SecretNextSuffix ); err == nil { t.Fatal( "a new key was left behind" ) }
	if cfg := d.assertWhole( t ); cfg.SecretKey != d.cfg.SecretKey { t.Fatal( "the key changed" ) }
}

// The real stops: after the marker, at each point in the swap. Whatever a
// crash left, the next load finishes it.
func TestAStopAfterTheMarkerFinishesForward( t *testing.T ) {
	steps := map[string]func( cfg *config.Config ){
		"before any rename": func( *config.Config ) {},
		"after the database only": func( cfg *config.Config ) {
			directory := config.RotationDir( cfg.AppDir )
			os.Rename( filepath.Join( directory , "app.db" ) , cfg.DatabasePath )
		},
		"after one log file": func( cfg *config.Config ) {
			directory := config.RotationDir( cfg.AppDir )
			os.Rename( filepath.Join( directory , "app.db" ) , cfg.DatabasePath )
			os.Rename( filepath.Join( directory , "logs" , "2026-11-01.jsonl" ) , filepath.Join( cfg.Logs.Dir , "2026-11-01.jsonl" ) )
		},
		"after all the data": func( cfg *config.Config ) {
			config.FinishRotationData( cfg.AppDir , cfg.DatabasePath , cfg.Logs.Dir )
		},
		"after the key": func( cfg *config.Config ) {
			config.FinishRotationData( cfg.AppDir , cfg.DatabasePath , cfg.Logs.Dir )
			config.FinishRotationKey( cfg.SecretFile )
		},
	}
	for label , stop := range steps {
		t.Run( label , func( t *testing.T ) {
			d := newDeployment( t )
			new_key := config.GenerateSecret()
			if _ , err := stage( d.cfg , new_key ); err != nil { t.Fatal( err ) }
			if err := config.WriteSecret( d.cfg.SecretFile + config.SecretNextSuffix , new_key ); err != nil { t.Fatal( err ) }
			if err := config.MarkRotation( d.cfg.AppDir ); err != nil { t.Fatal( err ) }
			stop( d.cfg )

			if cfg := d.assertWhole( t ); cfg.SecretKey != new_key { t.Fatal( "did not end on the new key" ) }
		} )
	}
}

// Stopped before the marker, the staged work is thrown away and the old key
// still rules, even with a new key sitting in .next.
func TestAStopBeforeTheMarkerIsForgotten( t *testing.T ) {
	d := newDeployment( t )
	new_key := config.GenerateSecret()
	if _ , err := stage( d.cfg , new_key ); err != nil { t.Fatal( err ) }
	if err := config.WriteSecret( d.cfg.SecretFile + config.SecretNextSuffix , new_key ); err != nil { t.Fatal( err ) }

	cfg , err := config.LoadPath( d.path , true )
	if err != nil { t.Fatal( err ) }
	if cfg.SecretKey != d.cfg.SecretKey { t.Fatal( "an uncommitted key was picked up" ) }

	if _ , err := Run( cfg , Options{} ); err != nil { t.Fatal( err ) }
	d.assertWhole( t )
}

// The container's half: it moves the data, leaves the key to the host, and
// keeps the marker so nothing starts on a mismatch.
func TestTheContainerHalfLeavesTheKeyToTheHost( t *testing.T ) {
	d := newDeployment( t )
	new_key := config.GenerateSecret()
	key_file := filepath.Join( t.TempDir() , "next.key" )
	if err := os.WriteFile( key_file , []byte( new_key + "\n" ) , 0o600 ); err != nil { t.Fatal( err ) }

	if _ , err := Run( d.cfg , Options{ NewKeyFile: key_file } ); err != nil { t.Fatal( err ) }
	if config.RotationPending( d.cfg.AppDir ) == false { t.Fatal( "the marker is gone before the key moved" ) }
	if key , _ := config.ReadSecret( d.cfg.SecretFile ); key != d.cfg.SecretKey { t.Fatal( "the key file was touched" ) }

	// Run again after a stop: it only finishes the data.
	result , err := Run( d.cfg , Options{ NewKeyFile: key_file } )
	if err != nil || result.Resumed == false { t.Fatalf( "resume: %+v %v" , result , err ) }

	// What docker/rotate-key.sh does on the host.
	if err := os.WriteFile( d.cfg.SecretFile , []byte( new_key + "\n" ) , 0o600 ); err != nil { t.Fatal( err ) }
	if err := config.ClearRotation( d.cfg.AppDir ); err != nil { t.Fatal( err ) }
	if cfg := d.assertWhole( t ); cfg.SecretKey != new_key { t.Fatal( "did not end on the new key" ) }

	same := filepath.Join( t.TempDir() , "same.key" )
	os.WriteFile( same , []byte( new_key + "\n" ) , 0o600 )
	loaded , err := config.LoadPath( d.path , true )
	if err != nil { t.Fatal( err ) }
	if _ , err := Run( loaded , Options{ NewKeyFile: same } ); err == nil { t.Fatal( "rotated onto the key already in use" ) }
}

// Every backup from before a rotation still restores, with the retired key.
func TestABackupFromBeforeARotationRestoresWithTheRetiredKey( t *testing.T ) {
	d := newDeployment( t )
	store , err := db.Open( d.cfg )
	if err != nil { t.Fatal( err ) }
	made , err := backup.Create( store , d.cfg , backup.Options{} )
	store.Close()
	if err != nil { t.Fatal( err ) }
	time.Sleep( 1100 * time.Millisecond )

	result , err := Run( d.cfg , Options{} )
	if err != nil { t.Fatal( err ) }
	cfg := d.assertWhole( t )

	if _ , err := backup.Restore( cfg , backup.RestoreOptions{ From: made.Path } ); err == nil { t.Fatal( "restored without the old key" ) }
	restored , err := backup.Restore( cfg , backup.RestoreOptions{ From: made.Path , KeyFile: result.RetiredKey } )
	if err != nil { t.Fatal( err ) }
	if restored.Rekeyed == false { t.Fatal( "not moved onto the current key" ) }
	d.assertWhole( t )
}
