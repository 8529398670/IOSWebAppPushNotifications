// Package rotate moves a deployment to a new secret key.
//
// The key does four jobs, and each needs something different:
//
//	database records   re-encrypted here (with server.encrypt_at_rest on)
//	two-factor secrets encrypted a second time inside the user record, so
//	                   re-encrypted here too, always: see models.RekeyRecord
//	activity log       every line is encrypted, gzipped days included, so each
//	                   file is rewritten
//	session cookies    sealed with the key and held by browsers, so they stop
//	                   working: everyone signs in again
//
// Backups are not touched. Each one keeps the key it was made with, which is
// why the old key is kept as secret.key.retired-<time>: `manage restore
// -key-file` reads an old backup with it.
//
// # Why it cannot break half way
//
// The data and secret.key cannot change at the same instant, so everything is
// staged and proved first, in <app_dir>/.rotate, while the live files stay as
// they are. Failing there changes nothing. Then one marker file decides it, and
// the rest is renames that anything can repeat: the next `manage` command or
// server start finishes the job before it reads the key (see
// config.MarkRotation). So at every moment there is one way forward, and the
// key and the data end up matching.
//
// The server has to be stopped, because it holds the old key in memory and
// would go on writing with it.
package rotate

import (
	errors "errors"
	fmt "fmt"
	io "io"
	os "os"
	filepath "path/filepath"

	config "ipb/server/config"
	db "ipb/server/db"
	encryption "ipb/server/encryption"
	logs "ipb/server/logs"
	models "ipb/server/models"
)

// ErrServerRunning is a rotation refused because a server holds the database.
var ErrServerRunning = errors.New( "the server is running -- stop it first, it holds the old key in memory and would go on writing with it" )

// Options says where the new key comes from. Empty means make one here.
//
// NewKeyFile is for the container, where secret.key is a read-only mount:
// docker/rotate-key.sh writes the new key on the host and passes it in, this
// moves the data onto it, and the script swaps the key file itself.
type Options struct {
	NewKeyFile string
}

// Result says what happened.
type Result struct {
	// Resumed is true when this only finished a rotation already decided.
	Resumed        bool
	RetiredKey     string
	OldFingerprint string
	NewFingerprint string
	LogFiles       int
}

// Run rotates the key.
func Run( cfg *config.Config , options Options ) ( result Result , err error ) {
	if err = ensureStopped( cfg ); err != nil { return }

	// Only the container gets here with a marker: everywhere else, loading
	// the config already finished the job.
	if config.RotationPending( cfg.AppDir ) {
		err = config.FinishRotationData( cfg.AppDir , cfg.DatabasePath , cfg.Logs.Dir )
		result.Resumed = true
		return
	}

	new_key , err := chooseKey( cfg , options )
	if err != nil { return }
	result.OldFingerprint = encryption.KeyFingerprint( cfg.SecretKey )
	result.NewFingerprint = encryption.KeyFingerprint( new_key )

	if result.LogFiles , err = stage( cfg , new_key ); err != nil {
		os.RemoveAll( config.RotationDir( cfg.AppDir ) )
		return
	}

	// Staging can take a while, and a server started in the meantime would
	// be writing to the file about to be replaced.
	if err = ensureStopped( cfg ); err != nil {
		os.RemoveAll( config.RotationDir( cfg.AppDir ) )
		return
	}

	next := cfg.SecretFile + config.SecretNextSuffix
	if options.NewKeyFile == "" {
		// A .next with no marker is left from a run that never committed.
		os.Remove( next )
		if err = config.WriteSecret( next , new_key ); err != nil { return }
	}

	if err = config.MarkRotation( cfg.AppDir ); err != nil { return }
	if err = config.FinishRotationData( cfg.AppDir , cfg.DatabasePath , cfg.Logs.Dir ); err != nil { return }

	if options.NewKeyFile != "" { return }
	if result.RetiredKey , err = config.FinishRotationKey( cfg.SecretFile ); err != nil { return }
	err = config.ClearRotation( cfg.AppDir )
	return
}

func chooseKey( cfg *config.Config , options Options ) ( key string , err error ) {
	if options.NewKeyFile == "" {
		if config.InContainer() {
			err = errors.New( "secret.key is read-only in here -- run docker/rotate-key.sh on the host" )
			return
		}
		key = config.GenerateSecret()
		return
	}
	if key , err = config.ReadSecret( options.NewKeyFile ); err != nil { return }
	if key == cfg.SecretKey {
		err = errors.New( "the new key is the key already in use" )
	}
	return
}

// stage does everything that can fail, on copies. Nothing live is touched.
func stage( cfg *config.Config , new_key string ) ( log_files int , err error ) {
	directory := config.RotationDir( cfg.AppDir )
	if err = os.RemoveAll( directory ); err != nil { return }
	if err = os.MkdirAll( directory , 0o700 ); err != nil { return }

	if _ , stat_err := os.Stat( cfg.DatabasePath ); stat_err == nil {
		staged := filepath.Join( directory , filepath.Base( cfg.DatabasePath ) )
		if err = copyFile( cfg.DatabasePath , staged ); err != nil { return }
		rewrite := models.RekeyRecord( cfg.SecretKey , new_key )
		if err = db.Rekey( staged , cfg.SecretKey , new_key , cfg.EncryptAtRest , rewrite ); err != nil {
			err = fmt.Errorf( "nothing was changed: %w" , err )
			return
		}
		if err = db.CheckFile( staged , new_key , cfg.EncryptAtRest ); err != nil {
			err = fmt.Errorf( "the re-encrypted database does not read back, nothing was changed: %w" , err )
			return
		}
	}

	if cfg.EncryptAtRest {
		log_files , err = logs.RekeyFiles( cfg.Logs.Dir , filepath.Join( directory , config.LogsDirName ) , cfg.SecretKey , new_key )
	}
	return
}

func ensureStopped( cfg *config.Config ) ( err error ) {
	release , err := db.Exclusive( cfg.DatabasePath )
	if errors.Is( err , db.ErrInUse ) {
		err = ErrServerRunning
		return
	}
	if err == nil {
		release()
	}
	return
}

func copyFile( source string , target string ) ( err error ) {
	input , err := os.Open( source )
	if err != nil { return }
	defer input.Close()
	output , err := os.OpenFile( target , os.O_WRONLY|os.O_CREATE|os.O_EXCL , 0o600 )
	if err != nil { return }
	defer output.Close()
	if _ , err = io.Copy( output , input ); err != nil { return }
	if err = output.Sync(); err != nil { return }
	err = output.Close()
	return
}
