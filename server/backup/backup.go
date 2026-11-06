// Package backup makes one file that holds a whole deployment's data, while
// the server runs, and puts one back.
//
// A backup is a .tar.gz holding:
//
//	manifest.json   when it was made, and which key reads it
//	app.db          a consistent copy, taken in one bolt read transaction
//	config.yaml     this deployment's settings
//	storage/        application files
//	secret.key      only with -include-key
//
// The activity log is left out: it can be far larger than everything else,
// and losing it loses history rather than data.
//
// # The key
//
// secret.key stays out by default, so that a leaked backup cannot be read. The
// manifest carries the key's fingerprint instead, which is what lets a restore
// say "this needs a different key" before it touches anything. Keeping a copy
// of the key is the operator's job, and every backup says so.
//
// Restoring a backup made under another key -- from before a rotation, or from
// another machine -- moves the restored data onto the key in use now, so
// secret.key itself is never rewritten here. That matters in the container,
// where it is mounted read-only.
package backup

import (
	tar "archive/tar"
	gzip "compress/gzip"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	io "io"
	fs "io/fs"
	os "os"
	path "path"
	filepath "path/filepath"
	sort "sort"
	strings "strings"
	time "time"

	config "ipb/server/config"
	db "ipb/server/db"
	encryption "ipb/server/encryption"
	models "ipb/server/models"
)

const (
	// formatVersion goes up when an older restore could no longer read a
	// backup correctly.
	formatVersion = 1

	manifestName = "manifest.json"
	databaseName = "app.db"
	configName   = "config.yaml"
	keyName      = "secret.key"
	storageName  = "storage"

	// Scheduled backups are the only ones Prune may delete, and the prefix
	// is how it tells: one made by hand stays until someone removes it.
	autoPrefix   = "auto-"
	manualPrefix = "backup-"
	suffix       = ".tar.gz"
	stampLayout  = "20060102-150405"

	// A scheduled backup is due this much before its interval is up, so the
	// hourly job's drift cannot push a daily backup back by a whole hour.
	dueSlack = 5 * time.Minute

	// How old a temporary file has to be before it counts as left behind by
	// a crash, rather than belonging to a backup still running.
	staleAfter = 24 * time.Hour
)

// ErrServerRunning is a restore refused because a server holds the database.
var ErrServerRunning = errors.New( "the server is running -- stop it first, restore replaces the database under it" )

// now is here so a test can make two backups with different names.
var now = time.Now

// Manifest is a backup's description of itself.
type Manifest struct {
	Format         int       `json:"format"`
	App            string    `json:"app"`
	CreatedAt      time.Time `json:"created_at"`
	SchemaVersion  int       `json:"schema_version"`
	EncryptAtRest  bool      `json:"encrypt_at_rest"`
	KeyFingerprint string    `json:"key_fingerprint"`
	ContainsKey    bool      `json:"contains_key"`
}

// Options says what Create makes. Out is a file to write or an existing
// directory to write into; empty means the backups directory.
type Options struct {
	Out        string
	IncludeKey bool
	Auto       bool
}

// Result is one finished backup.
type Result struct {
	Path     string   `json:"path"`
	Bytes    int64    `json:"bytes"`
	Manifest Manifest `json:"manifest"`
}

// Create writes a backup. Nothing appears at the final path until the whole
// file is written and on disk, so a backup that fails half way leaves nothing
// that looks like a backup.
func Create( store *db.Store , cfg *config.Config , options Options ) ( result Result , err error ) {
	created := now().UTC()
	target , err := targetPath( cfg , options , created )
	if err != nil { return }
	directory := filepath.Dir( target )
	if err = os.MkdirAll( directory , 0o700 ); err != nil { return }
	if _ , stat_err := os.Stat( target ); stat_err == nil {
		err = fmt.Errorf( "%s already exists" , target )
		return
	}

	snapshot , err := tempFile( directory , ".snapshot-*" )
	if err != nil { return }
	defer os.Remove( snapshot )
	if err = store.Snapshot( snapshot ); err != nil {
		err = fmt.Errorf( "could not copy the database: %w" , err )
		return
	}

	version , err := store.SchemaVersion()
	if err != nil { return }
	manifest := Manifest{
		Format:         formatVersion,
		App:            cfg.ProjectName,
		CreatedAt:      created,
		SchemaVersion:  version,
		EncryptAtRest:  cfg.EncryptAtRest,
		KeyFingerprint: encryption.KeyFingerprint( cfg.SecretKey ),
		ContainsKey:    options.IncludeKey,
	}

	partial , err := tempFile( directory , ".backup-*" )
	if err != nil { return }
	defer os.Remove( partial )
	if err = writeArchive( partial , snapshot , cfg , manifest ); err != nil { return }
	if err = os.Rename( partial , target ); err != nil { return }

	info , err := os.Stat( target )
	if err != nil { return }
	result = Result{ Path: target , Bytes: info.Size() , Manifest: manifest }
	return
}

func targetPath( cfg *config.Config , options Options , created time.Time ) ( target string , err error ) {
	prefix := manualPrefix
	if options.Auto {
		prefix = autoPrefix
	}
	name := prefix + created.Format( stampLayout ) + suffix
	if options.Out == "" {
		target = filepath.Join( cfg.Backups.Dir , name )
		return
	}
	target = options.Out
	if info , stat_err := os.Stat( target ); stat_err == nil && info.IsDir() {
		target = filepath.Join( target , name )
	}
	return
}

func tempFile( directory string , pattern string ) ( name string , err error ) {
	handle , err := os.CreateTemp( directory , pattern )
	if err != nil { return }
	name = handle.Name()
	err = handle.Close()
	return
}

func writeArchive( destination string , snapshot string , cfg *config.Config , manifest Manifest ) ( err error ) {
	output , err := os.OpenFile( destination , os.O_WRONLY|os.O_TRUNC , 0o600 )
	if err != nil { return }
	defer output.Close()
	zipped , err := gzip.NewWriterLevel( output , gzip.BestSpeed )
	if err != nil { return }
	archive := tar.NewWriter( zipped )

	encoded , err := json.MarshalIndent( manifest , "" , "  " )
	if err != nil { return }
	if err = addBytes( archive , manifestName , encoded ); err != nil { return }
	if err = addFile( archive , databaseName , snapshot ); err != nil { return }

	settings , err := os.ReadFile( cfg.ConfigFile )
	if err != nil { return }
	if err = addBytes( archive , configName , settings ); err != nil { return }
	if manifest.ContainsKey {
		if err = addBytes( archive , keyName , []byte( cfg.SecretKey + "\n" ) ); err != nil { return }
	}
	if err = addStorage( archive , cfg.StorageDir ); err != nil { return }

	if err = archive.Close(); err != nil { return }
	if err = zipped.Close(); err != nil { return }
	if err = output.Sync(); err != nil { return }
	err = output.Close()
	return
}

func addBytes( archive *tar.Writer , name string , body []byte ) ( err error ) {
	err = archive.WriteHeader( &tar.Header{ Name: name , Typeflag: tar.TypeReg , Mode: 0o600 , Size: int64( len( body ) ) , ModTime: now() } )
	if err != nil { return }
	_ , err = archive.Write( body )
	return
}

// addFile copies a file into the archive at the size it had when opened. A
// file that shrinks while it is read fails the backup rather than ending up
// in it cut short, and one that grows is taken as far as that size.
func addFile( archive *tar.Writer , name string , source string ) ( err error ) {
	handle , err := os.Open( source )
	if err != nil { return }
	defer handle.Close()
	info , err := handle.Stat()
	if err != nil { return }
	err = archive.WriteHeader( &tar.Header{ Name: name , Typeflag: tar.TypeReg , Mode: 0o600 , Size: info.Size() , ModTime: info.ModTime() } )
	if err != nil { return }
	_ , err = io.CopyN( archive , handle , info.Size() )
	if err != nil {
		err = fmt.Errorf( "%s changed while it was being read: %w" , source , err )
	}
	return
}

// addStorage walks the app's files. Only files and folders go in: a symlink
// could point anywhere, and following one would put something in the backup
// nobody asked for. Storage is copied as it stands, not at the database's
// moment, so a file written during a backup may or may not be in it.
func addStorage( archive *tar.Writer , root string ) ( err error ) {
	if _ , stat_err := os.Stat( root ); stat_err != nil { return }
	err = filepath.WalkDir( root , func( name string , entry fs.DirEntry , walk_err error ) ( visit_err error ) {
		if walk_err != nil {
			// A file deleted during the walk is simply not in this backup.
			if errors.Is( walk_err , fs.ErrNotExist ) { return }
			visit_err = walk_err
			return
		}
		relative , visit_err := filepath.Rel( root , name )
		if visit_err != nil { return }
		member := path.Join( storageName , filepath.ToSlash( relative ) )
		switch {
		case entry.IsDir():
			visit_err = archive.WriteHeader( &tar.Header{ Name: member + "/" , Typeflag: tar.TypeDir , Mode: 0o700 , ModTime: now() } )
		case entry.Type().IsRegular():
			visit_err = addFile( archive , member , name )
			if errors.Is( visit_err , fs.ErrNotExist ) {
				visit_err = nil
			}
		}
		return
	} )
	return
}

// ---------------------------------------------------------------------------
// scheduled backups
// ---------------------------------------------------------------------------

// RunScheduled is the hourly job's part: make a backup if one is on and due,
// then drop the oldest beyond backups.keep. made is nil when nothing was due.
func RunScheduled( store *db.Store , cfg *config.Config ) ( made *Result , removed int , err error ) {
	if cfg.Backups.Enabled == false { return }
	if due( cfg.Backups , now() ) == false { return }
	result , err := Create( store , cfg , Options{ Auto: true } )
	if err != nil { return }
	made = &result
	removed , err = Prune( cfg.Backups )
	return
}

// autoBackups lists scheduled backups, newest first. The stamp in the name
// sorts by time, and survives being copied, which a file's mtime does not.
func autoBackups( directory string ) ( names []string ) {
	entries , err := os.ReadDir( directory )
	if err != nil { return }
	for _ , entry := range entries {
		name := entry.Name()
		if strings.HasPrefix( name , autoPrefix ) && strings.HasSuffix( name , suffix ) {
			names = append( names , name )
		}
	}
	sort.Sort( sort.Reverse( sort.StringSlice( names ) ) )
	return
}

func due( settings config.BackupsConfig , at time.Time ) ( result bool ) {
	names := autoBackups( settings.Dir )
	if len( names ) == 0 {
		result = true
		return
	}
	stamp := strings.TrimSuffix( strings.TrimPrefix( names[ 0 ] , autoPrefix ) , suffix )
	newest , err := time.Parse( stampLayout , stamp )
	if err != nil {
		result = true
		return
	}
	result = at.Sub( newest ) >= settings.Interval - dueSlack
	return
}

// Prune removes scheduled backups beyond keep, oldest first, and any
// temporary file a crash left behind. Backups made by hand are never touched.
func Prune( settings config.BackupsConfig ) ( removed int , err error ) {
	names := autoBackups( settings.Dir )
	if len( names ) > settings.Keep {
		for _ , name := range names[ settings.Keep: ] {
			if err = os.Remove( filepath.Join( settings.Dir , name ) ); err != nil { return }
			removed++
		}
	}
	entries , read_err := os.ReadDir( settings.Dir )
	if read_err != nil { return }
	for _ , entry := range entries {
		name := entry.Name()
		if strings.HasPrefix( name , ".backup-" ) == false && strings.HasPrefix( name , ".snapshot-" ) == false { continue }
		if info , info_err := entry.Info(); info_err == nil && now().Sub( info.ModTime() ) > staleAfter {
			os.Remove( filepath.Join( settings.Dir , name ) )
		}
	}
	return
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

// RestoreOptions says what to restore. KeyFile is a key that reads the backup,
// for one made under a key this deployment no longer uses.
type RestoreOptions struct {
	From    string
	KeyFile string
}

// RestoreResult says what changed and where the previous data went.
type RestoreResult struct {
	Manifest      Manifest
	Rekeyed       bool
	SavedDatabase string
	SavedStorage  string
	SavedConfig   string
}

// Restore replaces the database and storage with a backup's. It needs the
// server stopped, and does everything that can fail in a staging folder
// first: the backup is unpacked, its key found, and every record decoded
// before anything in place is touched. What was there is kept beside it, so a
// restore can itself be undone by hand.
//
// config.yaml is not replaced. Settings belong to the deployment, and the
// container's copy is a mounted file; the backup's copy is left beside the
// database to compare.
//
// A backup from an older schema needs nothing here: the next start migrates
// it like any other older database. One from a newer schema is refused.
func Restore( cfg *config.Config , options RestoreOptions ) ( result RestoreResult , err error ) {
	if err = ensureStopped( cfg ); err != nil { return }
	staging , err := os.MkdirTemp( cfg.AppDir , ".restore-*" )
	if err != nil { return }
	defer os.RemoveAll( staging )

	if err = unpack( options.From , staging ); err != nil { return }
	manifest , err := readManifest( staging )
	if err != nil { return }
	result.Manifest = manifest
	if manifest.EncryptAtRest != cfg.EncryptAtRest {
		err = fmt.Errorf( "this backup has encrypt_at_rest %v and config.yaml says %v -- set server.encrypt_at_rest to match it first" , manifest.EncryptAtRest , cfg.EncryptAtRest )
		return
	}
	source_key , err := findKey( manifest , staging , cfg , options.KeyFile )
	if err != nil { return }

	staged_database := filepath.Join( staging , databaseName )
	if source_key != cfg.SecretKey {
		rewrite := models.RekeyRecord( source_key , cfg.SecretKey )
		if err = db.Rekey( staged_database , source_key , cfg.SecretKey , cfg.EncryptAtRest , rewrite ); err != nil {
			err = fmt.Errorf( "could not move this backup onto the current key: %w" , err )
			return
		}
		result.Rekeyed = true
	}
	if err = db.CheckFile( staged_database , cfg.SecretKey , cfg.EncryptAtRest ); err != nil {
		err = fmt.Errorf( "this backup does not read back, nothing was changed: %w" , err )
		return
	}

	// Again, because unpacking a big backup takes long enough for a server
	// to have been started in the meantime.
	if err = ensureStopped( cfg ); err != nil { return }
	err = swapIn( cfg , staging , now().UTC().Format( stampLayout ) , &result )
	return
}

// ensureStopped answers by trying bolt's own lock, which works whether or not
// the server has its control socket on.
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

// swapIn is the only step that changes anything in place. Everything it does
// is a rename, and a failure half way puts back what it moved.
func swapIn( cfg *config.Config , staging string , stamp string , result *RestoreResult ) ( err error ) {
	saved := cfg.DatabasePath + ".before-restore-" + stamp
	if _ , stat_err := os.Stat( cfg.DatabasePath ); stat_err == nil {
		if err = os.Rename( cfg.DatabasePath , saved ); err != nil { return }
		result.SavedDatabase = saved
	}
	if err = os.Rename( filepath.Join( staging , databaseName ) , cfg.DatabasePath ); err != nil {
		if result.SavedDatabase != "" {
			os.Rename( saved , cfg.DatabasePath )
			result.SavedDatabase = ""
		}
		return
	}

	if _ , stat_err := os.Stat( cfg.StorageDir ); stat_err == nil {
		kept := cfg.StorageDir + ".before-restore-" + stamp
		if err = os.Rename( cfg.StorageDir , kept ); err != nil { return }
		result.SavedStorage = kept
	}
	staged_storage := filepath.Join( staging , storageName )
	if _ , stat_err := os.Stat( staged_storage ); stat_err == nil {
		err = os.Rename( staged_storage , cfg.StorageDir )
	} else {
		err = os.MkdirAll( cfg.StorageDir , 0o700 )
	}
	if err != nil { return }

	staged_config := filepath.Join( staging , configName )
	if _ , stat_err := os.Stat( staged_config ); stat_err == nil {
		kept := filepath.Join( cfg.AppDir , configName + ".from-backup-" + stamp )
		if os.Rename( staged_config , kept ) == nil {
			result.SavedConfig = kept
		}
	}
	return
}

// memberPath checks one archive entry's name. A backup can come from anywhere
// by the time it is restored, so an entry only gets to be one of the names a
// backup contains: nothing absolute, nothing with a "..", nothing else.
func memberPath( name string ) ( result string , ok bool ) {
	trimmed := strings.TrimSuffix( name , "/" )
	if trimmed == "" || strings.Contains( trimmed , "\\" ) || path.IsAbs( trimmed ) || path.Clean( trimmed ) != trimmed {
		return
	}
	switch trimmed {
	case manifestName , databaseName , configName , keyName , storageName:
		result , ok = trimmed , true
		return
	}
	if strings.HasPrefix( trimmed , storageName + "/" ) {
		result , ok = trimmed , true
	}
	return
}

func unpack( source string , staging string ) ( err error ) {
	handle , err := os.Open( source )
	if err != nil { return }
	defer handle.Close()
	zipped , err := gzip.NewReader( handle )
	if err != nil {
		err = fmt.Errorf( "%s is not a backup: %w" , source , err )
		return
	}
	defer zipped.Close()
	archive := tar.NewReader( zipped )
	for {
		header , next_err := archive.Next()
		if errors.Is( next_err , io.EOF ) { return }
		if next_err != nil {
			err = fmt.Errorf( "%s is damaged: %w" , source , next_err )
			return
		}
		member , ok := memberPath( header.Name )
		if ok == false {
			err = fmt.Errorf( "%s holds an entry a backup never contains: %q" , source , header.Name )
			return
		}
		destination := filepath.Join( staging , filepath.FromSlash( member ) )
		switch header.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll( destination , 0o700 )
		case tar.TypeReg:
			err = extract( archive , destination )
		default:
			err = fmt.Errorf( "%s holds %q, which is neither a file nor a folder" , source , header.Name )
		}
		if err != nil { return }
	}
}

// extract refuses to write over anything: a name that appears twice in an
// archive is not something a backup does.
func extract( archive io.Reader , destination string ) ( err error ) {
	if err = os.MkdirAll( filepath.Dir( destination ) , 0o700 ); err != nil { return }
	output , err := os.OpenFile( destination , os.O_WRONLY|os.O_CREATE|os.O_EXCL , 0o600 )
	if err != nil { return }
	defer output.Close()
	_ , err = io.Copy( output , archive )
	return
}

func readManifest( staging string ) ( manifest Manifest , err error ) {
	raw , err := os.ReadFile( filepath.Join( staging , manifestName ) )
	if err != nil {
		err = errors.New( "this file has no manifest.json, so it is not a backup" )
		return
	}
	if err = json.Unmarshal( raw , &manifest ); err != nil {
		err = fmt.Errorf( "this backup's manifest cannot be read: %w" , err )
		return
	}
	if manifest.Format < 1 || manifest.Format > formatVersion {
		err = fmt.Errorf( "this backup is format %d and this app reads up to %d -- restore it with the version that made it" , manifest.Format , formatVersion )
		return
	}
	if manifest.SchemaVersion > db.LatestSchemaVersion() {
		err = fmt.Errorf( "this backup is at schema version %d and this build only knows %d -- it came from a newer version of this app; upgrade first" , manifest.SchemaVersion , db.LatestSchemaVersion() )
		return
	}
	if _ , stat_err := os.Stat( filepath.Join( staging , databaseName ) ); stat_err != nil {
		err = errors.New( "this backup has no app.db in it" )
	}
	return
}

// findKey works out which key reads the backup: one named on the command
// line, the one packed inside it, or the one in use. The fingerprint settles
// it, so a wrong key is refused by name rather than by a decryption failure.
func findKey( manifest Manifest , staging string , cfg *config.Config , key_file string ) ( key string , err error ) {
	if key_file != "" {
		if key , err = config.ReadSecret( key_file ); err != nil { return }
		if encryption.KeyFingerprint( key ) != manifest.KeyFingerprint {
			err = fmt.Errorf( "%s is not the key for this backup: it needs the key with fingerprint %s" , key_file , manifest.KeyFingerprint )
			key = ""
		}
		return
	}
	if encryption.KeyFingerprint( cfg.SecretKey ) == manifest.KeyFingerprint {
		key = cfg.SecretKey
		return
	}
	if packed , read_err := config.ReadSecret( filepath.Join( staging , keyName ) ); read_err == nil && encryption.KeyFingerprint( packed ) == manifest.KeyFingerprint {
		key = packed
		return
	}
	err = fmt.Errorf(
		"this backup was made with a different key (fingerprint %s) and secret.key is %s.\n"+
			"  Pass the key it was made with: -key-file path/to/secret.key.retired-<date>" ,
		manifest.KeyFingerprint , encryption.KeyFingerprint( cfg.SecretKey ) )
	return
}
