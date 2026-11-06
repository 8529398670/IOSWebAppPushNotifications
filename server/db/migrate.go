package db

// Data migrations: how a stored record changes shape in a deployed app.
//
// Records are JSON, so most changes need nothing here. A new optional field
// reads as its zero value from older records, and a new bucket is created at
// startup. A migration is for the rest: a field renamed or split, a value
// changed to a new meaning, records moved between buckets.
//
// The database holds a version number, which is how many of the migrations
// below have run on it. Open runs whatever is missing, in order, before
// anything else sees the data:
//
//   - A new database has nothing to migrate, so it is stamped with the latest
//     version and none of them run.
//   - An existing one is copied first, to app.db.before-migration-v<N>-<time>,
//     so a migration that turns out wrong can be undone by hand.
//   - Each migration runs in one transaction with the version bump, so a
//     failure leaves the database exactly as the last one left it, the server
//     refuses to start and says which one failed, and the next start tries it
//     again.
//   - A database newer than this build is refused rather than read: old code
//     would not know what the new shape means, and could write it back wrong.

import (
	bytes "bytes"
	json "encoding/json"
	fmt "fmt"
	log "log"
	os "os"
	time "time"

	bolt "go.etcd.io/bbolt"

	config "ipb/server/config"
	encryption "ipb/server/encryption"
)

// Migration is one step. Up gets the same record API as Store.Write.
type Migration struct {
	Name string
	Up   func( tx *Tx ) error
}

// migrations is every step this app has ever needed. Add to the end, and never
// edit, reorder or remove one that has shipped: a database's version is a
// position in this list. references/architecture.md has a worked example.
var migrations = []Migration{}

// schemaKey is where the version lives, in a bucket of its own that is not
// encrypted: the number gives nothing away, and a backup or a rotation has to
// be able to read it, or to leave it alone, without the key.
var schemaKey = []byte( "version" )

// LatestSchemaVersion is the version this build writes.
func LatestSchemaVersion() ( result int ) {
	result = len( migrations )
	return
}

// SchemaVersion is the version this database is at.
func ( store *Store ) SchemaVersion() ( result int , err error ) {
	err = store.bolt.View( func( tx *bolt.Tx ) ( tx_err error ) {
		result = readSchemaVersion( tx )
		return
	} )
	return
}

func readSchemaVersion( tx *bolt.Tx ) ( result int ) {
	bucket := tx.Bucket( []byte( BucketSchema ) )
	if bucket == nil { return }
	raw := bucket.Get( schemaKey )
	if len( raw ) == 8 {
		result = int( encryption.BytesToUint64( raw ) )
	}
	return
}

func writeSchemaVersion( tx *bolt.Tx , version int ) ( err error ) {
	err = tx.Bucket( []byte( BucketSchema ) ).Put( schemaKey , encryption.Uint64ToBytes( uint64( version ) ) )
	return
}

// migrate brings an open database up to date. fresh means the file did not
// exist before this start.
func ( store *Store ) migrate( cfg *config.Config , fresh bool , steps []Migration ) ( err error ) {
	version , err := store.SchemaVersion()
	if err != nil { return }
	latest := len( steps )
	if version > latest {
		err = fmt.Errorf( "the database is at schema version %d and this build only knows %d -- it was written by a newer version of this app; run that version, or restore a backup" , version , latest )
		return
	}
	if fresh {
		err = store.bolt.Update( func( tx *bolt.Tx ) ( tx_err error ) {
			tx_err = writeSchemaVersion( tx , latest )
			return
		} )
		return
	}
	if version == latest { return }

	kept := fmt.Sprintf( "%s.before-migration-v%d-%s" , cfg.DatabasePath , version , time.Now().UTC().Format( "20060102-150405" ) )
	if err = store.Snapshot( kept ); err != nil {
		err = fmt.Errorf( "could not copy the database before migrating it: %w" , err )
		return
	}
	log.Printf( "[migrate] schema version %d to %d, the previous database is kept at %s" , version , latest , kept )

	for index := version; index < latest; index++ {
		step := steps[ index ]
		err = store.Write( func( tx *Tx ) ( tx_err error ) {
			if tx_err = step.Up( tx ); tx_err != nil { return }
			tx_err = writeSchemaVersion( tx.tx , index + 1 )
			return
		} )
		if err != nil {
			err = fmt.Errorf( "migration %d (%s) failed, the database is unchanged by it: %w" , index + 1 , step.Name , err )
			return
		}
		log.Printf( "[migrate] %d: %s" , index + 1 , step.Name )
	}
	return
}

// exists reports whether there is already a database to migrate. An empty file
// is what bolt leaves if it dies while creating one.
func exists( path string ) ( result bool ) {
	info , err := os.Stat( path )
	result = err == nil && info.Size() > 0
	return
}

// EachRecord hands every record in a bucket to visit as generic JSON, for the
// migration that reshapes them, and writes back the ones it says it changed.
// Numbers stay json.Number, so a large id survives the trip exactly. Use it on
// buckets of objects, which is all of them but meta.
func ( tx *Tx ) EachRecord( bucket string , visit func( key []byte , record map[string]any ) ( changed bool , err error ) ) ( err error ) {
	target := tx.tx.Bucket( []byte( bucket ) )
	updates := map[string][]byte{}
	err = target.ForEach( func( key []byte , value []byte ) ( record_err error ) {
		plain , record_err := tx.store.open( value )
		if record_err != nil { return }
		record := map[string]any{}
		decoder := json.NewDecoder( bytes.NewReader( plain ) )
		decoder.UseNumber()
		if record_err = decoder.Decode( &record ); record_err != nil { return }
		changed , record_err := visit( append( []byte( nil ) , key... ) , record )
		if record_err != nil || changed == false { return }
		encoded , record_err := tx.store.encode( record )
		if record_err != nil { return }
		updates[ string( key ) ] = encoded
		return
	} )
	if err != nil { return }
	for key , encoded := range updates {
		if err = target.Put( []byte( key ) , encoded ); err != nil { return }
	}
	return
}
