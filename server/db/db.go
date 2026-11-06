// Package db owns the bolt file: opening it, creating buckets, and the
// encrypt-on-write / decrypt-on-read wrapper that every model goes through.
//
// Models never touch bolt or the encryption package directly. That is what
// makes at-rest encryption a single switch instead of something each model
// has to remember, and it means the answer to "where does data get written"
// is one file.
package db

import (
	bytes "bytes"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	os "os"
	time "time"

	bolt "go.etcd.io/bbolt"

	config "ipb/server/config"
	encryption "ipb/server/encryption"
)

var ErrNotFound = errors.New( "db: not found" )

// Bucket names. Add new ones here and to bucketNames so they are created at
// startup -- a bucket that only gets created on first write is a nil-pointer
// panic waiting for the first reader.
const (
	BucketUsers       = "users"
	BucketSessions    = "sessions"
	BucketLoginTokens = "login_tokens"
	BucketAPIKeys     = "api_keys"
	BucketInviteLinks = "invite_links"
	BucketSignInChallenges = "sign_in_challenges"
	BucketJobs        = "jobs"
	BucketWebhooks    = "webhooks"
	// BucketWebhookDeliveries is the outbox: see server/webhooks.
	BucketWebhookDeliveries = "webhook_deliveries"
	// BucketFiles describes uploads; the bytes are on disk. See models/file.go.
	BucketFiles       = "files"
	// Notifications. See the models/push_*.go files and server/push.
	BucketPushApps          = "push_apps"
	BucketPushAppMedia      = "push_app_media"
	BucketPushGroups        = "push_groups"
	BucketPushPrefs         = "push_prefs"
	BucketRecipientKeys     = "recipient_keys"
	BucketPushSubscriptions = "push_subscriptions"
	BucketPushKeys          = "push_keys"
	BucketInbox             = "push_inbox"
	BucketPushDeliveries    = "push_deliveries"
	BucketPushRepeats       = "push_repeats"
	BucketMeta        = "meta"
	// BucketSchema holds the schema version, unencrypted. See migrate.go.
	BucketSchema      = "schema"
)

var bucketNames = []string{ BucketUsers , BucketSessions , BucketLoginTokens , BucketAPIKeys , BucketInviteLinks , BucketSignInChallenges , BucketJobs , BucketWebhooks , BucketWebhookDeliveries , BucketFiles , BucketPushApps , BucketPushAppMedia , BucketPushGroups , BucketPushPrefs , BucketRecipientKeys , BucketPushSubscriptions , BucketPushKeys , BucketInbox , BucketPushDeliveries , BucketPushRepeats , BucketMeta , BucketSchema }

type Store struct {
	bolt          *bolt.DB
	secretKey     string
	encryptAtRest bool
}

// Open creates the file if needed and makes sure every bucket exists. The
// timeout matters: bolt takes an exclusive flock, so without it a second
// process (a stray `manage` command, a container that did not fully stop)
// blocks forever instead of telling you what is wrong.
func Open( cfg *config.Config ) ( store *Store , err error ) {
	store , err = openWith( cfg , migrations )
	return
}

// openWith is Open with the list of migrations named, so a test can bring its
// own.
func openWith( cfg *config.Config , steps []Migration ) ( store *Store , err error ) {
	fresh := exists( cfg.DatabasePath ) == false
	handle , err := bolt.Open( cfg.DatabasePath , 0o600 , &bolt.Options{ Timeout: 5 * time.Second } )
	if err != nil {
		err = fmt.Errorf( "could not open database at %s (is another instance running?): %w" , cfg.DatabasePath , err )
		return
	}
	store = &Store{
		bolt:          handle,
		secretKey:     cfg.SecretKey,
		encryptAtRest: cfg.EncryptAtRest,
	}
	err = handle.Update( func( tx *bolt.Tx ) ( tx_err error ) {
		for _ , name := range bucketNames {
			if _ , tx_err = tx.CreateBucketIfNotExists( []byte( name ) ); tx_err != nil {
				return
			}
		}
		return
	} )
	if err == nil {
		err = store.migrate( cfg , fresh , steps )
	}
	if err != nil {
		handle.Close()
		store = nil
	}
	return
}

// Snapshot writes a consistent copy of the database to path while the server
// goes on working: a bolt read transaction sees one fixed moment, and writers
// are not held up by it. The file keeps its encryption, so it needs the same
// key to read.
func ( store *Store ) Snapshot( path string ) ( err error ) {
	err = store.bolt.View( func( tx *bolt.Tx ) ( tx_err error ) {
		tx_err = tx.CopyFile( path , 0o600 )
		return
	} )
	return
}

// ErrInUse means another process holds the database.
var ErrInUse = errors.New( "db: the database is in use" )

// IsLocked says an open failed because another process holds the file, as
// opposed to something being wrong with the file itself.
func IsLocked( err error ) ( result bool ) {
	result = errors.Is( err , bolt.ErrTimeout )
	return
}

// Exclusive takes bolt's lock on a database file, for work that must not
// happen under a live server. release gives it back. A missing file is free,
// and so is a damaged one: bolt refuses to open it, but nothing can be
// serving it either, and repairing it by restoring is the likeliest reason to
// be here.
func Exclusive( path string ) ( release func() , err error ) {
	release = func() {}
	if _ , stat_err := os.Stat( path ); stat_err != nil { return }
	handle , open_err := bolt.Open( path , 0o600 , &bolt.Options{ Timeout: time.Second } )
	switch {
	case open_err == nil:
		release = func() { handle.Close() }
	case errors.Is( open_err , bolt.ErrTimeout ):
		err = ErrInUse
	}
	return
}

// CheckFile opens a database file that nothing is using and decodes every
// record in it, so a backup can be proved readable before it replaces
// anything.
func CheckFile( path string , secret_key string , encrypt_at_rest bool ) ( err error ) {
	handle , err := bolt.Open( path , 0o600 , &bolt.Options{ Timeout: 5 * time.Second , ReadOnly: true } )
	if err != nil { return }
	defer handle.Close()
	reader := &Store{ secretKey: secret_key , encryptAtRest: encrypt_at_rest }
	err = handle.View( func( tx *bolt.Tx ) ( tx_err error ) {
		tx_err = tx.ForEach( func( name []byte , bucket *bolt.Bucket ) ( bucket_err error ) {
			if string( name ) == BucketSchema { return }
			bucket_err = bucket.ForEach( func( key []byte , value []byte ) ( record_err error ) {
				if value == nil { return }
				var record any
				if record_err = reader.decode( value , &record ); record_err != nil {
					record_err = fmt.Errorf( "%s/%q: %w" , name , key , record_err )
				}
				return
			} )
			return
		} )
		return
	} )
	return
}

// Rekey rewrites a database file that nothing is using from old_key to
// new_key, in one transaction, so it is all or nothing. Every value goes
// through rewrite as plain JSON, for the fields a model encrypts a second
// time on its own (see models.RekeyRecord). With encrypt_at_rest off only
// rewrite has anything to change.
func Rekey( path string , old_key string , new_key string , encrypt_at_rest bool , rewrite func( bucket string , plain []byte ) ( []byte , error ) ) ( err error ) {
	handle , err := bolt.Open( path , 0o600 , &bolt.Options{ Timeout: 5 * time.Second } )
	if err != nil { return }
	defer handle.Close()
	err = handle.Update( func( tx *bolt.Tx ) ( tx_err error ) {
		tx_err = tx.ForEach( func( name []byte , bucket *bolt.Bucket ) ( bucket_err error ) {
			if string( name ) == BucketSchema { return }
			// Collected first: changing a bucket under its own cursor is the
			// one thing bolt warns about.
			changed := map[string][]byte{}
			bucket_err = bucket.ForEach( func( key []byte , value []byte ) ( record_err error ) {
				if value == nil { return }
				plain := value
				if encrypt_at_rest {
					if plain , record_err = encryption.ChaChaDecryptBytes( old_key , value ); record_err != nil {
						record_err = fmt.Errorf( "could not decrypt %s/%q with the old key: %w" , name , key , record_err )
						return
					}
				}
				if plain , record_err = rewrite( string( name ) , plain ); record_err != nil {
					record_err = fmt.Errorf( "%s/%q: %w" , name , key , record_err )
					return
				}
				if encrypt_at_rest {
					if plain , record_err = encryption.ChaChaEncryptBytes( new_key , plain ); record_err != nil { return }
				}
				// A copy: plain can still be bolt's own memory here.
				changed[ string( key ) ] = append( []byte( nil ) , plain... )
				return
			} )
			if bucket_err != nil { return }
			for key , value := range changed {
				if bucket_err = bucket.Put( []byte( key ) , value ); bucket_err != nil { return }
			}
			return
		} )
		return
	} )
	return
}

func ( store *Store ) Close() ( err error ) {
	err = store.bolt.Close()
	return
}

func ( store *Store ) encode( value any ) ( result []byte , err error ) {
	raw , err := json.Marshal( value )
	if err != nil { return }
	if store.encryptAtRest == false {
		result = raw
		return
	}
	result , err = encryption.ChaChaEncryptBytes( store.secretKey , raw )
	return
}

func ( store *Store ) decode( raw []byte , out any ) ( err error ) {
	plain , err := store.open( raw )
	if err != nil { return }
	err = json.Unmarshal( plain , out )
	return
}

// open is decode without the JSON: a stored value as its plain bytes.
func ( store *Store ) open( raw []byte ) ( plain []byte , err error ) {
	plain = raw
	if store.encryptAtRest == false { return }
	plain , err = encryption.ChaChaDecryptBytes( store.secretKey , raw )
	if err != nil {
		err = fmt.Errorf( "could not decrypt a stored record -- is secret.key the same key it was written with?: %w" , err )
	}
	return
}

// Put writes value under key. Callers pass a struct; JSON encoding and
// encryption happen here so no model has to think about either.
func ( store *Store ) Put( bucket string , key []byte , value any ) ( err error ) {
	encoded , err := store.encode( value )
	if err != nil { return }
	err = store.bolt.Update( func( tx *bolt.Tx ) ( tx_err error ) {
		tx_err = tx.Bucket( []byte( bucket ) ).Put( key , encoded )
		return
	} )
	return
}

// Get returns ErrNotFound rather than leaving out untouched, so callers can
// tell "no such record" apart from "record exists and is zero-valued".
func ( store *Store ) Get( bucket string , key []byte , out any ) ( err error ) {
	var raw []byte
	err = store.bolt.View( func( tx *bolt.Tx ) ( tx_err error ) {
		value := tx.Bucket( []byte( bucket ) ).Get( key )
		if value == nil {
			tx_err = ErrNotFound
			return
		}
		raw = append( []byte( nil ) , value... ) // bolt's slice is only valid inside the tx
		return
	} )
	if err != nil { return }
	err = store.decode( raw , out )
	return
}

func ( store *Store ) Delete( bucket string , key []byte ) ( err error ) {
	err = store.bolt.Update( func( tx *bolt.Tx ) ( tx_err error ) {
		tx_err = tx.Bucket( []byte( bucket ) ).Delete( key )
		return
	} )
	return
}

// ForEach walks a bucket in key order, decoding each value into a fresh
// instance produced by newItem. Iteration stops early if visit returns false.
func ( store *Store ) ForEach( bucket string , newItem func() any , visit func( key []byte , item any ) bool ) ( err error ) {
	err = store.bolt.View( func( tx *bolt.Tx ) ( tx_err error ) {
		cursor := tx.Bucket( []byte( bucket ) ).Cursor()
		for key , value := cursor.First(); key != nil; key , value = cursor.Next() {
			item := newItem()
			if decode_err := store.decode( value , item ); decode_err != nil {
				tx_err = decode_err
				return
			}
			key_copy := append( []byte( nil ) , key... )
			if visit( key_copy , item ) == false {
				return
			}
		}
		return
	} )
	return
}

// ForEachPrefix is ForEach over only the keys starting with prefix, which is
// how a bucket keyed by user reads one person's rows without decoding everyone's.
func ( store *Store ) ForEachPrefix( bucket string , prefix []byte , newItem func() any , visit func( key []byte , item any ) bool ) ( err error ) {
	err = store.bolt.View( func( tx *bolt.Tx ) ( tx_err error ) {
		cursor := tx.Bucket( []byte( bucket ) ).Cursor()
		for key , value := cursor.Seek( prefix ); key != nil && bytes.HasPrefix( key , prefix ); key , value = cursor.Next() {
			item := newItem()
			if decode_err := store.decode( value , item ); decode_err != nil {
				tx_err = decode_err
				return
			}
			if visit( append( []byte( nil ) , key... ) , item ) == false {
				return
			}
		}
		return
	} )
	return
}

// NextSequence hands out monotonic ids inside bolt's own transaction, so two
// concurrent creates can never collide on the same id.
func ( store *Store ) NextSequence( bucket string ) ( result uint64 , err error ) {
	err = store.bolt.Update( func( tx *bolt.Tx ) ( tx_err error ) {
		result , tx_err = tx.Bucket( []byte( bucket ) ).NextSequence()
		return
	} )
	return
}

// UpdateValue reads a record, hands it to mutate, and writes the result back
// inside a single write transaction.
//
// The obvious alternative -- Get, change the struct, Put -- has a lost update
// hiding in the gap between the two transactions: two concurrent callers both
// read the old record and the second Put silently discards the first one's
// change. Anything that edits an existing record should come through here.
func ( store *Store ) UpdateValue( bucket string , key []byte , newItem func() any , mutate func( item any ) error ) ( err error ) {
	err = store.bolt.Update( func( tx *bolt.Tx ) ( tx_err error ) {
		target := tx.Bucket( []byte( bucket ) )
		raw := target.Get( key )
		if raw == nil {
			tx_err = ErrNotFound
			return
		}
		item := newItem()
		if tx_err = store.decode( raw , item ); tx_err != nil { return }
		if tx_err = mutate( item ); tx_err != nil { return }
		encoded , encode_err := store.encode( item )
		if encode_err != nil {
			tx_err = encode_err
			return
		}
		tx_err = target.Put( key , encoded )
		return
	} )
	return
}

// DeleteWhere removes every record in a bucket that match reports true for,
// inside a single write transaction.
//
// Written the obvious way -- a read pass that collects keys, then one Delete
// per key -- this is two problems at once. It is N write transactions and N
// fsyncs where one would do, and because bolt allows a single writer at a
// time, a purge over a large bucket becomes a queue that every request
// handler waiting to write sits behind. It is also wrong: a record that
// starts matching between the read pass and the deletes is missed, which for
// session revocation means a session created mid-sweep outlives the account
// it belongs to.
func ( store *Store ) DeleteWhere( bucket string , newItem func() any , match func( key []byte , item any ) bool ) ( removed int , err error ) {
	err = store.bolt.Update( func( tx *bolt.Tx ) ( tx_err error ) {
		target := tx.Bucket( []byte( bucket ) )
		doomed := [][]byte{}
		cursor := target.Cursor()
		for key , value := cursor.First(); key != nil; key , value = cursor.Next() {
			item := newItem()
			if decode_err := store.decode( value , item ); decode_err != nil {
				tx_err = decode_err
				return
			}
			if match( key , item ) {
				doomed = append( doomed , append( []byte( nil ) , key... ) )
			}
		}
		// Deleting through the cursor while iterating is legal in bolt, but
		// where the cursor lands afterwards is subtle enough to be worth
		// avoiding. Collecting first costs one slice and keeps this
		// obviously correct -- and it is still one transaction either way.
		for _ , key := range doomed {
			if tx_err = target.Delete( key ); tx_err != nil { return }
		}
		removed = len( doomed )
		return
	} )
	if err != nil { removed = 0 }
	return
}

// Update exposes a raw bolt read/write transaction. Prefer Write, which
// gives the same atomicity with encoding and encryption handled for you.
func ( store *Store ) Update( fn func( tx *bolt.Tx ) error ) ( err error ) {
	err = store.bolt.Update( fn )
	return
}

// Tx is one write transaction with the same record API as Store, for the
// operations that have to be atomic across several records or buckets:
// turning a login link into a session, disabling an account together with
// every credential it holds, checking an API key quota and inserting the key.
//
// bolt allows a single writer at a time, so whatever runs inside Write sees
// no other write interleave with it. That is the whole point -- and also the
// cost: keep slow work (bcrypt, network calls) outside, because every other
// writer waits for this one to finish.
type Tx struct {
	store *Store
	tx    *bolt.Tx
}

func ( store *Store ) Write( fn func( tx *Tx ) error ) ( err error ) {
	err = store.bolt.Update( func( raw *bolt.Tx ) ( tx_err error ) {
		tx_err = fn( &Tx{ store: store , tx: raw } )
		return
	} )
	return
}

func ( tx *Tx ) Get( bucket string , key []byte , out any ) ( err error ) {
	value := tx.tx.Bucket( []byte( bucket ) ).Get( key )
	if value == nil {
		err = ErrNotFound
		return
	}
	err = tx.store.decode( value , out )
	return
}

func ( tx *Tx ) Put( bucket string , key []byte , value any ) ( err error ) {
	encoded , err := tx.store.encode( value )
	if err != nil { return }
	err = tx.tx.Bucket( []byte( bucket ) ).Put( key , encoded )
	return
}

func ( tx *Tx ) Delete( bucket string , key []byte ) ( err error ) {
	err = tx.tx.Bucket( []byte( bucket ) ).Delete( key )
	return
}

// NextSequence is Store.NextSequence inside this transaction, for a record
// that has to be created together with something else -- a user and the
// owner marker that names it, for one.
func ( tx *Tx ) NextSequence( bucket string ) ( result uint64 , err error ) {
	result , err = tx.tx.Bucket( []byte( bucket ) ).NextSequence()
	return
}

// ForEach is Store.ForEach inside this transaction.
func ( tx *Tx ) ForEach( bucket string , newItem func() any , visit func( key []byte , item any ) bool ) ( err error ) {
	cursor := tx.tx.Bucket( []byte( bucket ) ).Cursor()
	for key , value := cursor.First(); key != nil; key , value = cursor.Next() {
		item := newItem()
		if err = tx.store.decode( value , item ); err != nil { return }
		if visit( append( []byte( nil ) , key... ) , item ) == false { return }
	}
	return
}

// DeleteWhere is Store.DeleteWhere inside this transaction.
func ( tx *Tx ) DeleteWhere( bucket string , newItem func() any , match func( key []byte , item any ) bool ) ( removed int , err error ) {
	doomed := [][]byte{}
	err = tx.ForEach( bucket , newItem , func( key []byte , item any ) bool {
		if match( key , item ) {
			doomed = append( doomed , key )
		}
		return true
	} )
	if err != nil { return }
	target := tx.tx.Bucket( []byte( bucket ) )
	for _ , key := range doomed {
		if err = target.Delete( key ); err != nil { return }
	}
	removed = len( doomed )
	return
}

func ( store *Store ) EncodeValue( value any ) ( result []byte , err error ) {
	result , err = store.encode( value )
	return
}

func ( store *Store ) DecodeValue( raw []byte , out any ) ( err error ) {
	err = store.decode( raw , out )
	return
}
