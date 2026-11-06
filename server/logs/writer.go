package logs

import (
	bufio "bufio"
	bytes "bytes"
	base64 "encoding/base64"
	json "encoding/json"
	fmt "fmt"
	log "log"
	os "os"
	filepath "path/filepath"
	sync "sync"
	atomic "sync/atomic"
	time "time"

	config "ipb/server/config"
	encryption "ipb/server/encryption"
)

const (
	// queueSize entries can wait for the writer. Past that, Log drops rather
	// than blocks: a slow disk must never slow a request down.
	queueSize = 10000
	// The writer flushes this often, or every flushEvery lines.
	flushInterval = time.Second
	flushEvery    = 200
)

// Logger owns the logs directory. Log hands it an entry from any goroutine;
// one writer goroutine puts them on disk, rotating to a new file at the UTC
// day change and when a part reaches logs.max_file_mb. Readers (store.go)
// and the pruner share files_lock with it, so a file is never compressed or
// deleted while it is being written.
type Logger struct {
	// settings changes while the server runs (see Apply), so everything reads
	// it through Settings() rather than holding on to a copy.
	settings atomic.Pointer[config.LogsConfig]
	key      string
	encrypt  bool

	queue   chan Entry
	dropped atomic.Int64
	stop    chan struct{}
	done    chan struct{}
	started bool

	files_lock sync.Mutex
	// The open part: only touched with files_lock held.
	file    *os.File
	buffer  *bufio.Writer
	day     string
	part    int
	size    int64
	pending int

	counts_lock sync.Mutex
	counts      map[string]fileCounts

	// now is time.Now, replaced in tests.
	now func() time.Time

	onFlushed func()
	// unannounced means entries were written since onFlushed last ran.
	unannounced bool
}

// New makes a Logger; Start begins writing. key and encrypt are
// the key in secret.key and server.encrypt_at_rest.
func New( settings config.LogsConfig , key string , encrypt bool ) ( logger *Logger ) {
	logger = &Logger{
		key:      key,
		encrypt:  encrypt,
		queue:    make( chan Entry , queueSize ),
		stop:     make( chan struct{} ),
		done:     make( chan struct{} ),
		counts:   map[string]fileCounts{},
		now:      time.Now,
	}
	logger.settings.Store( &settings )
	return
}

// Enabled is false when logs.enabled is off, or for a nil Logger, so callers
// never need to check before calling Log.
func ( logger *Logger ) Enabled() ( result bool ) {
	result = logger != nil && logger.Settings().Enabled
	return
}

func ( logger *Logger ) Settings() ( settings config.LogsConfig ) {
	settings = *logger.settings.Load()
	return
}

// Apply takes new settings from an edited config.yaml. The directory and
// whether logging happens at all are fixed at startup: the writer and the
// log's routes are set up once, and logs.enabled is a [restart] key.
func ( logger *Logger ) Apply( next config.LogsConfig ) {
	if logger == nil { return }
	current := logger.Settings()
	next.Dir = current.Dir
	next.Enabled = current.Enabled
	logger.settings.Store( &next )
}

func ( logger *Logger ) Encrypted() ( result bool ) {
	result = logger.encrypt
	return
}

// Dropped is how many entries were thrown away because the queue was full.
func ( logger *Logger ) Dropped() ( count int64 ) {
	count = logger.dropped.Load()
	return
}

// OnFlushed sets what is called, at most once per flushInterval, after new
// entries reach the disk. It is how the Logs screen hears there is something
// to read, and it runs on the writer's goroutine, so it must not block. Set it
// before Start.
func ( logger *Logger ) OnFlushed( notify func() ) {
	if logger == nil { return }
	logger.onFlushed = notify
}

func ( logger *Logger ) Start() {
	if logger.Enabled() == false || logger.started { return }
	logger.started = true
	go logger.run()
}

// Close writes whatever is queued and closes the file. main.go calls it on
// shutdown, after the HTTP server has stopped taking requests.
func ( logger *Logger ) Close() {
	if logger.Enabled() == false || logger.started == false { return }
	close( logger.stop )
	<-logger.done
}

// Log queues an entry. It never blocks: a full queue drops the entry and
// counts it, and the writer logs the count once it catches up.
func ( logger *Logger ) Log( entry Entry ) {
	if logger.Enabled() == false { return }
	if entry.TS.IsZero() {
		entry.TS = logger.now()
	}
	entry.TS = entry.TS.UTC()
	if entry.Level == "" {
		entry.Level = LevelInfo
	}
	select {
	case logger.queue <- entry.owned():
	default:
		logger.dropped.Add( 1 )
	}
}

// System logs a server event with no request behind it.
func ( logger *Logger ) System( level string , message string , detail map[string]any ) {
	logger.Log( Entry{ Kind: KindSystem , Level: level , Msg: message , Detail: detail } )
}

func ( logger *Logger ) run() {
	defer close( logger.done )
	ticker := time.NewTicker( flushInterval )
	defer ticker.Stop()
	reported := int64( 0 )
	for {
		select {
		case entry := <-logger.queue:
			logger.write( entry )
		case <-ticker.C:
			// Report drops from here rather than from Log, which is exactly
			// when the queue has no room for the report.
			if dropped := logger.dropped.Load(); dropped > reported {
				logger.write( Entry{
					TS: logger.now().UTC() , Kind: KindSystem , Level: LevelWarn ,
					Msg: fmt.Sprintf( "%d log entries dropped: the writer fell behind" , dropped - reported ),
				} )
				reported = dropped
			}
			logger.flush()
			if logger.unannounced && logger.onFlushed != nil {
				logger.onFlushed()
			}
			logger.unannounced = false
		case <-logger.stop:
			for {
				select {
				case entry := <-logger.queue:
					logger.write( entry )
					continue
				default:
				}
				break
			}
			logger.files_lock.Lock()
			logger.closeLocked()
			logger.files_lock.Unlock()
			return
		}
	}
}

func ( logger *Logger ) flush() {
	logger.files_lock.Lock()
	defer logger.files_lock.Unlock()
	logger.flushLocked()
}

func ( logger *Logger ) flushLocked() {
	if logger.buffer == nil || logger.pending == 0 { return }
	if err := logger.buffer.Flush(); err != nil {
		log.Printf( "[logs] write failed: %v" , err )
	}
	logger.pending = 0
}

func ( logger *Logger ) closeLocked() {
	logger.flushLocked()
	if logger.file != nil {
		logger.file.Close()
	}
	logger.file = nil
	logger.buffer = nil
	logger.day = ""
}

func ( logger *Logger ) write( entry Entry ) {
	line , err := logger.encode( entry )
	if err != nil {
		log.Printf( "[logs] could not encode an entry: %v" , err )
		return
	}
	logger.files_lock.Lock()
	defer logger.files_lock.Unlock()
	day := entry.TS.Format( DayLayout )
	if err = logger.openLocked( day , int64( len( line ) ) ); err != nil {
		log.Printf( "[logs] %v" , err )
		return
	}
	written , _ := logger.buffer.Write( line )
	logger.size += int64( written )
	logger.pending += 1
	logger.unannounced = true
	if logger.pending >= flushEvery {
		logger.flushLocked()
	}
}

// openLocked makes sure the open part is the right one for day with room for
// next more bytes: a new day starts a new file, a full part the next one.
func ( logger *Logger ) openLocked( day string , next int64 ) ( err error ) {
	if logger.file != nil && logger.day == day && logger.size + next <= logger.Settings().MaxFileBytes {
		return
	}
	part := 0
	if logger.file != nil && logger.day == day {
		part = logger.part + 1
	} else {
		// After a restart, carry on in the newest part of the day.
		part = logger.lastPart( day )
	}
	logger.closeLocked()
	for {
		path := filepath.Join( logger.Settings().Dir , partName( day , part , false ) )
		file , open_err := os.OpenFile( path , os.O_CREATE | os.O_APPEND | os.O_WRONLY , 0o600 )
		if open_err != nil {
			err = fmt.Errorf( "could not open %s: %w" , path , open_err )
			return
		}
		info , stat_err := file.Stat()
		if stat_err != nil {
			file.Close()
			err = stat_err
			return
		}
		// A part already full from an earlier run: go to the next. An empty
		// one takes the line whatever its size, so one huge line cannot loop.
		if info.Size() > 0 && info.Size() + next > logger.Settings().MaxFileBytes {
			file.Close()
			part += 1
			continue
		}
		logger.file = file
		logger.buffer = bufio.NewWriterSize( file , 64 * 1024 )
		logger.day = day
		logger.part = part
		logger.size = info.Size()
		return
	}
}

// lastPart is the highest uncompressed part number on disk for day, or 0.
func ( logger *Logger ) lastPart( day string ) ( part int ) {
	files , _ := logger.dayFiles( day )
	for _ , file := range files {
		if file.compressed == false && file.part > part {
			part = file.part
		}
	}
	return
}

// encode is one line: the entry's JSON, or that encrypted and base64'd.
// HTML escaping is off so a search for "<" or "&" finds what was logged.
func ( logger *Logger ) encode( entry Entry ) ( line []byte , err error ) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder( &buffer )
	encoder.SetEscapeHTML( false )
	if err = encoder.Encode( entry ); err != nil { return }
	plain := bytes.TrimRight( buffer.Bytes() , "\n" )
	if logger.encrypt == false {
		line = append( plain , '\n' )
		return
	}
	sealed , err := encryption.ChaChaEncryptBytes( logger.key , plain )
	if err != nil { return }
	line = make( []byte , base64.StdEncoding.EncodedLen( len( sealed ) ) + 1 )
	base64.StdEncoding.Encode( line , sealed )
	line[ len( line ) - 1 ] = '\n'
	return
}

// decode reverses encode, whichever form the line is in.
func ( logger *Logger ) decode( line []byte ) ( plain []byte , err error ) {
	line = bytes.TrimSpace( line )
	if len( line ) == 0 {
		err = errEmptyLine
		return
	}
	if line[ 0 ] == '{' {
		plain = line
		return
	}
	sealed := make( []byte , base64.StdEncoding.DecodedLen( len( line ) ) )
	count , err := base64.StdEncoding.Decode( sealed , line )
	if err != nil { return }
	plain , err = encryption.ChaChaDecryptBytes( logger.key , sealed[ :count ] )
	return
}
