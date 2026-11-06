package logs

import (
	bufio "bufio"
	bytes "bytes"
	gzip "compress/gzip"
	base64 "encoding/base64"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	io "io"
	os "os"
	filepath "path/filepath"
	regexp "regexp"
	sort "sort"
	strconv "strconv"
	strings "strings"
	time "time"

	encryption "ipb/server/encryption"
)

// DayLayout names the day files: UTC dates.
const DayLayout = "2006-01-02"

// The longest line the reader accepts. A line is one entry, and every part
// of an entry is capped well below this, so a longer one is damage.
const maxLineBytes = 1024 * 1024

var (
	// ErrToday refuses deleting the day still being written. Its text is
	// the error code the Logs screen words (errors.logs_today).
	ErrToday = errors.New( "logs_today" )
	// ErrBadDay is a date that is not YYYY-MM-DD.
	ErrBadDay = errors.New( "bad_day" )

	errEmptyLine = errors.New( "empty line" )

	dayPattern  = regexp.MustCompile( `^\d{4}-\d{2}-\d{2}$` )
	filePattern = regexp.MustCompile( `^(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.jsonl(\.gz)?$` )
)

// ValidDay is true for a real YYYY-MM-DD date.
func ValidDay( day string ) ( result bool ) {
	if dayPattern.MatchString( day ) == false { return }
	_ , err := time.Parse( DayLayout , day )
	result = err == nil
	return
}

func partName( day string , part int , compressed bool ) ( name string ) {
	name = day
	if part > 0 {
		name += "." + strconv.Itoa( part )
	}
	name += ".jsonl"
	if compressed {
		name += ".gz"
	}
	return
}

type dayFile struct {
	path       string
	day        string
	part       int
	compressed bool
	size       int64
	modified   time.Time
}

// fileCounts caches a file's entry and error counts against its size and
// modification time, so listing the days does not re-read every file.
type fileCounts struct {
	size     int64
	modified time.Time
	entries  int
	errors   int
}

// files is every log file on disk, by day, each day's parts in order.
func ( logger *Logger ) files() ( by_day map[string][]dayFile , err error ) {
	by_day = map[string][]dayFile{}
	listing , err := os.ReadDir( logger.Settings().Dir )
	if err != nil {
		if os.IsNotExist( err ) { err = nil }
		return
	}
	for _ , item := range listing {
		match := filePattern.FindStringSubmatch( item.Name() )
		if match == nil || item.IsDir() { continue }
		info , info_err := item.Info()
		if info_err != nil { continue }
		part := 0
		if match[ 2 ] != "" {
			part , _ = strconv.Atoi( match[ 2 ] )
		}
		by_day[ match[ 1 ] ] = append( by_day[ match[ 1 ] ] , dayFile{
			path:       filepath.Join( logger.Settings().Dir , item.Name() ),
			day:        match[ 1 ],
			part:       part,
			compressed: match[ 3 ] != "",
			size:       info.Size(),
			modified:   info.ModTime(),
		} )
	}
	for _ , parts := range by_day {
		sort.Slice( parts , func( a int , b int ) bool { return parts[ a ].part < parts[ b ].part } )
	}
	return
}

func ( logger *Logger ) dayFiles( day string ) ( parts []dayFile , err error ) {
	by_day , err := logger.files()
	parts = by_day[ day ]
	return
}

func ( logger *Logger ) today() ( day string ) {
	day = logger.now().UTC().Format( DayLayout )
	return
}

// scan calls visit with each entry of one file, decoded, along with its JSON
// lowercased (what a free-text search matches against). Lines that do not
// decode -- a half-written last line, a line written under another key --
// are skipped.
func ( logger *Logger ) scan( file dayFile , visit func( entry *Entry , text []byte ) ) ( err error ) {
	handle , err := os.Open( file.path )
	if err != nil { return }
	defer handle.Close()
	var reader io.Reader = handle
	if file.compressed {
		unzipped , zip_err := gzip.NewReader( handle )
		if zip_err != nil {
			err = zip_err
			return
		}
		defer unzipped.Close()
		reader = unzipped
	}
	scanner := bufio.NewScanner( reader )
	scanner.Buffer( make( []byte , 64 * 1024 ) , maxLineBytes )
	for scanner.Scan() {
		plain , decode_err := logger.decode( scanner.Bytes() )
		if decode_err != nil { continue }
		var entry Entry
		if json.Unmarshal( plain , &entry ) != nil { continue }
		visit( &entry , bytes.ToLower( plain ) )
	}
	err = scanner.Err()
	return
}

// counts is a file's entry and error counts, from the cache when the file
// has not changed since they were taken.
func ( logger *Logger ) countFile( file dayFile ) ( counts fileCounts ) {
	logger.counts_lock.Lock()
	cached , found := logger.counts[ file.path ]
	logger.counts_lock.Unlock()
	if found && cached.size == file.size && cached.modified.Equal( file.modified ) {
		counts = cached
		return
	}
	counts = fileCounts{ size: file.size , modified: file.modified }
	logger.scan( file , func( entry *Entry , text []byte ) {
		counts.entries += 1
		if entry.Level == LevelError {
			counts.errors += 1
		}
	} )
	logger.counts_lock.Lock()
	logger.counts[ file.path ] = counts
	logger.counts_lock.Unlock()
	return
}

// Day is one row of the Logs screen's list.
type Day struct {
	Date       string `json:"date"`
	Bytes      int64  `json:"bytes"`
	Parts      int    `json:"parts"`
	Compressed bool   `json:"compressed"`
	Entries    int    `json:"entries"`
	Errors     int    `json:"errors"`
	// Matches is set only for a search, and then only days with a match are
	// listed.
	Matches *int `json:"matches,omitempty"`
}

// Days lists every day on disk, newest first, with total_bytes across all of
// them. With a query, each day also counts its matches, and days without
// one are left out -- which means reading every line, so a search costs a
// pass over the whole log.
func ( logger *Logger ) Days( query Query ) ( days []Day , total_bytes int64 , err error ) {
	logger.flush()
	by_day , err := logger.files()
	if err != nil { return }
	days = []Day{}
	for day , parts := range by_day {
		row := Day{ Date: day , Parts: len( parts ) }
		matches := 0
		for _ , file := range parts {
			row.Bytes += file.size
			row.Compressed = row.Compressed || file.compressed
			counts := logger.countFile( file )
			row.Entries += counts.entries
			row.Errors += counts.errors
			if query.Empty() == false {
				logger.scan( file , func( entry *Entry , text []byte ) {
					if query.Match( entry , text ) { matches += 1 }
				} )
			}
		}
		total_bytes += row.Bytes
		if query.Empty() == false {
			if matches == 0 { continue }
			row.Matches = &matches
		}
		days = append( days , row )
	}
	sort.Slice( days , func( a int , b int ) bool { return days[ a ].Date > days[ b ].Date } )
	return
}

// Record is an entry as the Logs screen gets it: with Pos, its line number
// within the day (0-based, across parts), which is what paging asks from.
type Record struct {
	Entry
	Pos int `json:"pos"`
}

// ReadDay is one page of a day, newest first: up to limit entries matching
// query, before line before (-1 for the newest). next is where the following
// page starts, or nil when there is nothing older.
func ( logger *Logger ) ReadDay( day string , query Query , before int , limit int ) ( records []Record , next *int , err error ) {
	if ValidDay( day ) == false {
		err = ErrBadDay
		return
	}
	logger.flush()
	parts , err := logger.dayFiles( day )
	if err != nil { return }
	// The newest limit matches seen so far, oldest first; more is set once
	// one has been pushed out the front.
	window := make( []Record , 0 , limit )
	more := false
	pos := 0
	for _ , file := range parts {
		scan_err := logger.scan( file , func( entry *Entry , text []byte ) {
			here := pos
			pos += 1
			if before >= 0 && here >= before { return }
			if query.Match( entry , text ) == false { return }
			if len( window ) == limit {
				window = window[ 1: ]
				more = true
			}
			window = append( window , Record{ Entry: *entry , Pos: here } )
		} )
		if scan_err != nil {
			err = scan_err
			return
		}
	}
	records = make( []Record , len( window ) )
	for index , record := range window {
		records[ len( window ) - 1 - index ] = record
	}
	if more && len( records ) > 0 {
		oldest := records[ len( records ) - 1 ].Pos
		next = &oldest
	}
	return
}

// Download writes a day as plain JSON lines, decrypted, oldest first.
func ( logger *Logger ) Download( day string , out io.Writer ) ( err error ) {
	if ValidDay( day ) == false {
		err = ErrBadDay
		return
	}
	logger.flush()
	parts , err := logger.dayFiles( day )
	if err != nil { return }
	for _ , file := range parts {
		handle_err := logger.scanRaw( file , func( plain []byte ) {
			out.Write( plain )
			out.Write( []byte{ '\n' } )
		} )
		if handle_err != nil {
			err = handle_err
			return
		}
	}
	return
}

// scanRaw is scan without parsing: each line's JSON as written.
func ( logger *Logger ) scanRaw( file dayFile , visit func( plain []byte ) ) ( err error ) {
	err = logger.scan( file , func( entry *Entry , text []byte ) {
		plain , encode_err := json.Marshal( entry )
		if encode_err == nil { visit( plain ) }
	} )
	return
}

// DeleteDay removes every file of a day. Today is refused: it is still being
// written, and deleting it would only make the writer start it again.
func ( logger *Logger ) DeleteDay( day string ) ( err error ) {
	if ValidDay( day ) == false {
		err = ErrBadDay
		return
	}
	if day == logger.today() {
		err = ErrToday
		return
	}
	logger.files_lock.Lock()
	defer logger.files_lock.Unlock()
	if logger.day == day {
		logger.closeLocked()
	}
	err = logger.removeDayLocked( day )
	return
}

func ( logger *Logger ) removeDayLocked( day string ) ( err error ) {
	parts , err := logger.dayFiles( day )
	if err != nil { return }
	for _ , file := range parts {
		if remove_err := os.Remove( file.path ); remove_err != nil && os.IsNotExist( remove_err ) == false {
			err = remove_err
		}
		logger.counts_lock.Lock()
		delete( logger.counts , file.path )
		logger.counts_lock.Unlock()
	}
	return
}

// PruneResult is what one Prune did, in days.
type PruneResult struct {
	Compressed  int   `json:"compressed"`
	Deleted     int   `json:"deleted"`
	BytesBefore int64 `json:"bytes_before"`
	BytesAfter  int64 `json:"bytes_after"`
}

// Prune applies config.yaml's logs settings: finished days older than
// compress_after_days are gzipped, days older than retention_days are
// deleted, and while the total is still over max_total_mb the oldest day is
// recycled. Today is never touched. The hourly `prune-logs` job (server/jobs) runs
// it, and so does the Logs screen's "Prune now".
func ( logger *Logger ) Prune() ( result PruneResult , err error ) {
	logger.files_lock.Lock()
	defer logger.files_lock.Unlock()
	today := logger.today()
	// Whatever is still open from before midnight is finished now.
	if logger.day != "" && logger.day != today {
		logger.closeLocked()
	} else {
		logger.flushLocked()
	}
	today_date , _ := time.Parse( DayLayout , today )

	by_day , err := logger.files()
	if err != nil { return }
	result.BytesBefore = totalBytes( by_day )

	for day , parts := range by_day {
		if day == today { continue }
		date , parse_err := time.Parse( DayLayout , day )
		if parse_err != nil { continue }
		age := int( today_date.Sub( date ).Hours() / 24 )
		if age < 1 { continue }
		if age > logger.Settings().RetentionDays {
			if err = logger.removeDayLocked( day ); err != nil { return }
			result.Deleted += 1
			continue
		}
		if logger.Settings().CompressAfterDays > 0 && age >= logger.Settings().CompressAfterDays {
			compressed := false
			for _ , file := range parts {
				if file.compressed { continue }
				if err = compressFile( file ); err != nil { return }
				compressed = true
			}
			if compressed { result.Compressed += 1 }
		}
	}

	by_day , err = logger.files()
	if err != nil { return }
	total := totalBytes( by_day )
	order := make( []string , 0 , len( by_day ) )
	for day := range by_day {
		if day != today { order = append( order , day ) }
	}
	sort.Strings( order )
	for _ , day := range order {
		if total <= logger.Settings().MaxTotalBytes { break }
		if err = logger.removeDayLocked( day ); err != nil { return }
		for _ , file := range by_day[ day ] {
			total -= file.size
		}
		result.Deleted += 1
	}
	result.BytesAfter = total
	return
}

func totalBytes( by_day map[string][]dayFile ) ( total int64 ) {
	for _ , parts := range by_day {
		for _ , file := range parts {
			total += file.size
		}
	}
	return
}

// RekeyFiles writes a copy of every log file in directory into staging, with
// each line moved from old_key to new_key and every file still gzipped or not
// as it was. It returns how many files it wrote.
//
// A line that does not open with old_key is copied as it stands: a half-written
// last line, or one left from a time encryption was off or another key was in
// use. Nothing could read those before, so nothing is lost, and dropping them
// would make this a tool that deletes things it does not understand.
func RekeyFiles( directory string , staging string , old_key string , new_key string ) ( count int , err error ) {
	entries , err := os.ReadDir( directory )
	if err != nil { return }
	if err = os.MkdirAll( staging , 0o700 ); err != nil { return }
	reader := &Logger{ key: old_key , encrypt: true }
	for _ , entry := range entries {
		if filePattern.MatchString( entry.Name() ) == false || entry.Type().IsRegular() == false { continue }
		source := filepath.Join( directory , entry.Name() )
		if err = rekeyFile( reader , source , filepath.Join( staging , entry.Name() ) , new_key ); err != nil {
			err = fmt.Errorf( "could not move %s to the new key: %w" , source , err )
			return
		}
		count++
	}
	return
}

func rekeyFile( reader *Logger , source string , target string , new_key string ) ( err error ) {
	input , err := os.Open( source )
	if err != nil { return }
	defer input.Close()
	output , err := os.OpenFile( target , os.O_WRONLY|os.O_CREATE|os.O_EXCL , 0o600 )
	if err != nil { return }
	defer output.Close()

	var lines io.Reader = input
	var writer io.Writer = output
	var zipped *gzip.Writer
	if strings.HasSuffix( source , ".gz" ) {
		unzipped , zip_err := gzip.NewReader( input )
		if zip_err != nil {
			err = zip_err
			return
		}
		defer unzipped.Close()
		lines = unzipped
		zipped = gzip.NewWriter( output )
		writer = zipped
	}

	buffered := bufio.NewReader( lines )
	for {
		line , read_err := buffered.ReadBytes( '\n' )
		if len( line ) > 0 {
			moved , move_err := rekeyLine( reader , line , new_key )
			if move_err != nil {
				err = move_err
				return
			}
			if _ , err = writer.Write( moved ); err != nil { return }
		}
		if errors.Is( read_err , io.EOF ) { break }
		if read_err != nil {
			err = read_err
			return
		}
	}
	if zipped != nil {
		if err = zipped.Close(); err != nil { return }
	}
	if err = output.Sync(); err != nil { return }
	err = output.Close()
	return
}

func rekeyLine( reader *Logger , line []byte , new_key string ) ( result []byte , err error ) {
	result = line
	trimmed := bytes.TrimSpace( line )
	if len( trimmed ) == 0 || trimmed[ 0 ] == '{' { return }
	plain , decode_err := reader.decode( trimmed )
	if decode_err != nil { return }
	sealed , err := encryption.ChaChaEncryptBytes( new_key , plain )
	if err != nil { return }
	result = make( []byte , base64.StdEncoding.EncodedLen( len( sealed ) ) + 1 )
	base64.StdEncoding.Encode( result , sealed )
	result[ len( result ) - 1 ] = '\n'
	return
}

// compressFile gzips one part next to itself, then removes the original. The
// .gz appears only once it is complete (a temporary name, then a rename), so
// a crash halfway leaves the original and a stray .tmp, never half a day.
func compressFile( file dayFile ) ( err error ) {
	target := filepath.Join( filepath.Dir( file.path ) , partName( file.day , file.part , true ) )
	temporary := target + ".tmp"
	source , err := os.Open( file.path )
	if err != nil { return }
	defer source.Close()
	output , err := os.OpenFile( temporary , os.O_CREATE | os.O_TRUNC | os.O_WRONLY , 0o600 )
	if err != nil { return }
	zipped := gzip.NewWriter( output )
	_ , copy_err := io.Copy( zipped , source )
	close_err := zipped.Close()
	file_err := output.Close()
	if err = errors.Join( copy_err , close_err , file_err ); err != nil {
		os.Remove( temporary )
		err = fmt.Errorf( "could not compress %s: %w" , file.path , err )
		return
	}
	if err = os.Rename( temporary , target ); err != nil { return }
	err = os.Remove( file.path )
	return
}
