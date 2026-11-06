package models

import (
	bytes "bytes"
	errors "errors"
	io "io"
	os "os"
	filepath "path/filepath"
	strings "strings"
	sync "sync"
	testing "testing"
	time "time"

	config "ipb/server/config"
	db "ipb/server/db"
)

func fileFixture( t *testing.T ) ( store *db.Store , cfg *config.Config ) {
	t.Helper()
	store = testStore( t )
	directory := t.TempDir()
	cfg = &config.Config{
		SecretKey: strings.Repeat( "ab" , 32 ),
		Files: config.FilesConfig{
			Enabled:           true,
			MaxFileBytes:      64 << 20,
			QuotaBytesPerUser: 64 << 20,
			AbandonedAfter:    time.Hour,
			Dir:               filepath.Join( directory , "storage" , "files" ),
			UploadsDir:        filepath.Join( directory , "uploads" ),
		},
	}
	return
}

// pattern is not all one byte, so a piece out of place would show.
func pattern( size int ) ( content []byte ) {
	content = make( []byte , size )
	for index := range content {
		content[ index ] = byte( index * 31 + index / 251 )
	}
	return
}

func stored( t *testing.T , store *db.Store , cfg *config.Config , user_id uint64 , content []byte ) ( file *File ) {
	t.Helper()
	file , err := CreateFile( store , cfg , user_id , "report.pdf" , "application/pdf" , int64( len( content ) ) )
	if err != nil { t.Fatal( err ) }
	for index := 0 ; index < file.Chunks ; index++ {
		start := index * config.FileChunkBytes
		end := min( start + config.FileChunkBytes , len( content ) )
		if err = WriteFileChunk( store , cfg , file , index , content[ start:end ] ); err != nil { t.Fatal( err ) }
	}
	if file , err = GetFile( store , file.ID ); err != nil { t.Fatal( err ) }
	if file , err = FinishFile( store , cfg , file ); err != nil { t.Fatal( err ) }
	return
}

func readAll( cfg *config.Config , file *File ) ( content []byte , err error ) {
	reader , err := OpenFile( cfg , file )
	if err != nil { return }
	defer reader.Close()
	content , err = io.ReadAll( reader )
	return
}

func TestAFileComesBackExactly( t *testing.T ) {
	store , cfg := fileFixture( t )
	for _ , size := range []int{ 0 , 1 , config.FileChunkBytes - 1 , config.FileChunkBytes , config.FileChunkBytes + 1 , 3 * config.FileChunkBytes } {
		content := pattern( size )
		file := stored( t , store , cfg , 1 , content )
		if file.State != FileReady { t.Fatalf( "%d: state %s" , size , file.State ) }
		back , err := readAll( cfg , file )
		if err != nil { t.Fatalf( "%d: %v" , size , err ) }
		if bytes.Equal( back , content ) == false { t.Fatalf( "%d: came back different" , size ) }
	}
}

func TestNothingOnDiskIsInTheClear( t *testing.T ) {
	store , cfg := fileFixture( t )
	marker := []byte( "the plain text of this file" )
	file := stored( t , store , cfg , 1 , bytes.Repeat( marker , 1000 ) )
	raw , err := os.ReadFile( finishedPath( cfg , file.ID ) )
	if err != nil { t.Fatal( err ) }
	if bytes.Contains( raw , marker ) { t.Fatal( "the file is on disk in the clear" ) }
}

func TestAPieceOnlyOpensInItsOwnPlace( t *testing.T ) {
	store , cfg := fileFixture( t )
	content := pattern( 3 * config.FileChunkBytes )
	piece := config.FileChunkBytes + fileChunkOverhead

	swapped := stored( t , store , cfg , 1 , content )
	path := finishedPath( cfg , swapped.ID )
	raw , _ := os.ReadFile( path )
	reordered := append( append( append( []byte{} , raw[ piece:2 * piece ]... ) , raw[ :piece ]... ) , raw[ 2 * piece: ]... )
	os.WriteFile( path , reordered , 0o600 )
	if _ , err := readAll( cfg , swapped ); err == nil { t.Fatal( "reordered pieces opened" ) }

	other := stored( t , store , cfg , 1 , content )
	foreign := stored( t , store , cfg , 1 , content )
	raw , _ = os.ReadFile( finishedPath( cfg , foreign.ID ) )
	os.WriteFile( finishedPath( cfg , other.ID ) , raw , 0o600 )
	if _ , err := readAll( cfg , other ); err == nil { t.Fatal( "another file's data opened" ) }

	changed := stored( t , store , cfg , 1 , content )
	raw , _ = os.ReadFile( finishedPath( cfg , changed.ID ) )
	raw[ 100 ] ^= 1
	os.WriteFile( finishedPath( cfg , changed.ID ) , raw , 0o600 )
	if _ , err := readAll( cfg , changed ); err == nil { t.Fatal( "a changed byte opened" ) }

	// A whole piece cut off is the wrong size, and the count in what each
	// piece is sealed to would refuse it anyway.
	cut := stored( t , store , cfg , 1 , content )
	raw , _ = os.ReadFile( finishedPath( cfg , cut.ID ) )
	os.WriteFile( finishedPath( cfg , cut.ID ) , raw[ :2 * piece ] , 0o600 )
	if _ , err := OpenFile( cfg , cut ); errors.Is( err , ErrFileMissing ) == false { t.Fatalf( "cut: %v" , err ) }
	shorter := *cut
	shorter.Chunks , shorter.Size = 2 , int64( 2 * config.FileChunkBytes )
	if _ , err := readAll( cfg , &shorter ); err == nil { t.Fatal( "a shortened record opened" ) }
}

func TestChunkWritesSurviveARetryAndRefuseGaps( t *testing.T ) {
	store , cfg := fileFixture( t )
	content := pattern( 2 * config.FileChunkBytes )
	file , err := CreateFile( store , cfg , 1 , "a" , "" , int64( len( content ) ) )
	if err != nil { t.Fatal( err ) }
	first := content[ :config.FileChunkBytes ]
	if err = WriteFileChunk( store , cfg , file , 0 , first[ :10 ] ); errors.Is( err , ErrFileChunkSize ) == false { t.Fatalf( "short: %v" , err ) }
	// The second piece with the first missing would leave a hole.
	if err = WriteFileChunk( store , cfg , file , 1 , content[ config.FileChunkBytes: ] ); errors.Is( err , ErrFileMissing ) == false { t.Fatalf( "gap: %v" , err ) }
	// A crash after the write and before the record leaves the same piece to
	// send again.
	for attempt := 0 ; attempt < 2 ; attempt++ {
		if err = WriteFileChunk( store , cfg , file , 0 , first ); err != nil { t.Fatal( err ) }
	}
	if err = WriteFileChunk( store , cfg , file , 1 , content[ config.FileChunkBytes: ] ); err != nil { t.Fatal( err ) }
	file , _ = GetFile( store , file.ID )
	if file , err = FinishFile( store , cfg , file ); err != nil { t.Fatal( err ) }
	back , err := readAll( cfg , file )
	if err != nil || bytes.Equal( back , content ) == false { t.Fatalf( "%v" , err ) }
}

func TestFinishGoesOnAfterACrashBeforeTheRecord( t *testing.T ) {
	store , cfg := fileFixture( t )
	content := pattern( 10 )
	file , _ := CreateFile( store , cfg , 1 , "a" , "" , 10 )
	if err := WriteFileChunk( store , cfg , file , 0 , content ); err != nil { t.Fatal( err ) }
	file , _ = GetFile( store , file.ID )
	os.MkdirAll( cfg.Files.Dir , 0o700 )
	if err := os.Rename( uploadPath( cfg , file.ID ) , finishedPath( cfg , file.ID ) ); err != nil { t.Fatal( err ) }
	finished , err := FinishFile( store , cfg , file )
	if err != nil || finished.State != FileReady { t.Fatalf( "%v %v" , finished , err ) }
}

func TestLimitsAreChecked( t *testing.T ) {
	store , cfg := fileFixture( t )
	cfg.Files.MaxFileBytes = 100
	if _ , err := CreateFile( store , cfg , 1 , "a" , "" , 101 ); errors.Is( err , ErrFileTooLarge ) == false { t.Fatalf( "%v" , err ) }
	for _ , name := range []string{ "" , "  " , "dir/" , strings.Repeat( "x" , 256 ) } {
		if _ , err := CreateFile( store , cfg , 1 , name , "" , 1 ); errors.Is( err , ErrBadFile ) == false { t.Fatalf( "%q: %v" , name , err ) }
	}
	if _ , err := CreateFile( store , cfg , 1 , "a" , "" , -1 ); errors.Is( err , ErrBadFile ) == false { t.Fatalf( "%v" , err ) }
}

func TestANameLosesItsPath( t *testing.T ) {
	for sent , wanted := range map[string]string{
		"../../etc/passwd":   "passwd",
		`C:\Users\a\b.txt`:   "b.txt",
		"a\x00b\r\n.txt":     "ab.txt",
		"  naïve résumé.pdf": "naïve résumé.pdf",
	} {
		if cleaned := CleanFileName( sent ); cleaned != wanted { t.Fatalf( "%q: %q" , sent , cleaned ) }
	}
}

func TestParallelUploadsCannotPassTheQuota( t *testing.T ) {
	store , cfg := fileFixture( t )
	cfg.Files.QuotaBytesPerUser = 100
	var group sync.WaitGroup
	var mutex sync.Mutex
	made := 0
	for attempt := 0 ; attempt < 20 ; attempt++ {
		group.Add( 1 )
		go func() {
			defer group.Done()
			if _ , err := CreateFile( store , cfg , 1 , "a" , "" , 30 ); err == nil {
				mutex.Lock()
				made++
				mutex.Unlock()
			}
		}()
	}
	group.Wait()
	if made != 3 { t.Fatalf( "%d uploads got in" , made ) }
	// Someone else's quota is their own.
	if _ , err := CreateFile( store , cfg , 2 , "a" , "" , 100 ); err != nil { t.Fatal( err ) }
}

func TestDeletingFreesTheQuotaAndRestoringTakesItBack( t *testing.T ) {
	store , cfg := fileFixture( t )
	cfg.Files.QuotaBytesPerUser = 100
	file , _ := CreateFile( store , cfg , 1 , "a" , "" , 80 )
	if err := DeleteFile( store , file.ID , 1 ); err != nil { t.Fatal( err ) }
	if err := DeleteFile( store , file.ID , 1 ); errors.Is( err , db.ErrNotFound ) == false { t.Fatalf( "%v" , err ) }
	second , err := CreateFile( store , cfg , 1 , "b" , "" , 80 )
	if err != nil { t.Fatal( err ) }
	if _ , err = RestoreFile( store , cfg , file.ID , 1 , false ); errors.Is( err , ErrFileQuota ) == false { t.Fatalf( "%v" , err ) }
	DeleteFile( store , second.ID , 1 )
	if _ , err = RestoreFile( store , cfg , file.ID , 1 , false ); err != nil { t.Fatal( err ) }
}

func setFile( t *testing.T , store *db.Store , file_id string , change func( file *File ) ) {
	t.Helper()
	err := store.UpdateValue( db.BucketFiles , []byte( file_id ) , func() any { return &File{} } , func( item any ) ( mutate_err error ) {
		change( item.( *File ) )
		return
	} )
	if err != nil { t.Fatal( err ) }
}

func TestTheSweep( t *testing.T ) {
	store , cfg := fileFixture( t )
	user , _ := CreateUser( store , "Alice" , RoleUser )
	kept := stored( t , store , cfg , user.ID , pattern( 10 ) )
	long_ago := time.Now().UTC().Add( -2 * RestoreWindow )

	deleted := stored( t , store , cfg , user.ID , pattern( 10 ) )
	setFile( t , store , deleted.ID , func( file *File ) { file.DeletedAt = &long_ago } )
	recent := stored( t , store , cfg , user.ID , pattern( 10 ) )
	DeleteFile( store , recent.ID , user.ID )

	abandoned , _ := CreateFile( store , cfg , user.ID , "a" , "" , 10 )
	WriteFileChunk( store , cfg , abandoned , 0 , pattern( 10 ) )
	setFile( t , store , abandoned.ID , func( file *File ) { file.UpdatedAt = time.Now().UTC().Add( -2 * time.Hour ) } )
	active , _ := CreateFile( store , cfg , user.ID , "a" , "" , 10 )

	orphaned := stored( t , store , cfg , 9999 , pattern( 10 ) )

	old_stray := filepath.Join( cfg.Files.Dir , "stray" )
	new_stray := filepath.Join( cfg.Files.UploadsDir , "arriving" )
	os.WriteFile( old_stray , []byte( "x" ) , 0o600 )
	os.WriteFile( new_stray , []byte( "x" ) , 0o600 )
	aged := time.Now().Add( -2 * fileStrayAge )
	os.Chtimes( old_stray , aged , aged )

	removed , strays , err := SweepFiles( store , cfg )
	if err != nil { t.Fatal( err ) }
	if removed != 3 || strays != 1 { t.Fatalf( "removed %d, strays %d" , removed , strays ) }
	for _ , gone := range []*File{ deleted , abandoned , orphaned } {
		if _ , err = GetFile( store , gone.ID ); errors.Is( err , db.ErrNotFound ) == false { t.Fatalf( "record: %v" , err ) }
		for _ , path := range []string{ uploadPath( cfg , gone.ID ) , finishedPath( cfg , gone.ID ) } {
			if _ , err = os.Stat( path ); err == nil { t.Fatalf( "%s is still there" , path ) }
		}
	}
	for _ , alive := range []*File{ kept , recent , active } {
		if _ , err = GetFile( store , alive.ID ); err != nil { t.Fatal( err ) }
	}
	if _ , err = readAll( cfg , kept ); err != nil { t.Fatal( err ) }
	if _ , err = os.Stat( old_stray ); err == nil { t.Fatal( "the old stray is still there" ) }
	if _ , err = os.Stat( new_stray ); err != nil { t.Fatal( "the young stray was removed" ) }
}

func TestRecordsOutliveAMissingFilesDirectory( t *testing.T ) {
	store , cfg := fileFixture( t )
	if _ , _ , err := SweepFiles( store , cfg ); err != nil { t.Fatal( err ) }
}

func TestUploadLocks( t *testing.T ) {
	locks := UploadLocks{}
	if locks.Hold( "a" ) == false || locks.Hold( "a" ) || locks.Hold( "b" ) == false { t.Fatal( "held wrongly" ) }
	locks.Release( "a" )
	if locks.Hold( "a" ) == false { t.Fatal( "not released" ) }
}
