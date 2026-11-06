package models

import (
	errors "errors"
	fmt "fmt"
	io "io"
	os "os"
	filepath "path/filepath"
	sort "sort"
	strings "strings"
	sync "sync"
	time "time"
	unicode "unicode"

	config "ipb/server/config"
	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// Uploaded files. The record here describes one; the bytes are on disk.
//
// A file arrives in pieces of config.FileChunkBytes, each an ordinary request
// under the global body limit. That is why nothing here raises the limit: the
// alternative is a server-wide streaming switch, which takes the limit away
// from every route, including the public ones. It also means a file is
// encrypted as it arrives and never sits in a temp directory in the clear.
//
// Each file has its own random key, and only that key is sealed with the
// secret key. Moving to a new secret key therefore rewrites one field of the
// record (see rekeyFields) rather than every file on disk, and needs nothing
// from rotate-key or a restore beyond what they already do for a sealed field.
//
// Each piece is sealed on its own, bound to the file's id, its index and the
// number of pieces, so it opens only where it belongs. All pieces but the last
// are the same size, which puts every piece at an offset that can be computed
// and leaves the disk format with nothing else in it.

const (
	FileUploading = "uploading"
	FileReady     = "ready"

	// fileChunkOverhead is what sealing adds to a piece: nonce and tag.
	fileChunkOverhead = 24 + 16
	fileNameMax       = 255
	fileTypeMax       = 127
	// fileStrayAge is how old a file with no record must be before it is
	// removed. Finishing a file renames it before the record says so, and a
	// restore can leave either one without the other.
	fileStrayAge = 24 * time.Hour
)

var (
	// The two that a person sees are codes, worded in language.yaml.
	ErrBadFile       = errors.New( "a file needs a name and a size" )
	ErrBadFileName   = errors.New( "a file name must be 1-255 bytes" )
	ErrFileTooLarge  = errors.New( "file_too_large" )
	ErrFileQuota     = errors.New( "file_quota" )
	ErrFileChunkSize = errors.New( "that piece is the wrong size" )
	// ErrFileMissing is a record whose bytes are not there.
	ErrFileMissing = errors.New( "that file's data is missing" )
)

type File struct {
	ID     string `json:"id"`
	UserID uint64 `json:"user_id"`
	Name   string `json:"name"`
	// Type is what the uploader said it is. It is shown, and never served:
	// a download is always application/octet-stream.
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Chunks   int    `json:"chunks"`
	Received int    `json:"received"`
	State    string `json:"state"`
	// Key is this file's own key, sealed with the secret key. It is in
	// rekeyFields, so it follows a rotation.
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the last piece arrived.
	UpdatedAt time.Time `json:"updated_at"`
	SoftDelete
}

func fileChunkCount( size int64 ) ( chunks int ) {
	chunks = int( ( size + config.FileChunkBytes - 1 ) / config.FileChunkBytes )
	return
}

// chunkLength is how many bytes piece index holds.
func ( file *File ) chunkLength( index int ) ( length int ) {
	length = config.FileChunkBytes
	if index == file.Chunks - 1 {
		length = int( file.Size - int64( index ) * config.FileChunkBytes )
	}
	return
}

// sealedOffset is where piece index starts on disk.
func sealedOffset( index int ) ( offset int64 ) {
	offset = int64( index ) * ( config.FileChunkBytes + fileChunkOverhead )
	return
}

func ( file *File ) sealedSize() ( size int64 ) {
	size = file.Size + int64( file.Chunks ) * fileChunkOverhead
	return
}

// chunkBound is what a piece is sealed to. Without the count, a file cut off
// after a whole piece would still open.
func ( file *File ) chunkBound( index int ) ( bound []byte ) {
	bound = []byte( fmt.Sprintf( "%s|%d|%d" , file.ID , index , file.Chunks ) )
	return
}

func uploadPath( cfg *config.Config , file_id string ) ( path string ) {
	path = filepath.Join( cfg.Files.UploadsDir , file_id )
	return
}

func finishedPath( cfg *config.Config , file_id string ) ( path string ) {
	path = filepath.Join( cfg.Files.Dir , file_id )
	return
}

// CleanFileName keeps the last part of whatever path a client sent, without
// control characters. It is only ever shown and offered as a download name:
// paths on disk use the id.
func CleanFileName( name string ) ( result string ) {
	if cut := strings.LastIndexAny( name , `/\` ); cut >= 0 {
		name = name[ cut + 1: ]
	}
	result = strings.TrimSpace( strings.Map( func( character rune ) rune {
		if unicode.IsControl( character ) || character == unicode.ReplacementChar { return -1 }
		return character
	} , name ) )
	return
}

// usedBytes is what an account holds against its quota. Uploads still arriving
// count at their full size, or several at once could pass the check together.
func usedBytes( tx *db.Tx , user_id uint64 ) ( used int64 , err error ) {
	err = tx.ForEach( db.BucketFiles , func() any { return &File{} } , func( _ []byte , item any ) bool {
		file := item.( *File )
		if file.UserID == user_id && file.Deleted() == false {
			used += file.Size
		}
		return true
	} )
	return
}

// StorageUsed is usedBytes outside a transaction, for showing it: one account,
// or every account for user_id 0.
func StorageUsed( store *db.Store , user_id uint64 ) ( used int64 , err error ) {
	err = store.ForEach( db.BucketFiles , func() any { return &File{} } , func( _ []byte , item any ) bool {
		file := item.( *File )
		if ( user_id == 0 || file.UserID == user_id ) && file.Deleted() == false {
			used += file.Size
		}
		return true
	} )
	return
}

// CreateFile starts an upload. The quota is checked in the same transaction
// that adds the record, so two uploads cannot both take the last of it.
func CreateFile( store *db.Store , cfg *config.Config , user_id uint64 , name string , declared_type string , size int64 ) ( file *File , err error ) {
	name = CleanFileName( name )
	if name == "" || len( name ) > fileNameMax || size < 0 || len( declared_type ) > fileTypeMax {
		err = ErrBadFile
		return
	}
	if size > cfg.Files.MaxFileBytes {
		err = ErrFileTooLarge
		return
	}
	key , err := encryption.ChaChaEncryptString( cfg.SecretKey , encryption.GenerateKeyHex() )
	if err != nil { return }
	now := time.Now().UTC()
	made := &File{
		ID:        encryption.GenerateURLToken( 12 ),
		UserID:    user_id,
		Name:      name,
		Type:      declared_type,
		Size:      size,
		Chunks:    fileChunkCount( size ),
		State:     FileUploading,
		Key:       key,
		CreatedAt: now,
		UpdatedAt: now,
	}
	err = store.Write( func( tx *db.Tx ) ( write_err error ) {
		used , write_err := usedBytes( tx , user_id )
		if write_err != nil { return }
		if used + size > cfg.Files.QuotaBytesPerUser {
			write_err = ErrFileQuota
			return
		}
		write_err = tx.Put( db.BucketFiles , []byte( made.ID ) , made )
		return
	} )
	if err == nil { file = made }
	return
}

func GetFile( store *db.Store , file_id string ) ( file *File , err error ) {
	file = &File{}
	if err = store.Get( db.BucketFiles , []byte( file_id ) , file ); err != nil {
		file = nil
	}
	return
}

// ListFiles is the finished files, newest first: every account's when user_id
// is 0, which no account has.
func ListFiles( store *db.Store , user_id uint64 ) ( files []*File , err error ) {
	files = []*File{}
	err = store.ForEach( db.BucketFiles , func() any { return &File{} } , func( _ []byte , item any ) bool {
		file := item.( *File )
		if file.State == FileReady && file.Deleted() == false && ( user_id == 0 || file.UserID == user_id ) {
			files = append( files , file )
		}
		return true
	} )
	sort.SliceStable( files , func( i int , j int ) bool { return files[ i ].CreatedAt.After( files[ j ].CreatedAt ) } )
	return
}

// WriteFileChunk seals one piece and puts it at its place in the upload. It
// goes to a computed offset, and whatever follows is cut off, so a retry after
// a crash between the write and the record's update simply writes it again.
// The caller holds the UploadLocks entry and has checked index is the next one.
func WriteFileChunk( store *db.Store , cfg *config.Config , file *File , index int , plain []byte ) ( err error ) {
	if len( plain ) != file.chunkLength( index ) {
		err = ErrFileChunkSize
		return
	}
	file_key , err := encryption.ChaChaDecryptBase64String( cfg.SecretKey , file.Key )
	if err != nil { return }
	sealed , err := encryption.ChaChaEncryptBound( file_key , plain , file.chunkBound( index ) )
	if err != nil { return }

	if err = os.MkdirAll( cfg.Files.UploadsDir , 0o700 ); err != nil { return }
	flags := os.O_WRONLY
	if index == 0 { flags |= os.O_CREATE }
	target , err := os.OpenFile( uploadPath( cfg , file.ID ) , flags , 0o600 )
	if errors.Is( err , os.ErrNotExist ) { err = ErrFileMissing }
	if err != nil { return }
	defer target.Close()
	// Short of where this piece goes means the pieces before it are gone, as
	// after a restore. Writing anyway would leave a hole.
	info , err := target.Stat()
	if err != nil { return }
	offset := sealedOffset( index )
	if info.Size() < offset {
		err = ErrFileMissing
		return
	}
	if _ , err = target.WriteAt( sealed , offset ); err != nil { return }
	if err = target.Truncate( offset + int64( len( sealed ) ) ); err != nil { return }
	// Before the record, which is durable as soon as it is written, says the
	// piece is here.
	if err = target.Sync(); err != nil { return }

	err = store.UpdateValue( db.BucketFiles , []byte( file.ID ) ,
		func() any { return &File{} } ,
		func( item any ) ( mutate_err error ) {
			stored := item.( *File )
			stored.Received = index + 1
			stored.UpdatedAt = time.Now().UTC()
			return
		} )
	return
}

// FinishFile moves a complete upload into place and marks it ready. Asked again
// after a crash between the two, it finds the file already moved and goes on.
func FinishFile( store *db.Store , cfg *config.Config , file *File ) ( finished *File , err error ) {
	// Both, here rather than at startup: an empty file has written no piece,
	// and a restore replaces storage/ with whatever the backup held.
	for _ , directory := range []string{ cfg.Files.Dir , cfg.Files.UploadsDir } {
		if err = os.MkdirAll( directory , 0o700 ); err != nil { return }
	}
	source := uploadPath( cfg , file.ID )
	target := finishedPath( cfg , file.ID )
	if file.Chunks == 0 {
		if err = os.WriteFile( source , nil , 0o600 ); err != nil { return }
	}
	info , stat_err := os.Stat( source )
	switch {
	case stat_err == nil:
		if info.Size() != file.sealedSize() {
			err = ErrFileMissing
			return
		}
		if err = os.Rename( source , target ); err != nil { return }
	case errors.Is( stat_err , os.ErrNotExist ):
		if info , stat_err = os.Stat( target ); stat_err != nil || info.Size() != file.sealedSize() {
			err = ErrFileMissing
			return
		}
	default:
		err = stat_err
		return
	}
	err = store.UpdateValue( db.BucketFiles , []byte( file.ID ) ,
		func() any { return &File{} } ,
		func( item any ) ( mutate_err error ) {
			finished = item.( *File )
			finished.State = FileReady
			finished.UpdatedAt = time.Now().UTC()
			return
		} )
	if err != nil { finished = nil }
	return
}

// RenameFile changes the name a file is shown and downloaded under, and answers
// it as cleaned. Only the record changes: paths on disk use the id, and a piece
// is sealed to the id too. db.ErrNotFound when there is no such file, it is
// deleted, or it is still uploading. expect, when not nil, is the name the
// caller believes is stored, as in RenameUser: a *RenameConflictError if not.
func RenameFile( store *db.Store , file_id string , name string , expect *string ) ( cleaned string , err error ) {
	clean := CleanFileName( name )
	if clean == "" || len( clean ) > fileNameMax {
		err = ErrBadFileName
		return
	}
	err = store.UpdateValue( db.BucketFiles , []byte( file_id ) ,
		func() any { return &File{} } ,
		func( item any ) ( mutate_err error ) {
			file := item.( *File )
			if file.Deleted() || file.State != FileReady {
				mutate_err = db.ErrNotFound
				return
			}
			if expect != nil && file.Name != *expect {
				mutate_err = &RenameConflictError{ Current: file.Name }
				return
			}
			file.Name = clean
			return
		} )
	if err == nil { cleaned = clean }
	return
}

// DeleteFile marks it, for the usual undo window. The bytes stay until the
// sweep. A file already deleted is simply not there.
func DeleteFile( store *db.Store , file_id string , actor_id uint64 ) ( err error ) {
	err = store.UpdateValue( db.BucketFiles , []byte( file_id ) ,
		func() any { return &File{} } ,
		func( item any ) ( mutate_err error ) {
			if item.( *File ).markDeleted( actor_id ) == false {
				mutate_err = db.ErrNotFound
			}
			return
		} )
	return
}

// RestoreFile undoes a delete. It counts against the quota again, so that is
// checked here the same way as for a new upload.
func RestoreFile( store *db.Store , cfg *config.Config , file_id string , actor_id uint64 , actor_is_admin bool ) ( file *File , err error ) {
	err = store.Write( func( tx *db.Tx ) ( write_err error ) {
		stored := &File{}
		if write_err = tx.Get( db.BucketFiles , []byte( file_id ) , stored ); write_err != nil { return }
		if write_err = stored.unmarkDeleted( actor_id , actor_is_admin ); write_err != nil { return }
		used , write_err := usedBytes( tx , stored.UserID )
		if write_err != nil { return }
		if used + stored.Size > cfg.Files.QuotaBytesPerUser {
			write_err = ErrFileQuota
			return
		}
		if write_err = tx.Put( db.BucketFiles , []byte( file_id ) , stored ); write_err != nil { return }
		file = stored
		return
	} )
	if errors.Is( err , db.ErrNotFound ) { err = ErrRestoreGone }
	if err != nil { file = nil }
	return
}

// FileReader gives back a finished file's plain bytes, a piece at a time, so
// memory stays flat whatever the size. A piece that does not open is an error,
// and nothing from it is handed out.
type FileReader struct {
	file     *File
	key      string
	source   *os.File
	index    int
	pending  []byte
	// BeforeRead runs ahead of each piece. A download uses it to move the
	// connection's write deadline along.
	BeforeRead func()
}

// OpenFile starts reading a finished file. ErrFileMissing means the bytes are
// gone, or are not the size the record says.
func OpenFile( cfg *config.Config , file *File ) ( reader *FileReader , err error ) {
	key , err := encryption.ChaChaDecryptBase64String( cfg.SecretKey , file.Key )
	if err != nil { return }
	source , err := os.Open( finishedPath( cfg , file.ID ) )
	if errors.Is( err , os.ErrNotExist ) { err = ErrFileMissing }
	if err != nil { return }
	info , err := source.Stat()
	if err == nil && info.Size() != file.sealedSize() { err = ErrFileMissing }
	if err != nil {
		source.Close()
		return
	}
	reader = &FileReader{ file: file , key: key , source: source }
	return
}

func ( reader *FileReader ) Read( into []byte ) ( count int , err error ) {
	if len( reader.pending ) == 0 {
		if reader.index >= reader.file.Chunks {
			err = io.EOF
			return
		}
		if reader.BeforeRead != nil { reader.BeforeRead() }
		sealed := make( []byte , reader.file.chunkLength( reader.index ) + fileChunkOverhead )
		if _ , err = io.ReadFull( reader.source , sealed ); err != nil { return }
		reader.pending , err = encryption.ChaChaDecryptBound( reader.key , sealed , reader.file.chunkBound( reader.index ) )
		if err != nil { return }
		reader.index++
	}
	count = copy( into , reader.pending )
	reader.pending = reader.pending[ count: ]
	return
}

func ( reader *FileReader ) Close() ( err error ) {
	err = reader.source.Close()
	return
}

// SweepFiles is the cleanup job's work. A deleted file past its undo window, an
// upload nobody has touched for files.abandoned_upload_hours and a file whose
// account has gone lose their record and then their bytes, so a crash between
// the two leaves a stray rather than a record pointing at nothing. Strays are
// the last step. Every step runs whatever happens to the one before it.
func SweepFiles( store *db.Store , cfg *config.Config ) ( removed int , strays int , err error ) {
	users , users_err := ListUsers( store )
	accounts := map[ uint64 ]bool{}
	for _ , user := range users {
		accounts[ user.ID ] = true
	}
	cutoff := time.Now().UTC().Add( -cfg.Files.AbandonedAfter )
	doomed := []string{}
	// Without the accounts, every file would look like it had lost its owner.
	if users_err == nil {
		removed , err = store.DeleteWhere( db.BucketFiles , func() any { return &File{} } , func( key []byte , item any ) ( gone bool ) {
			file := item.( *File )
			gone = file.deletedLongAgo() || accounts[ file.UserID ] == false ||
				( file.State == FileUploading && file.UpdatedAt.Before( cutoff ) )
			if gone { doomed = append( doomed , string( key ) ) }
			return
		} )
	}
	failures := []error{ users_err , err }
	for _ , file_id := range doomed {
		failures = append( failures , removeFileData( cfg , file_id ) )
	}
	strays , stray_err := removeStrays( store , cfg )
	err = errors.Join( append( failures , stray_err )... )
	return
}

func removeFileData( cfg *config.Config , file_id string ) ( err error ) {
	for _ , path := range []string{ uploadPath( cfg , file_id ) , finishedPath( cfg , file_id ) } {
		if remove_err := os.Remove( path ); remove_err != nil && errors.Is( remove_err , os.ErrNotExist ) == false {
			err = errors.Join( err , remove_err )
		}
	}
	return
}

// removeStrays reads the record ids after the directories, so a file arriving
// in between has its record seen. Its age would keep it safe anyway.
func removeStrays( store *db.Store , cfg *config.Config ) ( removed int , err error ) {
	type candidate struct { path , name string }
	candidates := []candidate{}
	old := time.Now().Add( -fileStrayAge )
	for _ , directory := range []string{ cfg.Files.UploadsDir , cfg.Files.Dir } {
		entries , read_err := os.ReadDir( directory )
		if errors.Is( read_err , os.ErrNotExist ) { continue }
		if read_err != nil {
			err = errors.Join( err , read_err )
			continue
		}
		for _ , entry := range entries {
			info , info_err := entry.Info()
			if info_err != nil || info.Mode().IsRegular() == false || info.ModTime().After( old ) { continue }
			candidates = append( candidates , candidate{ filepath.Join( directory , entry.Name() ) , entry.Name() } )
		}
	}
	if len( candidates ) == 0 { return }
	known := map[ string ]bool{}
	list_err := store.ForEach( db.BucketFiles , func() any { return &File{} } , func( key []byte , _ any ) bool {
		known[ string( key ) ] = true
		return true
	} )
	if list_err != nil {
		err = errors.Join( err , list_err )
		return
	}
	for _ , stray := range candidates {
		if known[ stray.name ] { continue }
		if remove_err := os.Remove( stray.path ); remove_err != nil {
			err = errors.Join( err , remove_err )
			continue
		}
		removed++
	}
	return
}

// UploadLocks keeps two requests from writing one upload at once. It lives in
// the process, like the rate limiter, because this template is one process.
type UploadLocks struct {
	mutex sync.Mutex
	held  map[ string ]bool
}

// Hold claims file_id; false means another request has it.
func ( locks *UploadLocks ) Hold( file_id string ) ( held bool ) {
	locks.mutex.Lock()
	defer locks.mutex.Unlock()
	if locks.held == nil { locks.held = map[ string ]bool{} }
	if locks.held[ file_id ] { return }
	locks.held[ file_id ] = true
	held = true
	return
}

func ( locks *UploadLocks ) Release( file_id string ) {
	locks.mutex.Lock()
	defer locks.mutex.Unlock()
	delete( locks.held , file_id )
}
