package config

// The running configuration, and the one way it changes.
//
// config.yaml can change under a running server two ways: the owner saves
// the Settings screen (Save), or someone edits the file -- by hand, with
// `config set`, from another machine -- and the watcher notices (Poll). Both
// end in Apply, which validates the whole file and either swaps in a new
// Config or changes nothing. A file that does not validate is reported and
// ignored; the server keeps running on the last version that did.
//
// Only [live] keys (see schema.go) change in the running Config. A [restart]
// key is saved and shown as pending, but the server keeps the value it
// started with -- liveConfig copies the boot Config and overwrites only the
// live fields, so a restart-only setting cannot leak in half-applied.
//
// Everything that reads configuration per request reads Holder.Get(), never
// a Config it was handed at startup. That is what makes a change live: the
// next request sees the new pointer.

import (
	sha256 "crypto/sha256"
	hex "encoding/hex"
	errors "errors"
	fmt "fmt"
	os "os"
	filepath "path/filepath"
	reflect "reflect"
	strings "strings"
	sync "sync"
	atomic "sync/atomic"
	time "time"
)

var (
	// ErrStale: the container's mounted config.yaml was replaced on the host
	// (an editor that saves by writing a new file and renaming it over the
	// old one). The mount still shows the old file, so neither reading nor
	// writing it means anything until the container restarts.
	ErrStale = errors.New( "config.yaml was replaced on the host; restart the container to see the new one" )
	// ErrReadOnly: this process cannot write config.yaml.
	ErrReadOnly = errors.New( "config.yaml is not writable by the server" )
	// ErrLocked: a key that cannot be changed from here -- docker.* and
	// build.* inside the container, and what the image pins.
	ErrLocked = errors.New( "this setting cannot be changed from inside the container" )
)

// ConflictError: config.yaml changed since the client read it.
type ConflictError struct {
	Version string
}

func ( conflict *ConflictError ) Error() ( result string ) {
	result = "config.yaml changed since it was loaded"
	return
}

// UnknownSettingError: a key the schema does not have.
type UnknownSettingError struct {
	Key string
}

func ( unknown *UnknownSettingError ) Error() ( result string ) {
	result = fmt.Sprintf( "unknown setting %q" , unknown.Key )
	return
}

// LoadError is the last time config.yaml failed to apply.
type LoadError struct {
	Message string    `json:"message"`
	At      time.Time `json:"at"`
	Origin  string    `json:"origin"`
}

// ApplyResult is what an Apply changed, by apply mode.
type ApplyResult struct {
	Changes []Change `json:"changes"`
	Live    []string `json:"applied"`
	Restart []string `json:"restart"`
	Scripts []string `json:"scripts"`
	// Unchanged lists submitted keys that already had the submitted value.
	Unchanged []string `json:"unchanged"`
	Version   string   `json:"version"`
}

// Version identifies one exact config.yaml: the client sends back the one it
// loaded, and a save is refused if the file is no longer that one.
func Version( raw []byte ) ( version string ) {
	sum := sha256.Sum256( raw )
	version = "sha256:" + hex.EncodeToString( sum[:] )
	return
}

type fileStat struct {
	modified time.Time
	size     int64
	links    uint64
}

// Holder owns the running Config.
type Holder struct {
	current atomic.Pointer[Config]
	boot    *Config
	// bootFile is the File the server started on: a [restart] key whose
	// value differs from it is pending a restart.
	bootFile *File

	path       string
	inPlace    bool
	backupPath string

	// mu serialises Apply, Save and Poll. Get never takes it.
	mu       sync.Mutex
	file     *File
	lastErr  *LoadError
	errHash  string
	seenHash string
	pending  string
	stat     fileStat
	stale    bool

	subscribers []func( old *Config , next *Config )

	// Report tells the operator about a reload or a rejected edit: main.go
	// points it at stdout and the activity log. The logs package imports
	// this one, so this one cannot import it back.
	Report func( level string , message string , detail map[string]any )
}

// NewHolder starts from the Config Load returned.
func NewHolder( boot *Config ) ( holder *Holder ) {
	holder = &Holder{
		boot:     boot,
		bootFile: boot.file,
		file:     boot.file,
		path:     boot.ConfigFile,
		seenHash: Version( boot.raw ),
	}
	if holder.file == nil {
		holder.file , _ = Defaults()
		holder.bootFile = holder.file
	}
	holder.current.Store( boot )
	// The container's config.yaml is a single-file bind mount: renaming a
	// new file over it fails, so it is rewritten in place, with the old
	// version kept in the (writable) app directory first.
	holder.inPlace = InContainer() && boot.ConfigFile == pinned.ConfigFile
	if holder.inPlace {
		holder.backupPath = filepath.Join( boot.AppDir , BackupFileName )
	}
	if info , err := os.Stat( holder.path ); err == nil {
		holder.stat = statOf( info )
	}
	return
}

// NewStaticHolder is a Holder that never changes, for tests and tools that
// need one without a config.yaml behind it.
func NewStaticHolder( cfg *Config ) ( holder *Holder ) {
	holder = &Holder{ boot: cfg }
	holder.current.Store( cfg )
	return
}

// Get is the current Config. Read it once per request and use that copy
// throughout, so one request never sees half of an edit.
func ( holder *Holder ) Get() ( cfg *Config ) {
	cfg = holder.current.Load()
	return
}

// Boot is the Config the server started on: what [restart] settings and
// anything set up once at startup (the listener, the control socket, the
// database) actually run with.
func ( holder *Holder ) Boot() ( cfg *Config ) {
	cfg = holder.boot
	return
}

// OnChange registers a function called after every applied change, with the
// lock held -- keep it quick.
func ( holder *Holder ) OnChange( subscriber func( old *Config , next *Config ) ) {
	holder.mu.Lock()
	defer holder.mu.Unlock()
	holder.subscribers = append( holder.subscribers , subscriber )
}

// liveConfig is boot with the [live] keys taken from file. Every live key in
// defaults.yaml must be copied here; schema_test.go checks that a live key
// changes the result and a restart key does not.
func liveConfig( boot *Config , boot_file *File , file *File ) ( next *Config ) {
	copied := *boot
	next = &copied
	next.file = file

	// The link address follows server.public_url, but host, port and the
	// docker section are whatever the server and container started with.
	effective := *file
	effective.Server.Host = boot_file.Server.Host
	effective.Server.Port = boot_file.Server.Port
	effective.Docker = boot_file.Docker
	next.URL , next.URLSource = ServerURL( &effective )

	next.SecureCookies = file.Server.SecureCookies
	next.RateLimitMax = file.Server.RateLimitMax
	next.RateLimitWindow = seconds( file.Server.RateLimitWindowSeconds )
	next.RateLimitSignInMax = file.Server.RateLimitSignInMax
	next.RateLimitUploadMax = file.Server.RateLimitUploadMax
	next.RateLimitSendMax = file.Server.RateLimitSendMax
	next.MCPEnabled = file.Server.MCP
	next.Maintenance = file.Server.Maintenance
	next.Announcement = file.Server.Announcement
	next.MetricsEnabled = file.Metrics.Enabled

	next.SessionTTL = seconds( file.Auth.SessionTTLSeconds )
	next.SessionMaxAge = seconds( file.Auth.SessionMaxAgeSeconds )
	next.LoginTokenTTL = seconds( file.Auth.LoginTokenTTLSeconds )
	next.APIKeysEnabled = file.Auth.APIKeys
	next.PasswordsEnabled = file.Auth.Passwords
	next.TwoFactorEnabled = file.Auth.TwoFactor
	next.InviteLinksEnabled = file.Auth.InviteLinks
	next.APIKeyTTL = seconds( file.Auth.APIKeyTTLSeconds )

	next.Logs.RetentionDays = file.Logs.RetentionDays
	next.Logs.MaxTotalBytes = int64( file.Logs.MaxTotalMB ) * 1024 * 1024
	next.Logs.MaxFileBytes = int64( file.Logs.MaxFileMB ) * 1024 * 1024
	next.Logs.CompressAfterDays = file.Logs.CompressAfterDays
	next.Logs.StaticAssets = file.Logs.StaticAssets
	next.Logs.UIClicks = file.Logs.UIClicks
	next.Logs.Echo = file.Logs.Echo

	next.Push.Subject = PushSubject( &effective , next.URL )
	next.Push.InboxKeep = time.Duration( file.Push.InboxDays ) * 24 * time.Hour
	next.Webhooks.Enabled = file.Webhooks.Enabled
	next.Webhooks.Timeout = seconds( file.Webhooks.TimeoutSeconds )
	next.Webhooks.AllowPrivateTargets = file.Webhooks.AllowPrivateTargets
	next.Files.Enabled = file.Files.Enabled
	next.Files.MaxFileBytes = int64( file.Files.MaxFileBytes )
	next.Files.QuotaBytesPerUser = int64( file.Files.QuotaBytesPerUser )
	next.Files.AbandonedAfter = time.Duration( file.Files.AbandonedUploadHours ) * time.Hour
	next.Backups.Enabled = file.Backups.Enabled
	next.Backups.Interval = time.Duration( file.Backups.IntervalHours ) * time.Hour
	next.Backups.Keep = file.Backups.Keep
	return
}

// apply is Apply with the lock held. persist, when given, writes the file;
// if it fails nothing is swapped.
func ( holder *Holder ) apply( raw []byte , persist func() error ) ( result ApplyResult , err error ) {
	file , err := Parse( raw , holder.path )
	if err != nil { return }
	if legacy := file.Server.SecretKey; legacy != "" && legacy != holder.boot.SecretKey {
		err = &ValidationError{ Problems: []string{ "server.secret_key does not belong in config.yaml any more -- the key is in secret.key" } }
		return
	}
	if persist != nil {
		if err = persist(); err != nil { return }
	}
	next := liveConfig( holder.boot , holder.bootFile , file )
	result.Changes = Diff( holder.file , file )
	for _ , change := range result.Changes {
		switch change.Mode {
		case ModeLive:
			result.Live = append( result.Live , change.Key )
		case ModeScripts:
			result.Scripts = append( result.Scripts , change.Key )
		default:
			result.Restart = append( result.Restart , change.Key )
		}
	}
	result.Version = Version( raw )
	holder.file = file
	holder.lastErr = nil
	holder.errHash = ""
	old := holder.current.Swap( next )
	for _ , subscriber := range holder.subscribers {
		subscriber( old , next )
	}
	return
}

// Save applies changes from the Settings screen: checks them, rewrites only
// those values in config.yaml, validates the whole result, writes it, and
// applies it. version is the Version the client loaded; if config.yaml is
// not that file any more the save is refused with a ConflictError, so a hand
// edit made meanwhile is never silently overwritten.
func ( holder *Holder ) Save( version string , changes map[string]any ) ( result ApplyResult , err error ) {
	holder.mu.Lock()
	defer holder.mu.Unlock()

	if holder.stale {
		err = ErrStale
		return
	}
	raw , err := os.ReadFile( holder.path )
	if err != nil { return }
	if current := Version( raw ); current != version {
		err = &ConflictError{ Version: current }
		return
	}
	if holder.writable() == false {
		err = ErrReadOnly
		return
	}
	edited , unchanged , err := EditChanges( raw , changes , holder.path , true )
	if err != nil { return }
	result , err = holder.apply( edited , func() error {
		return writeConfigFile( holder.path , edited , holder.inPlace , holder.backupPath )
	} )
	if err != nil { return }
	result.Unchanged = unchanged
	// The watcher will see this write; it is not news.
	holder.seenHash = result.Version
	holder.pending = ""
	if info , stat_err := os.Stat( holder.path ); stat_err == nil {
		holder.stat = statOf( info )
	}
	return
}

// EditChanges is the part of Save that turns submitted changes into a new
// config.yaml, without writing it. `config set` uses it too.
//
// Each value is checked against the schema, written in place by EditYAML,
// and then the whole result is parsed back as a check on the editor itself:
// every changed key must read back as exactly what was asked, and every
// other key as exactly what it was. Anything else is a bug in the editor,
// and nothing is written.
func EditChanges( raw []byte , changes map[string]any , label string , from_server bool ) ( edited []byte , unchanged []string , err error ) {
	before , err := decodeOverDefaults( raw , label )
	if err != nil { return }
	before_values := Flatten( before )

	sections , err := Schema()
	if err != nil { return }
	wanted := map[string]any{}
	var edits []Edit
	for path := range changes {
		if _ , found := schemaByPath[ path ]; found == false {
			err = &UnknownSettingError{ Key: path }
			return
		}
	}
	// Schema order, so keys added to a section land in a sensible order.
	for _ , section := range sections {
		for _ , key := range section.Keys {
			value , submitted := changes[ key.Path ]
			if submitted == false { continue }
			if from_server && Locked( key ) {
				err = fmt.Errorf( "%s: %w" , key.Path , ErrLocked )
				return
			}
			typed , coerce_err := Coerce( key , value )
			if coerce_err != nil {
				err = &ValidationError{ Problems: []string{ coerce_err.Error() } }
				return
			}
			if reflect.DeepEqual( typed , before_values[ key.Path ] ) {
				unchanged = append( unchanged , key.Path )
				continue
			}
			wanted[ key.Path ] = typed
			edits = append( edits , Edit{ Path: key.Path , Value: typed } )
		}
	}
	if len( edits ) == 0 {
		edited = raw
		return
	}
	edited , err = EditYAML( raw , edits , nil , schemaComments )
	if err != nil { return }

	after , err := Parse( edited , label )
	if err != nil { return }
	for path , value := range Flatten( after ) {
		expected , changed := wanted[ path ]
		if changed == false {
			expected = before_values[ path ]
		}
		if reflect.DeepEqual( value , expected ) == false {
			err = fmt.Errorf( "internal error: editing config.yaml would have changed %s from %v to %v -- nothing was written" , path , expected , value )
			return
		}
	}
	return
}

// Locked is true for a key that cannot be changed from inside the container:
// docker.* and build.* (a compromised container must not be able to choose
// what docker/run.sh mounts and chowns on the host next time), and the keys
// the image pins.
func Locked( key KeySchema ) ( locked bool ) {
	if InContainer() == false { return }
	locked = key.Mode == ModeScripts || pinnedKey( key.Path )
	return
}

func pinnedKey( path string ) ( result bool ) {
	result = ( path == "server.host" && pinned.Host != "" ) || ( path == "server.app_dir" && pinned.AppDir != "" )
	return
}

// Poll checks config.yaml for a change made outside Save and applies it. A
// change is applied once two polls in a row have seen the same content, so an
// editor caught half way through writing the file is never applied.
func ( holder *Holder ) Poll() {
	holder.mu.Lock()
	defer holder.mu.Unlock()
	if holder.path == "" { return }

	info , err := os.Stat( holder.path )
	if err != nil {
		holder.fail( "file" , "" , fmt.Sprintf( "cannot read %s: %v -- still running on the last good version" , holder.path , err ) )
		return
	}
	stat := statOf( info )
	if stat.links == 0 && holder.stale == false {
		holder.stale = true
		holder.report( "warn" , "config.yaml was replaced on the host; restart the container to pick it up" , map[string]any{ "file": holder.path } )
	}
	if stat == holder.stat { return }

	raw , err := os.ReadFile( holder.path )
	if err != nil { return }
	hash := Version( raw )
	if hash == holder.seenHash {
		holder.stat = stat
		holder.pending = ""
		return
	}
	if hash != holder.pending {
		holder.pending = hash
		return
	}
	holder.stat = stat
	holder.seenHash = hash
	holder.pending = ""

	result , err := holder.apply( raw , nil )
	if err != nil {
		holder.fail( "file" , hash , fmt.Sprintf( "%s is invalid; still running on the last good version: %v" , holder.path , err ) )
		return
	}
	if len( result.Changes ) == 0 { return }
	holder.report( "info" , "config.yaml reloaded: " + describe( result ) , map[string]any{
		"origin":  "file",
		"changes": result.Changes,
		"applied": result.Live,
		"restart": result.Restart,
		"scripts": result.Scripts,
	} )
}

// describe is a reload in one line: "live server.rate_limit_max; on restart
// server.port".
func describe( result ApplyResult ) ( text string ) {
	var parts []string
	for _ , group := range []struct{ label string ; keys []string }{
		{ "live" , result.Live } , { "on restart" , result.Restart } , { "for the scripts" , result.Scripts } ,
	} {
		if len( group.keys ) > 0 {
			parts = append( parts , group.label + " " + strings.Join( group.keys , ", " ) )
		}
	}
	text = strings.Join( parts , "; " )
	return
}

// fail records an error, reporting it once per distinct file content.
func ( holder *Holder ) fail( origin string , hash string , message string ) {
	repeat := holder.lastErr != nil && holder.lastErr.Message == message && holder.errHash == hash
	holder.lastErr = &LoadError{ Message: message , At: time.Now().UTC() , Origin: origin }
	holder.errHash = hash
	if repeat == false {
		holder.report( "warn" , message , map[string]any{ "file": holder.path , "origin": origin } )
	}
}

func ( holder *Holder ) report( level string , message string , detail map[string]any ) {
	if holder.Report != nil {
		holder.Report( level , message , detail )
	}
}

// Watch polls every interval until stop is closed.
func ( holder *Holder ) Watch( interval time.Duration ) ( stop chan struct{} ) {
	stop = make( chan struct{} )
	go func() {
		ticker := time.NewTicker( interval )
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				holder.Poll()
			}
		}
	}()
	return
}

// writable reports whether Save could write config.yaml: the file itself
// when it is rewritten in place, otherwise the folder the replacement is
// created in. Probing writes nothing.
func ( holder *Holder ) writable() ( result bool ) {
	if holder.inPlace {
		handle , err := os.OpenFile( holder.path , os.O_WRONLY , 0 )
		if err != nil { return }
		handle.Close()
		result = true
		return
	}
	probe , err := os.CreateTemp( filepath.Dir( holder.path ) , ".config.yaml.*.tmp" )
	if err != nil { return }
	probe.Close()
	os.Remove( probe.Name() )
	result = true
	return
}

// ---------------------------------------------------------------------------
// what the Settings screen shows
// ---------------------------------------------------------------------------

// KeyState is one setting as the Settings screen shows it.
type KeyState struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Value   any    `json:"value"`
	Default any    `json:"default"`
	InFile  bool   `json:"in_file"`
	Help    string `json:"help"`
	Apply   string `json:"apply"`
	// PendingRestart: config.yaml's value differs from the one the server
	// started with, which Running holds.
	PendingRestart bool `json:"pending_restart"`
	Running        any  `json:"running"`
	// Locked: not editable here (see Locked).
	Locked bool `json:"locked"`
}

type SectionState struct {
	Name string     `json:"name"`
	Help string     `json:"help"`
	Keys []KeyState `json:"keys"`
}

// Snapshot is the whole Settings screen. It never includes the secret key:
// it is built from the schema, which does not have it.
type Snapshot struct {
	File        string         `json:"file"`
	SecretFile  string         `json:"secret_file"`
	Version     string         `json:"version"`
	Writable    bool           `json:"writable"`
	Stale       bool           `json:"stale"`
	InContainer bool           `json:"in_container"`
	Error       *LoadError     `json:"error"`
	Sections    []SectionState `json:"sections"`
}

// Snapshot reads config.yaml as it is on disk. When that does not validate,
// the values shown are the last good ones and Error says why.
func ( holder *Holder ) Snapshot() ( snapshot Snapshot , err error ) {
	holder.mu.Lock()
	defer holder.mu.Unlock()

	sections , err := Schema()
	if err != nil { return }
	raw , read_err := os.ReadFile( holder.path )
	shown := holder.file
	if read_err == nil {
		if parsed , parse_err := Parse( raw , holder.path ); parse_err == nil {
			shown = parsed
		} else if holder.lastErr == nil || holder.errHash != Version( raw ) {
			holder.lastErr = &LoadError{ Message: parse_err.Error() , At: time.Now().UTC() , Origin: "file" }
			holder.errHash = Version( raw )
		}
	}
	values := Flatten( shown )
	running := Flatten( holder.bootFile )
	present := KeysInFile( raw )

	snapshot = Snapshot{
		File:        holder.path,
		SecretFile:  SecretPathFor( holder.path ),
		Version:     Version( raw ),
		Writable:    holder.stale == false && holder.writable(),
		Stale:       holder.stale,
		InContainer: InContainer(),
		Error:       holder.lastErr,
	}
	for _ , section := range sections {
		state := SectionState{ Name: section.Name , Help: section.Help }
		for _ , key := range section.Keys {
			pending := key.Mode == ModeRestart && pinnedKey( key.Path ) == false &&
				reflect.DeepEqual( values[ key.Path ] , running[ key.Path ] ) == false
			state.Keys = append( state.Keys , KeyState{
				Key:            key.Path,
				Name:           key.Name,
				Type:           key.Type,
				Value:          values[ key.Path ],
				Default:        key.Default,
				InFile:         present[ key.Path ],
				Help:           key.Help,
				Apply:          key.Mode,
				PendingRestart: pending,
				Running:        running[ key.Path ],
				Locked:         Locked( key ),
			} )
		}
		snapshot.Sections = append( snapshot.Sections , state )
	}
	return
}

// ---------------------------------------------------------------------------
// writing config.yaml
// ---------------------------------------------------------------------------

// writeConfigFile replaces config.yaml's content.
//
// Normally that is a new file renamed over the old one: a crash leaves one
// version or the other, never half of each. The container cannot do that.
// Its config.yaml is a single file bind-mounted from the host, and renaming
// over a mount point fails (EBUSY); its folder is root's and read-only
// anyway. So there it is rewritten in place -- after the old version is
// copied to backup_path in the app directory, which is writable -- and
// written from the start before the tail is cut, so the file is never empty.
func writeConfigFile( path string , content []byte , in_place bool , backup_path string ) ( err error ) {
	info , err := os.Stat( path )
	if err != nil { return }

	if in_place {
		if backup_path != "" {
			previous , read_err := os.ReadFile( path )
			if read_err != nil {
				err = read_err
				return
			}
			if err = writeAtomic( backup_path , previous , 0o600 ); err != nil {
				err = fmt.Errorf( "could not keep a backup of config.yaml at %s: %w" , backup_path , err )
				return
			}
		}
		handle , open_err := os.OpenFile( path , os.O_WRONLY , 0 )
		if open_err != nil {
			err = open_err
			return
		}
		_ , err = handle.WriteAt( content , 0 )
		if err == nil {
			err = handle.Truncate( int64( len( content ) ) )
		}
		if err == nil {
			err = handle.Sync()
		}
		if close_err := handle.Close(); err == nil {
			err = close_err
		}
		if err != nil && backup_path != "" {
			err = fmt.Errorf( "%w (the previous config.yaml is at %s)" , err , backup_path )
		}
		return
	}

	err = writeAtomic( path , content , info.Mode().Perm() )
	if err == nil {
		// Keep the group docker/run.sh gave it, so the container can still
		// read and write it. Best effort: only the owner or root can.
		keepGroup( path , info )
	}
	return
}

// writeAtomic writes path through a temporary file in the same folder.
func writeAtomic( path string , content []byte , mode os.FileMode ) ( err error ) {
	dir := filepath.Dir( path )
	temp , err := os.CreateTemp( dir , "." + filepath.Base( path ) + ".*.tmp" )
	if err != nil { return }
	temp_name := temp.Name()
	defer func() {
		if err != nil {
			os.Remove( temp_name )
		}
	}()
	if err = temp.Chmod( mode ); err != nil {
		temp.Close()
		return
	}
	if _ , err = temp.Write( content ); err != nil {
		temp.Close()
		return
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return
	}
	if err = temp.Close(); err != nil { return }
	if err = os.Rename( temp_name , path ); err != nil { return }
	syncDir( dir )
	return
}

func statOf( info os.FileInfo ) ( stat fileStat ) {
	stat = fileStat{ modified: info.ModTime() , size: info.Size() , links: 1 }
	if links , ok := linkCount( info ); ok {
		stat.links = links
	}
	return
}
