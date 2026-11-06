// Package config is the single source of truth for everything this app can be
// told to do differently: the server, the Docker container, and the portable
// build. All of it lives in one config.yaml.
//
// Nothing reads environment variables. A setting that could come from the
// environment, a file, or a default has to be hunted for in three places;
// one that can only come from config.yaml is answered by reading one file.
// The shell scripts follow the same rule -- they ask this package for their
// values (`config shell`, see command.go) rather than parsing YAML themselves,
// so there is exactly one parser and one set of validation rules.
//
// Defaults are not written in Go. They live in config/defaults.yaml, which
// main.go embeds and hands over (UseEmbedded), documents every key, and is
// what `config init` writes out. A
// config.yaml is decoded on top of it, strictly: an unknown key is an error,
// because a typo that is silently ignored is a setting that silently is not
// applied.
//
// The secret key is not in config.yaml. It is in secret.key beside it (see
// secret.go), which is what lets config.yaml be edited while the server runs
// -- from the owner's Settings screen or by hand -- without either path ever
// touching the key. live.go holds the running configuration and applies those
// edits; yamledit.go rewrites single values in place so the file's comments
// survive; schema.go reads which keys can change live from the tags in
// defaults.yaml.
package config

import (
	bytes "bytes"
	errors "errors"
	fmt "fmt"
	io "io"
	net "net"
	url "net/url"
	os "os"
	filepath "path/filepath"
	regexp "regexp"
	runtime "runtime"
	strings "strings"
	time "time"

	yaml "gopkg.in/yaml.v3"
)

// AppSlug names the application on disk. It is what turns into
// ~/.config/<slug>/, so it is deliberately the lowercase, filesystem-safe
// form of the project name rather than the display name. It is a constant
// rather than a setting because it is how config.yaml itself is found.
const AppSlug = "ipb"

// Filenames this app uses. Everything it persists lives under the app
// directory -- see DefaultAppDir for why.
const (
	// ConfigDirName is the folder of a source checkout that holds
	// config.yaml, config.example.yaml, language.yaml and the defaults.
	ConfigDirName     = "config"
	ConfigFileName    = "config.yaml"
	DatabaseFileName  = "app.db"
	ControlSocketName = "control.sock"
	StorageDirName    = "storage"
	// FilesDirName is inside storage, so backups carry finished files.
	FilesDirName      = "files"
	// UploadsDirName is beside storage, not in it: a half-sent file is not
	// worth a backup, and is still changing while one runs.
	UploadsDirName    = "uploads"
	LogsDirName       = "logs"
	BackupsDirName    = "backups"
	LanguageFileName  = "language.yaml"

	// SecretFileName sits beside config.yaml. See SecretPathFor.
	SecretFileName = "secret.key"

	// BackupFileName is the previous config.yaml, kept in the app directory
	// whenever the container rewrites its mounted copy in place. See
	// writeConfigFile.
	BackupFileName = "config.yaml.bak"
)

// defaultsYAML and exampleHeader are config/defaults.yaml and
// config/example_header.yaml. go:embed cannot reach outside this package's
// directory, so main.go embeds them and passes them in before anything runs.
// exampleHeader is what turns defaults.yaml into config.example.yaml: a note
// on how to copy it into place. See ExampleFileContent.
var (
	defaultsYAML  []byte
	exampleHeader []byte
)

// UseEmbedded registers the embedded defaults. main.go calls it from init().
func UseEmbedded( defaults []byte , header []byte ) {
	defaultsYAML = defaults
	exampleHeader = header
}

// ExampleFileName is the committed copy of the defaults that a fresh clone
// copies to config.yaml. It is not read by anything.
const ExampleFileName = "config.example.yaml"

// ---------------------------------------------------------------------------
// config.yaml, section by section
// ---------------------------------------------------------------------------

// File mirrors config.yaml. Every section is decoded strictly, including the
// docker and build sections the server itself never reads: validating them
// here is what lets docker/run.sh and scripts/build.sh fail on a typo before they
// start anything.
type File struct {
	App    AppSection    `yaml:"app"`
	Server ServerSection `yaml:"server"`
	Auth   AuthSection   `yaml:"auth"`
	Logs   LogsSection   `yaml:"logs"`
	Backups BackupsSection `yaml:"backups"`
	Metrics MetricsSection `yaml:"metrics"`
	Webhooks WebhooksSection `yaml:"webhooks"`
	Push     PushSection     `yaml:"push"`
	Files    FilesSection    `yaml:"files"`
	Docker DockerSection `yaml:"docker"`
	Build  BuildSection  `yaml:"build"`
}

type AppSection struct {
	Name string `yaml:"name"`
}

type ServerSection struct {
	Host                   string `yaml:"host"`
	Port                   int    `yaml:"port"`
	PublicURL              string `yaml:"public_url"`
	AppDir                 string `yaml:"app_dir"`
	StaticDir              string `yaml:"static_dir"`
	LanguageFile           string `yaml:"language_file"`
	// Deprecated: the key lives in secret.key. This is read only so that a
	// config.yaml from before the move can be migrated (MigrateLegacySecret);
	// defaults.yaml has no such key, so nothing else ever sees it.
	SecretKey              string `yaml:"secret_key"`
	EncryptAtRest          bool   `yaml:"encrypt_at_rest"`
	SecureCookies          bool   `yaml:"secure_cookies"`
	CookieName             string `yaml:"cookie_name"`
	TrustProxy             bool     `yaml:"trust_proxy"`
	TrustedProxies         []string `yaml:"trusted_proxies"`
	ProxyHeader            string   `yaml:"proxy_header"`
	BodyLimitBytes         int    `yaml:"body_limit_bytes"`
	RateLimitMax           int    `yaml:"rate_limit_max"`
	RateLimitWindowSeconds int    `yaml:"rate_limit_window_seconds"`
	RateLimitSignInMax     int    `yaml:"rate_limit_signin_max"`
	RateLimitUploadMax     int    `yaml:"rate_limit_upload_max"`
	RateLimitSendMax       int    `yaml:"rate_limit_send_max"`
	ControlSocket          bool   `yaml:"control_socket"`
	MCP                    bool   `yaml:"mcp"`
	Maintenance            string `yaml:"maintenance"`
	Announcement           string `yaml:"announcement"`
}

type AuthSection struct {
	SessionTTLSeconds    int  `yaml:"session_ttl_seconds"`
	SessionMaxAgeSeconds int  `yaml:"session_max_age_seconds"`
	LoginTokenTTLSeconds int  `yaml:"login_token_ttl_seconds"`
	APIKeys              bool `yaml:"api_keys"`
	APIKeyTTLSeconds     int  `yaml:"api_key_ttl_seconds"`
	Passwords            bool `yaml:"passwords"`
	TwoFactor            bool `yaml:"two_factor"`
	InviteLinks          bool `yaml:"invite_links"`
}

type LogsSection struct {
	Enabled           bool `yaml:"enabled"`
	RetentionDays     int  `yaml:"retention_days"`
	MaxTotalMB        int  `yaml:"max_total_mb"`
	MaxFileMB         int  `yaml:"max_file_mb"`
	CompressAfterDays int  `yaml:"compress_after_days"`
	StaticAssets      bool `yaml:"static_assets"`
	UIClicks          bool `yaml:"ui_clicks"`
	Echo              bool `yaml:"echo"`
}

type BackupsSection struct {
	Enabled       bool `yaml:"enabled"`
	IntervalHours int  `yaml:"interval_hours"`
	Keep          int  `yaml:"keep"`
}

type MetricsSection struct {
	Enabled bool `yaml:"enabled"`
}

type WebhooksSection struct {
	Enabled             bool `yaml:"enabled"`
	TimeoutSeconds      int  `yaml:"timeout_seconds"`
	AllowPrivateTargets bool `yaml:"allow_private_targets"`
}

type PushSection struct {
	VapidSubject string `yaml:"vapid_subject"`
	InboxDays    int    `yaml:"inbox_days"`
}

type FilesSection struct {
	Enabled              bool `yaml:"enabled"`
	MaxFileBytes         int  `yaml:"max_file_bytes"`
	QuotaBytesPerUser    int  `yaml:"quota_bytes_per_user"`
	AbandonedUploadHours int  `yaml:"abandoned_upload_hours"`
}

type DockerSection struct {
	Image       string `yaml:"image"`
	Container   string `yaml:"container"`
	BindAddress string `yaml:"bind_address"`
	HostPort    int    `yaml:"host_port"`
	DataDir     string `yaml:"data_dir"`
	Restart     string `yaml:"restart"`
	Memory      string `yaml:"memory"`
	CPUs        string `yaml:"cpus"`
	PidsLimit   int    `yaml:"pids_limit"`
	TmpfsSize   string `yaml:"tmpfs_size"`
}

type BuildSection struct {
	BinaryName string   `yaml:"binary_name"`
	OutputDir  string   `yaml:"output_dir"`
	Targets    []string `yaml:"targets"`
}

// ---------------------------------------------------------------------------
// the resolved configuration the server runs on
// ---------------------------------------------------------------------------

// Config is config.yaml after resolution: paths made absolute, seconds turned
// into durations, container overrides applied. The rest of the server reads
// this, never File, so a change to the file's shape stays inside this package.
type Config struct {
	ProjectName string

	// ProjectDir is what relative paths in config.yaml are resolved against.
	// See ProjectDirFor.
	ProjectDir string

	// URL is where a browser reaches this server, for the links it prints:
	// server.public_url when set, otherwise one worked out from the listen
	// address (see ServerURL). URLSource names which, so a printed link can
	// say how much to trust it.
	URL       string
	URLSource string

	// ConfigFile is the config.yaml this was loaded from.
	ConfigFile string

	// ConfigCreated is true when this run wrote ConfigFile because none
	// existed.
	ConfigCreated bool

	// SecretFile is secret.key, beside ConfigFile: the one file besides the
	// app directory that a backup must include.
	SecretFile string

	// SecretCreated is true when this run generated the key, SecretMigrated
	// when it moved server.secret_key out of config.yaml into SecretFile.
	// The startup log says so either way.
	SecretCreated  bool
	SecretMigrated bool

	// RotationFinished is true when this load completed a key rotation that
	// had been cut short. RotationPending is the same discovery inside the
	// container, which cannot complete one: docker/rotate-key.sh does, on the
	// host. See secret.go.
	RotationFinished bool
	RotationPending  bool

	// ConfigWarning is non-empty when secret.key is readable by other users,
	// or config.yaml writable by them. It is a warning rather than an error
	// so a misconfigured mode never stops a server that was working, but it
	// does get logged on every start.
	ConfigWarning string

	// AppDir is the one directory this application owns: the database, the
	// control socket (except in the container, see layout_container.go), and
	// any uploaded or generated files.
	//
	// Defaulting to ~/.config/<slug> rather than ./data matters for the
	// single-file build: a binary run from a Downloads folder, a USB stick,
	// or a different working directory each time still finds the same state.
	AppDir       string
	DatabasePath string

	// ControlSocketPath is the unix socket the running server listens on so
	// that other processes can act on the database without opening it.
	//
	// bolt allows exactly one process to hold the database file, so a second
	// process cannot simply open it while the server is up. Rather than
	// fighting that, the server owns the database and everything else --
	// the manage CLI, a cron job, a sidecar -- asks the server over this
	// socket. One process holds the secret key, and there is no second copy
	// of the auth checks to keep in step.
	//
	// server.control_socket: false switches it off. Then manage only works
	// while the server is stopped.
	ControlSocketPath    string
	ControlSocketEnabled bool

	// StorageDir is for application files -- exports, generated artifacts.
	// Finished uploads are in storage/files (see Files.Dir); the rest exists
	// so that features added later have an obvious, backed-up place to put files
	// instead of inventing one.
	StorageDir string

	// StaticDir and LanguageFile are checked on disk first; if either is
	// missing, the copy embedded in the binary is used instead (see
	// server/assets). That is what lets one build serve a live directory
	// during development and run as a single self-contained file in
	// production, with no flag to remember.
	StaticDir    string
	LanguageFile string

	Host string
	Port int

	// SecureCookies must stay true anywhere a real browser will talk to this
	// over the internet. It is only false for plain-http://localhost work,
	// because a Secure cookie is silently dropped over http and the login
	// flow would appear to succeed and then do nothing.
	SecureCookies bool
	CookieName    string

	SessionTTL    time.Duration
	SessionMaxAge time.Duration
	LoginTokenTTL time.Duration

	// APIKeysEnabled decides whether the Authorization: Bearer header is
	// believed at all, and whether the endpoints that mint keys exist.
	// Turning it off stops existing keys from authenticating too -- the rows
	// stay, so switching it back on restores them.
	APIKeysEnabled bool
	// PasswordsEnabled decides whether a password is believed at all, and
	// whether an account can set one. Off keeps the hashes, so switching it
	// back on restores them.
	PasswordsEnabled bool
	// TwoFactorEnabled decides whether 2FA is offered and asked for. Off keeps
	// the secrets, the same way.
	TwoFactorEnabled bool
	// InviteLinksEnabled decides whether /join and every invite route answer,
	// and whether a PIN can be set. Off keeps the links and PINs, the same way.
	InviteLinksEnabled bool

	// APIKeyTTL is how long a new key lasts when the request does not say.
	// The default is bounded so that a forgotten key eventually stops being
	// a live credential.
	APIKeyTTL time.Duration

	// MCPEnabled decides whether POST /mcp exists. It answers only API keys,
	// so with APIKeysEnabled off it is not registered either -- nothing could
	// authenticate to it.
	MCPEnabled bool
	// MetricsEnabled decides whether GET /metrics answers. Like /mcp it takes
	// keys only, so it also needs APIKeysEnabled.
	MetricsEnabled bool

	// SecretKey encrypts session cookie payloads and, when EncryptAtRest is
	// on, every value written to bolt. Losing it means losing the database
	// contents.
	SecretKey     string
	EncryptAtRest bool

	RateLimitMax    int
	RateLimitWindow time.Duration
	// Maintenance is server.maintenance: read it through MaintenanceMode.
	Maintenance string
	// Announcement is server.announcement: shown on every signed-in page.
	Announcement string

	// RateLimitSignInMax is the separate budget for signing in and joining.
	RateLimitSignInMax int
	// RateLimitUploadMax is the separate budget for the chunks of an upload.
	RateLimitUploadMax int
	// RateLimitSendMax is the separate budget for the notification API.
	RateLimitSendMax int
	BodyLimit       int

	// TrustProxy tells fiber to believe ProxyHeader -- but only on a
	// connection whose peer address is in TrustedProxies. Fiber with
	// TrustProxy on and no allowlist trusts nobody, so every visitor behind
	// the proxy shares the proxy's one rate-limit budget; with the allowlist
	// and nothing else, any client could still name its own IP. Both halves
	// are required, and Validate refuses one without the other.
	TrustProxy     bool
	TrustedProxies []string
	ProxyHeader    string

	// Logs is the activity log's settings; see server/logs.
	Logs LogsConfig

	// Backups is the scheduled backup's settings; see server/backup.
	Backups BackupsConfig
	// Webhooks is how outbound webhooks are sent; see server/webhooks.
	Webhooks WebhooksConfig
	// Push is how notifications are sent; see server/push.
	Push PushConfig
	// Files is how uploads are limited; see models/file.go.
	Files FilesConfig

	// file and raw are what this was built from, for NewHolder.
	file *File
	raw  []byte
}

// LogsConfig is config.yaml's logs section, resolved: sizes in bytes, and the
// directory the day files go in (<app_dir>/logs, created 0700 by Load).
type LogsConfig struct {
	Enabled           bool
	Dir               string
	RetentionDays     int
	MaxTotalBytes     int64
	MaxFileBytes      int64
	CompressAfterDays int
	StaticAssets      bool
	UIClicks          bool
	Echo              bool
}

// ErrRotationPending is what everything but the rotation itself says when one
// was left half way inside the container.
var ErrRotationPending = errors.New( "a key rotation was cut short -- run docker/rotate-key.sh on the host to finish it" )

// FileChunkBytes is the size of every piece of an upload but the last. It sits
// under server.body_limit_bytes on purpose: a file of any size arrives as
// ordinary small requests, so nothing has to raise a limit that also protects
// the public routes. See models/file.go.
const FileChunkBytes = 768 * 1024

// FilesConfig is config.yaml's files section, resolved.
type FilesConfig struct {
	Enabled           bool
	MaxFileBytes      int64
	QuotaBytesPerUser int64
	AbandonedAfter    time.Duration
	// Dir holds finished files, and UploadsDir the ones still arriving.
	Dir        string
	UploadsDir string
}

// WebhooksConfig is config.yaml's webhooks section, resolved.
type WebhooksConfig struct {
	Enabled             bool
	Timeout             time.Duration
	AllowPrivateTargets bool
}

// PushConfig is config.yaml's push section, resolved. Subject is what push
// services are told to reach the operator at: push.vapid_subject, or the
// server's own address when that is empty.
type PushConfig struct {
	Subject   string
	InboxKeep time.Duration
}

// BackupsConfig is config.yaml's backups section, resolved. Dir is where every
// backup goes unless `manage backup -out` says otherwise (<app_dir>/backups,
// created 0700 the first time something is written there).
type BackupsConfig struct {
	Enabled  bool
	Dir      string
	Interval time.Duration
	Keep     int
}

// layout is what the container image pins, regardless of config.yaml. See
// layout_container.go; outside the image every field is empty and nothing is
// pinned.
type layout struct {
	ConfigFile    string
	AppDir        string
	ControlSocket string
	Host          string
}

// InContainer reports whether this binary was built for the container image.
func InContainer() ( result bool ) {
	result = pinned.ConfigFile != ""
	return
}

// ---------------------------------------------------------------------------
// where things live
// ---------------------------------------------------------------------------

// DefaultAppDir is ~/.config/<slug>. Everything lands in one directory rather
// than being split across XDG's config/data/state roots: this app's state is
// small, and one directory to back up is worth more here than strict
// adherence to a layout designed for larger, more separable applications.
func DefaultAppDir() ( dir string ) {
	if home , err := os.UserHomeDir(); err == nil && home != "" {
		dir = filepath.Join( home , ".config" , AppSlug )
		return
	}
	// No home directory at all (some minimal environments). Fall back to the
	// working directory rather than failing to start.
	dir = filepath.Join( "." , AppSlug + "-data" )
	return
}

// Locate finds the config.yaml in use: the pinned path inside the container
// image, otherwise ./config/config.yaml, otherwise the one in the default app
// directory. When none exists, path is where one would be created.
//
// ./config/config.yaml comes first because that is a source checkout, which
// is also where the scripts read it. A portable binary run from anywhere else
// falls through to ~/.config/<slug>/ and finds the same file every time.
func Locate() ( path string , exists bool ) {
	if pinned.ConfigFile != "" {
		path = pinned.ConfigFile
		exists = isFile( path )
		return
	}
	if local , err := filepath.Abs( filepath.Join( ConfigDirName , ConfigFileName ) ); err == nil && isFile( local ) {
		path , exists = local , true
		return
	}
	path = filepath.Join( DefaultAppDir() , ConfigFileName )
	if absolute , err := filepath.Abs( path ); err == nil {
		path = absolute
	}
	exists = isFile( path )
	return
}

func isFile( path string ) ( result bool ) {
	info , err := os.Stat( path )
	result = err == nil && info.Mode().IsRegular()
	return
}

// ProjectDirFor is the directory relative paths in config.yaml resolve
// against. In a checkout (and in the container image, /app) config.yaml sits
// in config/, and paths like ./static and ./data mean the project folder
// around it, so that is the parent. Anywhere else -- ~/.config/<slug>/ for a
// portable binary -- it is the folder holding config.yaml.
func ProjectDirFor( config_path string ) ( dir string ) {
	dir = filepath.Dir( config_path )
	if filepath.Base( dir ) == ConfigDirName {
		dir = filepath.Dir( dir )
	}
	return
}

// resolvePath makes a config path absolute against the project directory
// (ProjectDirFor), so the same file means the same thing whatever directory
// the process was started from.
func resolvePath( base string , value string ) ( result string ) {
	result = value
	if result == "" || filepath.IsAbs( result ) {
		return
	}
	result = filepath.Join( base , result )
	return
}

// ---------------------------------------------------------------------------
// reading and validating
// ---------------------------------------------------------------------------

func decodeStrict( raw []byte , out *File ) ( err error ) {
	decoder := yaml.NewDecoder( bytes.NewReader( raw ) )
	decoder.KnownFields( true )
	err = decoder.Decode( out )
	if errors.Is( err , io.EOF ) {
		// An empty file is a valid file that sets nothing.
		err = nil
	}
	return
}

// Defaults is defaults.yaml on its own: the configuration a missing key falls
// back to.
func Defaults() ( file *File , err error ) {
	if len( defaultsYAML ) == 0 {
		err = errors.New( "no defaults registered -- main.go must call config.UseEmbedded before reading config" )
		return
	}
	file = &File{}
	if err = decodeStrict( defaultsYAML , file ); err != nil {
		err = fmt.Errorf( "embedded defaults.yaml is invalid: %w" , err )
	}
	return
}

// Parse decodes a config.yaml over the defaults and validates the result.
// It does not require a secret key -- build.sh reads the build section of a
// checkout that may not have one yet. Load and `config check` do.
func Parse( raw []byte , label string ) ( file *File , err error ) {
	file , err = Defaults()
	if err != nil { return }
	if err = decodeStrict( raw , file ); err != nil {
		err = fmt.Errorf( "%s: %w" , label , err )
		return
	}
	if err = file.Validate(); err != nil {
		err = fmt.Errorf( "%s: %w" , label , err )
	}
	return
}

// ReadFile reads and validates one config.yaml without touching anything else
// on disk.
func ReadFile( path string ) ( file *File , err error ) {
	raw , err := os.ReadFile( path )
	if err != nil { return }
	file , err = Parse( raw , path )
	return
}

// Current is the file the server would use, or the defaults when there is no
// file yet. It never writes anything, which is what the shell-facing commands
// and the healthcheck need.
func Current() ( file *File , path string , exists bool , err error ) {
	path , exists = Locate()
	if exists {
		file , err = ReadFile( path )
		return
	}
	file , err = Defaults()
	return
}

var (
	imagePattern     = regexp.MustCompile( `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(:[0-9]+)?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)*$` )
	containerPattern = regexp.MustCompile( `^[a-zA-Z0-9][a-zA-Z0-9_.-]*$` )
	restartPattern   = regexp.MustCompile( `^(no|always|unless-stopped|on-failure(:[0-9]+)?)$` )
	sizePattern      = regexp.MustCompile( `^[0-9]+[bkmgBKMG]?$` )
	cpusPattern      = regexp.MustCompile( `^[0-9]+(\.[0-9]+)?$` )
	targetPattern    = regexp.MustCompile( `^[a-z0-9]+/[a-z0-9]+$` )
	binaryPattern    = regexp.MustCompile( `^[A-Za-z0-9][A-Za-z0-9._-]*$` )
	secretPattern    = regexp.MustCompile( `^[0-9a-fA-F]{64}$` )
)

// Validate rejects values that would fail later in a confusing way -- a port
// out of range, a Docker size the daemon would refuse, a build target go
// cannot parse. The docker and build values also end up in shell commands,
// so they are held to strict patterns rather than trusted.
// The values of server.maintenance. "none" rather than "off": YAML 1.1 readers
// take a bare off as false, and the Python template's reader is one of those.
const (
	MaintenanceNone     = "none"
	MaintenanceReadOnly = "read_only"
	MaintenanceFull     = "full"
)

// MaintenanceMode is server.maintenance, with a Config built by hand reading
// as normal running.
func ( cfg *Config ) MaintenanceMode() ( mode string ) {
	mode = cfg.Maintenance
	if mode == "" {
		mode = MaintenanceNone
	}
	return
}

func ( file *File ) Validate() ( err error ) {
	var problems []string
	check := func( ok bool , format string , values ...any ) {
		if ok == false {
			problems = append( problems , fmt.Sprintf( format , values... ) )
		}
	}
	path_ok := func( value string ) ( result bool ) {
		result = strings.TrimSpace( value ) != "" && strings.ContainsAny( value , ":\n\r" ) == false
		return
	}

	check( strings.TrimSpace( file.App.Name ) != "" , "app.name must not be empty" )

	server := file.Server
	check( strings.TrimSpace( server.Host ) != "" , "server.host must not be empty" )
	check( server.Port >= 1 && server.Port <= 65535 , "server.port must be 1-65535, got %d" , server.Port )
	check( validPublicURL( server.PublicURL ) ,
		"server.public_url %q must be empty or a bare origin like https://app.example.com (http or https, no path)" , server.PublicURL )
	check( strings.TrimSpace( server.CookieName ) != "" , "server.cookie_name must not be empty" )
	check( strings.TrimSpace( server.ProxyHeader ) != "" , "server.proxy_header must not be empty" )
	check( server.TrustProxy == false || len( server.TrustedProxies ) > 0 ,
		"server.trust_proxy is true but server.trusted_proxies is empty -- list the address or CIDR range your reverse proxy connects from" )
	for _ , entry := range server.TrustedProxies {
		check( validProxyEntry( entry ) , "server.trusted_proxies entry %q must be an IP address or a CIDR range like 10.0.0.0/8" , entry )
		check( entry != "0.0.0.0/0" && entry != "::/0" , "server.trusted_proxies entry %q trusts every address, which lets any client forge its own IP" , entry )
	}
	check( server.BodyLimitBytes > 0 , "server.body_limit_bytes must be positive" )
	check( server.RateLimitMax > 0 , "server.rate_limit_max must be positive" )
	check( server.RateLimitWindowSeconds > 0 , "server.rate_limit_window_seconds must be positive" )
	check( server.RateLimitSignInMax > 0 , "server.rate_limit_signin_max must be positive" )
	check( server.RateLimitUploadMax > 0 , "server.rate_limit_upload_max must be positive" )
	check( server.RateLimitSendMax > 0 , "server.rate_limit_send_max must be positive" )
	check( server.Maintenance == MaintenanceNone || server.Maintenance == MaintenanceReadOnly || server.Maintenance == MaintenanceFull ,
		"server.maintenance must be none, read_only or full" )
	check( len( server.Announcement ) <= 500 , "server.announcement must be 500 characters or fewer" )

	auth := file.Auth
	check( auth.SessionTTLSeconds > 0 , "auth.session_ttl_seconds must be positive" )
	check( auth.SessionMaxAgeSeconds >= auth.SessionTTLSeconds , "auth.session_max_age_seconds must be at least auth.session_ttl_seconds" )
	check( auth.LoginTokenTTLSeconds > 0 , "auth.login_token_ttl_seconds must be positive" )
	check( auth.APIKeyTTLSeconds > 0 , "auth.api_key_ttl_seconds must be positive" )

	logs := file.Logs
	check( logs.RetentionDays >= 1 && logs.RetentionDays <= 3650 , "logs.retention_days must be 1-3650, got %d" , logs.RetentionDays )
	check( logs.MaxTotalMB >= 1 , "logs.max_total_mb must be positive" )
	check( logs.MaxFileMB >= 1 && logs.MaxFileMB <= logs.MaxTotalMB , "logs.max_file_mb must be positive and no more than logs.max_total_mb" )
	check( logs.CompressAfterDays >= 0 , "logs.compress_after_days must be 0 (never) or more" )

	check( file.Push.InboxDays >= 1 , "push.inbox_days must be at least 1, got %d" , file.Push.InboxDays )
	check( validPushSubject( file.Push.VapidSubject ) , "push.vapid_subject %q must be empty, a mailto: address, or an https:// URL" , file.Push.VapidSubject )
	check( file.Webhooks.TimeoutSeconds >= 1 && file.Webhooks.TimeoutSeconds <= 60 , "webhooks.timeout_seconds must be 1-60, got %d" , file.Webhooks.TimeoutSeconds )
	check( file.Files.MaxFileBytes > 0 , "files.max_file_bytes must be positive" )
	check( file.Files.QuotaBytesPerUser > 0 , "files.quota_bytes_per_user must be positive" )
	check( file.Files.AbandonedUploadHours > 0 , "files.abandoned_upload_hours must be positive" )
	check( file.Files.Enabled == false || server.BodyLimitBytes >= FileChunkBytes , "server.body_limit_bytes must be at least %d while files.enabled is on: that is the size of one piece of an upload" , FileChunkBytes )
	backups := file.Backups
	check( backups.IntervalHours >= 1 , "backups.interval_hours must be at least 1, got %d" , backups.IntervalHours )
	check( backups.Keep >= 1 , "backups.keep must be at least 1, got %d" , backups.Keep )

	docker := file.Docker
	check( imagePattern.MatchString( docker.Image ) , "docker.image %q is not a valid lowercase image name" , docker.Image )
	check( containerPattern.MatchString( docker.Container ) , "docker.container %q is not a valid container name" , docker.Container )
	check( validBindAddress( docker.BindAddress ) , "docker.bind_address %q must be an IP address" , docker.BindAddress )
	check( docker.HostPort >= 1 && docker.HostPort <= 65535 , "docker.host_port must be 1-65535, got %d" , docker.HostPort )
	check( path_ok( docker.DataDir ) , "docker.data_dir must be a path with no ':' in it" )
	check( restartPattern.MatchString( docker.Restart ) , "docker.restart must be no, always, unless-stopped or on-failure[:N], got %q" , docker.Restart )
	check( sizePattern.MatchString( docker.Memory ) , "docker.memory must look like 256m, got %q" , docker.Memory )
	check( cpusPattern.MatchString( docker.CPUs ) , "docker.cpus must be a number like 1 or 0.5, got %q" , docker.CPUs )
	check( docker.PidsLimit > 0 , "docker.pids_limit must be positive" )
	check( sizePattern.MatchString( docker.TmpfsSize ) , "docker.tmpfs_size must look like 16m, got %q" , docker.TmpfsSize )

	build := file.Build
	check( binaryPattern.MatchString( build.BinaryName ) , "build.binary_name %q must be a plain file name" , build.BinaryName )
	check( path_ok( build.OutputDir ) , "build.output_dir must be a path with no ':' in it" )
	check( len( build.Targets ) > 0 , "build.targets must list at least one os/arch" )
	for _ , target := range build.Targets {
		check( targetPattern.MatchString( target ) , "build.targets entry %q must look like linux/amd64" , target )
	}

	if len( problems ) > 0 {
		err = &ValidationError{ Problems: problems }
	}
	return
}

// ValidationError lists everything wrong with a config.yaml at once. Each
// problem starts with the key it is about ("server.port must be ..."), which
// is how the Settings screen puts it under the right field.
type ValidationError struct {
	Problems []string
}

func ( validation *ValidationError ) Error() ( result string ) {
	result = strings.Join( validation.Problems , "; " )
	return
}

func validProxyEntry( value string ) ( result bool ) {
	if strings.Contains( value , "/" ) {
		_ , _ , err := net.ParseCIDR( value )
		result = err == nil
		return
	}
	result = net.ParseIP( value ) != nil
	return
}

// validPushSubject is what Apple's push service accepts: it refuses anything
// else with BadJwtToken, which says nothing about why.
func validPushSubject( value string ) ( result bool ) {
	result = value == "" || strings.HasPrefix( value , "mailto:" ) || strings.HasPrefix( value , "https://" )
	return
}

// PushSubject resolves push.vapid_subject against the address people use.
func PushSubject( file *File , server_url string ) ( result string ) {
	result = file.Push.VapidSubject
	if result == "" { result = server_url }
	return
}

func validPublicURL( value string ) ( result bool ) {
	if value == "" {
		result = true
		return
	}
	parsed , err := url.Parse( value )
	result = err == nil && ( parsed.Scheme == "http" || parsed.Scheme == "https" ) && parsed.Host != "" &&
		( parsed.Path == "" || parsed.Path == "/" ) && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.User == nil
	return
}

func validBindAddress( value string ) ( result bool ) {
	result = net.ParseIP( value ) != nil
	return
}

// CheckSecretKey is separate from Validate because only a process that will
// actually use the key needs one. label says where the key came from, for
// the message.
//
// An empty key is refused rather than filled in. A secret.key that exists
// was written with a key, so an empty one means it was emptied -- and
// quietly generating a replacement would make every existing record
// permanently unreadable.
func CheckSecretKey( key string , label string ) ( err error ) {
	key = strings.TrimSpace( key )
	if key == "" {
		err = fmt.Errorf(
			"%s is empty\n"+
				"  If this app already has data, put back the key it was written with -- a new key cannot read it.\n"+
				"  For a fresh install, delete the empty file and the server writes a new one." , label )
		return
	}
	if secretPattern.MatchString( key ) == false {
		err = fmt.Errorf( "%s must hold 64 hex characters (32 bytes), got %d characters" , label , len( key ) )
	}
	return
}

// permissionWarning flags a secret.key other users can read or anyone but
// its owner can change, and a config.yaml anyone on the machine can write --
// the server applies an edit to that within seconds. Group read on
// secret.key is allowed: it is how the container's user reads it (see
// docker/run.sh).
func permissionWarning( config_path string , secret_path string ) ( warning string ) {
	if runtime.GOOS == "windows" {
		return
	}
	var problems []string
	if info , err := os.Stat( secret_path ); err == nil && info.Mode().Perm() & 0o027 != 0 {
		problems = append( problems , fmt.Sprintf( "%s is open to other users (mode %04o) and holds the secret key -- chmod 600 it" , secret_path , info.Mode().Perm() ) )
	}
	if info , err := os.Stat( config_path ); err == nil && info.Mode().Perm() & 0o002 != 0 {
		problems = append( problems , fmt.Sprintf( "%s is writable by every user (mode %04o), and the server applies edits to it -- chmod 600 it" , config_path , info.Mode().Perm() ) )
	}
	warning = strings.Join( problems , "; " )
	return
}

// ---------------------------------------------------------------------------
// creating a config.yaml
// ---------------------------------------------------------------------------

// NewFileContent is defaults.yaml as it is -- the whole file, comments
// included, so the result documents itself. It holds no secret: that is
// written to secret.key separately.
func NewFileContent() ( content []byte , err error ) {
	if err = checkNoSecretInDefaults(); err != nil { return }
	content = append( []byte{} , defaultsYAML... )
	return
}

// ExampleFileContent is defaults.yaml with a header explaining how to copy
// it into place. It is generated rather than kept by hand so that it cannot
// drift from the defaults it documents.
func ExampleFileContent() ( content []byte , err error ) {
	if err = checkNoSecretInDefaults(); err != nil { return }
	content = append( append( []byte{} , exampleHeader... ) , defaultsYAML... )
	return
}

// checkNoSecretInDefaults keeps a key from creeping back into defaults.yaml,
// where every config.yaml and the committed example would copy it.
func checkNoSecretInDefaults() ( err error ) {
	defaults , err := Defaults()
	if err != nil { return }
	if defaults.Server.SecretKey != "" || bytes.Contains( defaultsYAML , []byte( "\n  secret_key:" ) ) {
		err = errors.New( "embedded defaults.yaml must not contain server.secret_key -- the key lives in secret.key" )
	}
	return
}

// WriteExample writes config.example.yaml. Unlike WriteNew it overwrites:
// the file holds no secret, and regenerating it is the point.
func WriteExample( path string ) ( err error ) {
	content , err := ExampleFileContent()
	if err != nil { return }
	err = os.WriteFile( path , content , 0o644 )
	return
}

// WriteNew creates path from NewFileContent, refusing to overwrite: an
// existing config.yaml is someone's settings. A secret.key is written beside
// it unless one is already there -- an existing key is what existing data
// depends on, so it is never replaced. secret_created says which.
func WriteNew( path string ) ( secret_created bool , err error ) {
	content , err := NewFileContent()
	if err != nil { return }
	// 0700 because secret.key lives in here too.
	if err = os.MkdirAll( filepath.Dir( path ) , 0o700 ); err != nil {
		err = fmt.Errorf( "could not create %s: %w" , filepath.Dir( path ) , err )
		return
	}
	handle , err := os.OpenFile( path , os.O_WRONLY|os.O_CREATE|os.O_EXCL , 0o600 )
	if err != nil {
		err = fmt.Errorf( "could not create %s: %w" , path , err )
		return
	}
	_ , err = handle.Write( content )
	if close_err := handle.Close(); err == nil {
		err = close_err
	}
	if err != nil { return }
	secret_path := SecretPathFor( path )
	if isFile( secret_path ) {
		return
	}
	if err = WriteSecret( secret_path , GenerateSecret() ); err != nil { return }
	secret_created = true
	return
}

// ---------------------------------------------------------------------------

// Load finds config.yaml (creating it, and secret.key, if there is none),
// moves a secret key out of an older config.yaml (see resolveSecret),
// validates it, and makes sure the app directory exists. The server and the
// manage CLI both start here.
func Load() ( cfg *Config , err error ) {
	path , exists := Locate()
	cfg , err = LoadPath( path , exists )
	return
}

// LoadPath is Load for a config.yaml whose path is already known: the one
// Locate found, or a test's.
func LoadPath( path string , exists bool ) ( cfg *Config , err error ) {
	created := false
	if exists == false {
		if InContainer() {
			err = fmt.Errorf( "no config at %s -- docker/run.sh mounts the project's config/config.yaml there" , path )
			return
		}
		if _ , err = WriteNew( path ); err != nil { return }
		created = true
	}

	file , err := ReadFile( path )
	if err != nil { return }

	paths := ResolvePaths( file , path )

	// A key rotation cut short: the data may already be on the new key, so
	// this has to finish before the key is read. Inside the container
	// secret.key cannot be written, so it is left for docker/rotate-key.sh.
	rotation_pending := false
	rotation_finished := false
	if RotationPending( paths.AppDir ) {
		if InContainer() {
			rotation_pending = true
		} else {
			if err = finishRotation( paths , path ); err != nil {
				err = fmt.Errorf( "could not finish an interrupted key rotation: %w" , err )
				return
			}
			rotation_finished = true
		}
	}

	secret , err := resolveSecret( file , path , paths.DatabasePath )
	if err != nil { return }
	if secret.Rewrote {
		// The migration took the key's line out of config.yaml: build from
		// the file as it now is, which is also what the Holder starts from.
		if file , err = ReadFile( path ); err != nil { return }
	}
	raw , err := os.ReadFile( path )
	if err != nil { return }

	// 0700 because the database lives in here.
	if mkdir_err := os.MkdirAll( paths.AppDir , 0o700 ); mkdir_err != nil {
		err = fmt.Errorf( "could not create app directory %q: %w" , paths.AppDir , mkdir_err )
		return
	}
	storage_dir := filepath.Join( paths.AppDir , StorageDirName )
	if mkdir_err := os.MkdirAll( storage_dir , 0o700 ); mkdir_err != nil {
		err = fmt.Errorf( "could not create storage directory %q: %w" , storage_dir , mkdir_err )
		return
	}

	logs_dir := filepath.Join( paths.AppDir , LogsDirName )
	if mkdir_err := os.MkdirAll( logs_dir , 0o700 ); mkdir_err != nil {
		err = fmt.Errorf( "could not create logs directory %q: %w" , logs_dir , mkdir_err )
		return
	}

	cfg = build( file , path , paths , secret.Key )
	cfg.ConfigCreated = created
	cfg.SecretCreated = secret.Created
	cfg.SecretMigrated = secret.Migrated
	cfg.RotationPending = rotation_pending
	cfg.RotationFinished = rotation_finished
	cfg.ConfigWarning = permissionWarning( path , cfg.SecretFile )
	if secret.Warning != "" {
		cfg.ConfigWarning = strings.TrimPrefix( cfg.ConfigWarning + "; " + secret.Warning , "; " )
	}
	cfg.raw = raw
	return
}

// build is config.yaml resolved into the Config the server runs on. It
// creates nothing, which is what lets the Holder rebuild the live part of it
// on every edit (see liveConfig).
func build( file *File , path string , paths Paths , secret_key string ) ( cfg *Config ) {
	host := file.Server.Host
	if pinned.Host != "" {
		host = pinned.Host
	}
	link_url , link_source := ServerURL( file )

	cfg = &Config{
		ProjectName: file.App.Name,
		ProjectDir:  paths.ProjectDir,
		URL:         link_url,
		URLSource:   link_source,

		ConfigFile: path,
		SecretFile: SecretPathFor( path ),

		AppDir:       paths.AppDir,
		DatabasePath: paths.DatabasePath,

		ControlSocketPath:    paths.ControlSocketPath,
		ControlSocketEnabled: file.Server.ControlSocket,
		StorageDir:           filepath.Join( paths.AppDir , StorageDirName ),

		StaticDir:    paths.StaticDir,
		LanguageFile: paths.LanguageFile,

		Host: host,
		Port: file.Server.Port,

		SecureCookies: file.Server.SecureCookies,
		CookieName:    file.Server.CookieName,

		SessionTTL:    seconds( file.Auth.SessionTTLSeconds ),
		SessionMaxAge: seconds( file.Auth.SessionMaxAgeSeconds ),
		LoginTokenTTL: seconds( file.Auth.LoginTokenTTLSeconds ),

		APIKeysEnabled: file.Auth.APIKeys,
		PasswordsEnabled: file.Auth.Passwords,
		TwoFactorEnabled: file.Auth.TwoFactor,
		InviteLinksEnabled: file.Auth.InviteLinks,
		APIKeyTTL:      seconds( file.Auth.APIKeyTTLSeconds ),
		MCPEnabled:     file.Server.MCP,
		Maintenance:    file.Server.Maintenance,
		Announcement:   file.Server.Announcement,
		MetricsEnabled: file.Metrics.Enabled,

		SecretKey:     secret_key,
		EncryptAtRest: file.Server.EncryptAtRest,

		RateLimitMax:    file.Server.RateLimitMax,
		RateLimitWindow: seconds( file.Server.RateLimitWindowSeconds ),
		RateLimitSignInMax: file.Server.RateLimitSignInMax,
		RateLimitUploadMax: file.Server.RateLimitUploadMax,
		RateLimitSendMax:   file.Server.RateLimitSendMax,
		BodyLimit:       file.Server.BodyLimitBytes,

		TrustProxy:     file.Server.TrustProxy,
		TrustedProxies: file.Server.TrustedProxies,
		ProxyHeader:    file.Server.ProxyHeader,

		Logs: LogsConfig{
			Enabled:           file.Logs.Enabled,
			Dir:               filepath.Join( paths.AppDir , LogsDirName ),
			RetentionDays:     file.Logs.RetentionDays,
			MaxTotalBytes:     int64( file.Logs.MaxTotalMB ) * 1024 * 1024,
			MaxFileBytes:      int64( file.Logs.MaxFileMB ) * 1024 * 1024,
			CompressAfterDays: file.Logs.CompressAfterDays,
			StaticAssets:      file.Logs.StaticAssets,
			UIClicks:          file.Logs.UIClicks,
			Echo:              file.Logs.Echo,
		},

		Webhooks: WebhooksConfig{
			Enabled:             file.Webhooks.Enabled,
			Timeout:             time.Duration( file.Webhooks.TimeoutSeconds ) * time.Second,
			AllowPrivateTargets: file.Webhooks.AllowPrivateTargets,
		},
		Push: PushConfig{
			Subject:   PushSubject( file , link_url ),
			InboxKeep: time.Duration( file.Push.InboxDays ) * 24 * time.Hour,
		},
		Files: FilesConfig{
			Enabled:           file.Files.Enabled,
			MaxFileBytes:      int64( file.Files.MaxFileBytes ),
			QuotaBytesPerUser: int64( file.Files.QuotaBytesPerUser ),
			AbandonedAfter:    time.Duration( file.Files.AbandonedUploadHours ) * time.Hour,
			Dir:               filepath.Join( paths.AppDir , StorageDirName , FilesDirName ),
			UploadsDir:        filepath.Join( paths.AppDir , UploadsDirName ),
		},
		Backups: BackupsConfig{
			Enabled:  file.Backups.Enabled,
			Dir:      filepath.Join( paths.AppDir , BackupsDirName ),
			Interval: time.Duration( file.Backups.IntervalHours ) * time.Hour,
			Keep:     file.Backups.Keep,
		},

		file: file,
	}
	return
}

// Paths is where everything config.yaml names actually is, resolved the one
// way the server resolves it. `config shell server` prints the same values,
// so the scripts never work out a path on their own.
type Paths struct {
	ProjectDir        string
	AppDir            string
	DatabasePath      string
	ControlSocketPath string
	StaticDir         string
	LanguageFile      string
}

// ResolvePaths works the paths out without creating anything.
func ResolvePaths( file *File , config_path string ) ( paths Paths ) {
	base := ProjectDirFor( config_path )
	paths.ProjectDir = base

	paths.AppDir = DefaultAppDir()
	if file.Server.AppDir != "" {
		paths.AppDir = resolvePath( base , file.Server.AppDir )
	}
	if pinned.AppDir != "" {
		paths.AppDir = pinned.AppDir
	}
	if absolute , err := filepath.Abs( paths.AppDir ); err == nil {
		paths.AppDir = absolute
	}
	paths.DatabasePath = filepath.Join( paths.AppDir , DatabaseFileName )
	paths.ControlSocketPath = filepath.Join( paths.AppDir , ControlSocketName )
	if pinned.ControlSocket != "" {
		paths.ControlSocketPath = pinned.ControlSocket
	}
	paths.StaticDir = resolvePath( base , file.Server.StaticDir )

	// An operator can drop a language.yaml into the app directory to reword
	// the UI without rebuilding. Failing that, the one beside config.yaml
	// (config/language.yaml in a checkout) is used, and failing that the
	// embedded copy.
	paths.LanguageFile = resolvePath( base , file.Server.LanguageFile )
	if paths.LanguageFile == "" {
		paths.LanguageFile = filepath.Join( paths.AppDir , LanguageFileName )
		if isFile( paths.LanguageFile ) == false {
			paths.LanguageFile = filepath.Join( filepath.Dir( config_path ) , LanguageFileName )
		}
	}
	return
}

// ServerURL is the address printed links start with, and source says where
// it came from. server.public_url wins: only the operator knows what sits in
// front. Without it, the container's answer is the address Docker publishes
// (docker.bind_address:docker.host_port), and anywhere else it is the listen
// address -- with a wildcard host shown as loopback, since 0.0.0.0 is not
// somewhere a browser can go.
func ServerURL( file *File ) ( result string , source string ) {
	if file.Server.PublicURL != "" {
		result = strings.TrimRight( file.Server.PublicURL , "/" )
		source = "server.public_url"
		return
	}
	if InContainer() {
		result , source = DockerURL( file )
		return
	}
	result = "http://" + hostPort( file.Server.Host , file.Server.Port )
	source = "server.host and server.port; this machine only -- set server.public_url for the address people use"
	return
}

// DockerURL is ServerURL for the container as seen from the host.
func DockerURL( file *File ) ( result string , source string ) {
	if file.Server.PublicURL != "" {
		result = strings.TrimRight( file.Server.PublicURL , "/" )
		source = "server.public_url"
		return
	}
	result = "http://" + hostPort( file.Docker.BindAddress , file.Docker.HostPort )
	source = "docker.bind_address and docker.host_port, the published port -- set server.public_url for the address people use"
	return
}

func hostPort( host string , port int ) ( result string ) {
	switch host {
	case "0.0.0.0" , "":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	result = net.JoinHostPort( host , fmt.Sprint( port ) )
	return
}

func seconds( value int ) ( result time.Duration ) {
	result = time.Duration( value ) * time.Second
	return
}

func ( cfg *Config ) ListenAddress() ( result string ) {
	result = fmt.Sprintf( "%s:%d" , cfg.Host , cfg.Port )
	return
}
