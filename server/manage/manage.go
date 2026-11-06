// Package manage implements the handful of account operations that cannot
// happen through the web UI, because they are needed before anyone can log in
// or at the point when nobody can.
//
// It lives in a package rather than in main.go so the binary's "manage"
// subcommand stays a one-line dispatch and the commands can be tested on
// their own. The container image runs the same binary: docker exec <name>
// /app/server manage ...
//
// # How it reaches the database
//
// bolt hands its file to exactly one process, so this tool cannot simply open
// the database while the server is running. It takes whichever route is
// available, in this order:
//
//	server running   ask it over the control socket (server/control)
//	server stopped   open the database directly
//
// Every command is written once against the backend interface below and works
// either way, so the same `reissue-login` that rescues a locked-out user on a
// live deployment also works on a fresh install with nothing running yet.
package manage

import (
	json "encoding/json"
	errors "errors"
	flag "flag"
	fmt "fmt"
	os "os"
	filepath "path/filepath"
	time "time"

	backup "ipb/server/backup"
	bootstrap "ipb/server/bootstrap"
	config "ipb/server/config"
	control "ipb/server/control"
	db "ipb/server/db"
	logs "ipb/server/logs"
	models "ipb/server/models"
	rotate "ipb/server/rotate"
)

const usage = `manage -- account administration for iPB

Usage:
  bootstrap-admin -name "Ada"        create the first admin + login link
  create-login    -name "Grace" -role user
  reissue-login   -user-id 3         fresh link for an existing user
  list-users                         id, name, role, status
  set-disabled    -user-id 3 -disabled=true
  revoke-access   -user-id 3         end every session, login link and API key
  reset-2fa       -user-id 3         take two-factor sign-in off an account
  delete-user     -user-id 3 -yes    remove the account and everything it held
  transfer-owner  -user-id 3         make another enabled admin the owner
  list-keys       [-user-id 3]       API keys, whose they are, when last used
  create-key      -user-id 3 -name "CI" [-role user] [-days 90]
  revoke-key      -key-id abc123     kill one API key now, keep its record
  delete-key      -key-id abc123     kill one API key now and remove its record
  create-invite   -user-id 1 -label "Book club" [-uses 10] [-days 30]
                                     one link a group can join through
  backup          [-out path] [-include-key]
                                     one file with the database, config.yaml and
                                     storage, safe while the server runs
  restore         -from path -yes [-key-file path]
                                     put a backup back; the server must be stopped
  rotate-key      -yes               move to a new secret key; the server must be
                                     stopped (in Docker: docker/rotate-key.sh)
  paths                              where this app keeps its state
  logs            [-day 2026-11-02] [-q "status:5xx"] [-limit 50]
                                     the activity log: days, or one day's
                                     entries newest first, as JSON lines

The owner is the first admin, and the one account that can delete other
admins from the web UI. Nothing deletes or disables the owner -- move it with
transfer-owner first. delete-user cannot be undone, hence -yes.

An API key carries a role from the same set users do, so an admin-scoped key
can do what an admin can and a user-scoped one cannot. A key never outranks
the account it belongs to. -days 0 means it never expires; omit -days to use
the server's configured default.

A backup leaves secret.key out unless -include-key says otherwise, so keep a
copy of the key apart from your backups. Without it a backup cannot be read.
restore keeps what it replaces beside it, as app.db.before-restore-<time>. A
backup made under an older key needs -key-file, naming that key.

rotate-key re-encrypts the database, two-factor secrets and the activity log,
and everyone has to sign in again. The old key stays as
secret.key.retired-<time>, because every backup made before it still needs it.

Reachable two ways, identical either way:
  ./ipb manage list-users     (the single portable binary)
  ./manage list-users                      (the standalone tool in the image)

These work whether or not the server is running. With the server up the
command is sent to it over the control socket; with the server stopped the database is opened directly.

Every command reads the same config.yaml and secret.key as the server (see
"paths" for which). secret.key in particular must hold the key the data was
written with, or the stored records cannot be decrypted.
`

// Usage prints the command list. Exported so an entry point can show it for
// a bare "manage" with no subcommand.
func Usage() {
	fmt.Print( usage )
}

// backend is the small set of operations the commands need. Having both a
// control-socket implementation and a direct-database one behind one
// interface is what keeps each command written a single time -- the
// alternative is two copies of every command that drift apart.
//
// It speaks in control.UserResponse rather than *models.User because that is
// the shape that survives the socket; the direct implementation converts.
type backend interface {
	ListUsers() ( users []control.UserResponse , err error )
	CreateUser( display_name string , role string ) ( user control.UserResponse , err error )
	ReissueLogin( user_id uint64 ) ( user control.UserResponse , err error )
	SetDisabled( user_id uint64 , disabled bool ) ( user control.UserResponse , err error )
	RevokeAccess( user_id uint64 ) ( revoked models.Revoked , err error )
	ResetTwoFactor( user_id uint64 ) ( err error )
	DeleteUser( user_id uint64 ) ( removed models.Revoked , err error )
	TransferOwner( user_id uint64 ) ( user control.UserResponse , err error )
	ListAPIKeys( user_id uint64 ) ( keys []control.APIKeyResponse , err error )
	CreateAPIKey( user_id uint64 , name string , role string , expires_in_days *int ) ( key control.APIKeyResponse , err error )
	RevokeAPIKey( key_id string ) ( key control.APIKeyResponse , err error )
	DeleteAPIKey( key_id string ) ( key control.APIKeyResponse , err error )
	CreateInviteLink( user_id uint64 , label string , max_uses int , days int ) ( link control.InviteLinkResponse , err error )
	Backup( options backup.Options ) ( result backup.Result , err error )
	AnyAdminExists() ( result bool , err error )
	Close() ( err error )
	Route() ( description string )
}

// Run executes one subcommand. arguments is everything after "manage".
func Run( arguments []string ) ( err error ) {
	if len( arguments ) < 1 {
		Usage()
		err = fmt.Errorf( "no command given" )
		return
	}

	cfg , err := config.Load()
	if err != nil {
		err = fmt.Errorf( "config error: %w" , err )
		return
	}
	if cfg.SecretMigrated {
		fmt.Fprintf( os.Stderr , "MOVED server.secret_key out of %s into %s -- back it up with the database.\n" , cfg.ConfigFile , cfg.SecretFile )
	}

	// "paths" reports configuration only, so it never needs the database and
	// stays useful when everything else is failing.
	command := arguments[ 0 ]
	rest := arguments[ 1: ]
	if command == "paths" {
		err = commandPaths( cfg )
		return
	}
	// "logs" reads the log files, never the database, so it works the same
	// with the server up or down -- the files are only ever appended to.
	if command == "logs" {
		err = commandLogs( cfg , rest )
		return
	}

	if cfg.RotationFinished {
		fmt.Fprintf( os.Stderr , "[secret] finished a key rotation that had been cut short; the new key is in %s\n" , cfg.SecretFile )
	}
	if command == "rotate-key" {
		err = commandRotateKey( cfg , rest )
		return
	}
	if cfg.RotationPending {
		err = config.ErrRotationPending
		return
	}

	// "restore" replaces the database, so it must not be holding it open --
	// and it has to work on a database too damaged for anything else to open.
	if command == "restore" {
		err = commandRestore( cfg , rest )
		return
	}

	back , err := connect( cfg )
	if err != nil { return }
	defer back.Close()

	// Say which route this took. Whether a command reached a live server or
	// opened the file itself changes what "it worked" means, and it goes to
	// stderr so piping list-users stays clean.
	fmt.Fprintf( os.Stderr , "[manage] %s\n" , back.Route() )

	switch command {
	case "bootstrap-admin":
		err = commandBootstrapAdmin( back , cfg , rest )
	case "create-login":
		err = commandCreateLogin( back , cfg , rest )
	case "reissue-login":
		err = commandReissueLogin( back , cfg , rest )
	case "list-users":
		err = commandListUsers( back )
	case "set-disabled":
		err = commandSetDisabled( back , rest )
	case "revoke-access":
		err = commandRevokeAccess( back , rest )
	case "reset-2fa":
		err = commandResetTwoFactor( back , rest )
	case "delete-user":
		err = commandDeleteUser( back , rest )
	case "transfer-owner":
		err = commandTransferOwner( back , rest )
	case "list-keys":
		err = commandListKeys( back , rest )
	case "create-key":
		err = commandCreateKey( back , cfg , rest )
	case "revoke-key":
		err = commandRevokeKey( back , rest )
	case "delete-key":
		err = commandDeleteKey( back , rest )
	case "create-invite":
		err = commandCreateInvite( back , cfg , rest )
	case "backup":
		err = commandBackup( back , rest )
	default:
		Usage()
		err = fmt.Errorf( "unknown command %q" , command )
	}
	return
}

// connect prefers a running server and falls back to the database file.
//
// The fallback is not a workaround, it is the point: on a fresh install there
// is no server yet, and `bootstrap-admin` has to work before anything else
// exists. The failure message names both routes, because "database is locked"
// on its own sends people hunting for the wrong problem.
func connect( cfg *config.Config ) ( back backend , err error ) {
	client , dial_err := control.Dial( cfg )
	if dial_err == nil {
		back = &controlBackend{ client: client , path: cfg.ControlSocketPath }
		return
	}
	if errors.Is( dial_err , control.ErrNoServer ) == false {
		err = fmt.Errorf( "control socket error: %w" , dial_err )
		return
	}

	store , open_err := db.Open( cfg )
	if open_err != nil {
		// A refused schema or a failed migration has its own message, and
		// advice about the socket would only send someone the wrong way.
		if db.IsLocked( open_err ) == false {
			err = open_err
			return
		}
		if cfg.ControlSocketEnabled {
			advice := "If the server is running, it was started with server.control_socket: false; restart it with the socket enabled or stop it first."
			// The socket is on the server container's own tmpfs, so a
			// `docker run` beside it finds no socket and then a locked file.
			if config.InContainer() {
				advice = "If the server is running in another container, this one cannot see its socket: use `docker exec <name> /app/server manage ...` there, or stop it first."
			}
			err = fmt.Errorf(
				"could not reach a running server on %s, and could not open the database directly: %w\n%s" ,
				cfg.ControlSocketPath , open_err , advice )
			return
		}
		err = fmt.Errorf( "database error (server.control_socket is false, so the server must be stopped): %w" , open_err )
		return
	}
	// A database written before the owner marker existed gets one here too,
	// so that the owner rules hold for commands run before the server's
	// first boot on the new version.
	if _ , err = models.EnsureOwner( store ); err != nil {
		store.Close()
		return
	}
	back = &directBackend{ store: store , cfg: cfg }
	return
}

// controlBackend sends each command to the running server.
type controlBackend struct {
	client *control.Client
	path   string
}

func ( b *controlBackend ) Route() ( description string ) {
	description = fmt.Sprintf( "running server via %s" , b.path )
	return
}

func ( b *controlBackend ) Close() ( err error ) {
	err = b.client.Close()
	return
}

func ( b *controlBackend ) ListUsers() ( users []control.UserResponse , err error ) {
	users , err = b.client.ListUsers()
	return
}

func ( b *controlBackend ) CreateUser( display_name string , role string ) ( user control.UserResponse , err error ) {
	user , err = b.client.CreateUser( display_name , role )
	return
}

func ( b *controlBackend ) ReissueLogin( user_id uint64 ) ( user control.UserResponse , err error ) {
	user , err = b.client.ReissueLogin( user_id )
	return
}

func ( b *controlBackend ) SetDisabled( user_id uint64 , disabled bool ) ( user control.UserResponse , err error ) {
	user , err = b.client.SetDisabled( user_id , disabled )
	return
}

func ( b *controlBackend ) RevokeAccess( user_id uint64 ) ( revoked models.Revoked , err error ) {
	revoked , err = b.client.RevokeAccess( user_id )
	return
}

func ( b *controlBackend ) ResetTwoFactor( user_id uint64 ) ( err error ) {
	err = b.client.ResetTwoFactor( user_id )
	return
}

func ( b *controlBackend ) DeleteUser( user_id uint64 ) ( removed models.Revoked , err error ) {
	removed , err = b.client.DeleteUser( user_id )
	return
}

func ( b *controlBackend ) TransferOwner( user_id uint64 ) ( user control.UserResponse , err error ) {
	user , err = b.client.TransferOwner( user_id )
	return
}

func ( b *controlBackend ) DeleteAPIKey( key_id string ) ( key control.APIKeyResponse , err error ) {
	key , err = b.client.DeleteAPIKey( key_id )
	return
}

func ( b *controlBackend ) ListAPIKeys( user_id uint64 ) ( keys []control.APIKeyResponse , err error ) {
	keys , err = b.client.ListAPIKeys( user_id )
	return
}

func ( b *controlBackend ) CreateAPIKey( user_id uint64 , name string , role string , expires_in_days *int ) ( key control.APIKeyResponse , err error ) {
	key , err = b.client.CreateAPIKey( user_id , name , role , expires_in_days )
	return
}

func ( b *controlBackend ) RevokeAPIKey( key_id string ) ( key control.APIKeyResponse , err error ) {
	key , err = b.client.RevokeAPIKey( key_id )
	return
}

func ( b *controlBackend ) CreateInviteLink( user_id uint64 , label string , max_uses int , days int ) ( link control.InviteLinkResponse , err error ) {
	link , err = b.client.CreateInviteLink( user_id , label , max_uses , days )
	return
}

func ( b *controlBackend ) Backup( options backup.Options ) ( result backup.Result , err error ) {
	result , err = b.client.Backup( options )
	return
}

// AnyAdminExists is derived from the user list rather than given its own
// endpoint. It is asked once, by bootstrap-admin, and a listing is cheap.
func ( b *controlBackend ) AnyAdminExists() ( result bool , err error ) {
	users , err := b.client.ListUsers()
	if err != nil { return }
	for _ , user := range users {
		if user.Role == models.RoleAdmin && user.Disabled == false {
			result = true
			return
		}
	}
	return
}

// directBackend opens the database itself, for when no server is running.
type directBackend struct {
	store *db.Store
	cfg   *config.Config
}

func ( b *directBackend ) Route() ( description string ) {
	description = fmt.Sprintf( "database directly at %s" , b.cfg.DatabasePath )
	return
}

func ( b *directBackend ) Close() ( err error ) {
	err = b.store.Close()
	return
}

func fromModel( user *models.User , owner_id uint64 , credential string ) ( result control.UserResponse ) {
	result = control.UserResponse{
		ID:          user.ID,
		DisplayName: user.DisplayName,
		Role:        user.Role,
		Disabled:    user.Disabled(),
		Owner:       user.ID == owner_id,
		Credential:  credential,
	}
	return
}

// response re-reads a user and the owner marker, so what is printed is what
// is stored.
func ( b *directBackend ) response( user_id uint64 , credential string ) ( user control.UserResponse , err error ) {
	found , err := models.GetUser( b.store , user_id )
	if err != nil { return }
	owner_id , err := models.OwnerID( b.store )
	if err != nil { return }
	user = fromModel( found , owner_id , credential )
	return
}

func ( b *directBackend ) ListUsers() ( users []control.UserResponse , err error ) {
	stored , err := models.ListUsers( b.store )
	if err != nil { return }
	owner_id , err := models.OwnerID( b.store )
	if err != nil { return }
	users = []control.UserResponse{}
	for _ , user := range stored {
		users = append( users , fromModel( user , owner_id , "" ) )
	}
	return
}

func ( b *directBackend ) CreateUser( display_name string , role string ) ( user control.UserResponse , err error ) {
	created , err := models.CreateUser( b.store , display_name , role )
	if err != nil { return }
	credential , err := models.IssueLoginToken( b.store , created.ID , b.cfg.LoginTokenTTL )
	if err != nil { return }
	user , err = b.response( created.ID , credential )
	return
}

func ( b *directBackend ) ReissueLogin( user_id uint64 ) ( user control.UserResponse , err error ) {
	found , err := models.GetUser( b.store , user_id )
	if err != nil {
		err = fmt.Errorf( "no user with id %d" , user_id )
		return
	}
	credential , err := models.IssueLoginToken( b.store , found.ID , b.cfg.LoginTokenTTL )
	if err != nil { return }
	user , err = b.response( found.ID , credential )
	return
}

func ( b *directBackend ) SetDisabled( user_id uint64 , disabled bool ) ( user control.UserResponse , err error ) {
	found , err := models.GetUser( b.store , user_id )
	if err != nil {
		err = fmt.Errorf( "no user with id %d" , user_id )
		return
	}
	// Disabling deletes the account's sessions and unused login links in the
	// same transaction -- see models.SetUserDisabled.
	if err = models.SetUserDisabled( b.store , found.ID , disabled ); err != nil { return }
	user , err = b.response( found.ID , "" )
	return
}

func ( b *directBackend ) RevokeAccess( user_id uint64 ) ( revoked models.Revoked , err error ) {
	if _ , err = models.GetUser( b.store , user_id ); err != nil {
		err = fmt.Errorf( "no user with id %d" , user_id )
		return
	}
	// The operator may revoke the owner's access too -- see
	// models.RevokeAllCredentials.
	revoked , err = models.RevokeAllCredentials( b.store , user_id , true )
	return
}

// ResetTwoFactor acts as the operator (actor 0), who may reset anyone.
func ( b *directBackend ) ResetTwoFactor( user_id uint64 ) ( err error ) {
	err = models.ResetTwoFactor( b.store , user_id , 0 )
	if errors.Is( err , db.ErrNotFound ) {
		err = fmt.Errorf( "no user with id %d" , user_id )
	}
	return
}

// DeleteUser acts as the operator (actor 0): any account but the owner.
func ( b *directBackend ) DeleteUser( user_id uint64 ) ( removed models.Revoked , err error ) {
	removed , err = models.DeleteUser( b.store , user_id , 0 )
	if errors.Is( err , db.ErrNotFound ) {
		err = fmt.Errorf( "no user with id %d" , user_id )
	}
	return
}

func ( b *directBackend ) TransferOwner( user_id uint64 ) ( user control.UserResponse , err error ) {
	err = models.TransferOwner( b.store , user_id )
	if errors.Is( err , db.ErrNotFound ) {
		err = fmt.Errorf( "no user with id %d" , user_id )
	}
	if err != nil { return }
	user , err = b.response( user_id , "" )
	return
}

// fromKeyModel mirrors control's own conversion so that a listing looks the
// same whether it came over the socket or out of the database.
func fromKeyModel( key *models.APIKey , display_name string , credential string ) ( result control.APIKeyResponse ) {
	result = control.APIKeyResponse{
		ID:          key.ID,
		UserID:      key.UserID,
		DisplayName: display_name,
		Name:        key.Name,
		Role:        key.Role,
		Live:        key.Live(),
		Revoked:     key.Revoked(),
		Expired:     key.Expired(),
		CreatedAt:   key.CreatedAt,
		ExpiresAt:   key.ExpiresAt,
		LastUsedAt:  key.LastUsedAt,
		RevokedAt:   key.RevokedAt,
		Credential:  credential,
	}
	return
}

// displayNames is one pass over the users bucket, rather than a read per key.
func ( b *directBackend ) displayNames() ( names map[ uint64 ]string , err error ) {
	names = map[ uint64 ]string{}
	users , err := models.ListUsers( b.store )
	if err != nil { return }
	for _ , user := range users {
		names[ user.ID ] = user.DisplayName
	}
	return
}

func ( b *directBackend ) ListAPIKeys( user_id uint64 ) ( keys []control.APIKeyResponse , err error ) {
	var stored []*models.APIKey
	if user_id == 0 {
		stored , err = models.ListAPIKeys( b.store )
	} else {
		stored , err = models.ListAPIKeysForUser( b.store , user_id )
	}
	if err != nil { return }

	names , err := b.displayNames()
	if err != nil { return }

	keys = []control.APIKeyResponse{}
	for _ , key := range stored {
		keys = append( keys , fromKeyModel( key , names[ key.UserID ] , "" ) )
	}
	return
}

func ( b *directBackend ) CreateAPIKey( user_id uint64 , name string , role string , expires_in_days *int ) ( key control.APIKeyResponse , err error ) {
	// Refuse rather than mint something that cannot be used: with the feature
	// off the server ignores the Authorization header entirely.
	if b.cfg.APIKeysEnabled == false {
		err = fmt.Errorf( "api keys are disabled on this server (auth.api_keys: false)" )
		return
	}

	owner , err := models.GetUser( b.store , user_id )
	if err != nil {
		err = fmt.Errorf( "no user with id %d" , user_id )
		return
	}
	ttl , ok := models.APIKeyTTLFromDays( expires_in_days , b.cfg.APIKeyTTL )
	if ok == false {
		err = fmt.Errorf( "-days must be 0 (never) or up to %d" , models.APIKeyMaxDays )
		return
	}

	credential , created , err := models.IssueAPIKey( b.store , owner.ID , name , role , ttl )
	if err != nil { return }
	key = fromKeyModel( created , owner.DisplayName , credential )
	return
}

func ( b *directBackend ) RevokeAPIKey( key_id string ) ( key control.APIKeyResponse , err error ) {
	found , err := models.GetAPIKey( b.store , key_id )
	if err != nil {
		err = fmt.Errorf( "no api key with id %s" , key_id )
		return
	}
	if err = models.RevokeAPIKey( b.store , found.ID ); err != nil { return }

	refreshed , err := models.GetAPIKey( b.store , found.ID )
	if err != nil { return }
	names , err := b.displayNames()
	if err != nil { return }
	key = fromKeyModel( refreshed , names[ refreshed.UserID ] , "" )
	return
}

func ( b *directBackend ) DeleteAPIKey( key_id string ) ( key control.APIKeyResponse , err error ) {
	found , err := models.GetAPIKey( b.store , key_id )
	if err != nil {
		err = fmt.Errorf( "no api key with id %s" , key_id )
		return
	}
	names , err := b.displayNames()
	if err != nil { return }
	// The CLI has no undo, so its delete is the hard one (see PurgeAPIKey).
	if err = models.PurgeAPIKey( b.store , found.ID ); err != nil { return }
	key = fromKeyModel( found , names[ found.UserID ] , "" )
	return
}

func ( b *directBackend ) CreateInviteLink( user_id uint64 , label string , max_uses int , days int ) ( link control.InviteLinkResponse , err error ) {
	credential , created , err := models.IssueInviteLinkAs( b.store , user_id , label , max_uses , days )
	if errors.Is( err , db.ErrNotFound ) {
		err = fmt.Errorf( "no user with id %d" , user_id )
	}
	if err != nil { return }
	link = control.InviteLinkFromModel( created , credential )
	return
}

func ( b *directBackend ) AnyAdminExists() ( result bool , err error ) {
	result , err = models.AnyAdminExists( b.store )
	return
}

func ( b *directBackend ) Backup( options backup.Options ) ( result backup.Result , err error ) {
	result , err = backup.Create( b.store , b.cfg , options )
	return
}

func commandBootstrapAdmin( back backend , cfg *config.Config , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "bootstrap-admin" , flag.ExitOnError )
	name := set.String( "name" , "" , "display name for the first admin" )
	force := set.Bool( "force" , false , "create another admin even if one exists" )
	set.Parse( arguments )

	if models.ValidDisplayName( *name ) == false {
		err = fmt.Errorf( "-name is required (1-80 characters)" )
		return
	}

	exists , err := back.AnyAdminExists()
	if err != nil { return }
	if exists && *force == false {
		fmt.Println( "An admin already exists. Re-run with -force to create another." )
		return
	}

	user , err := back.CreateUser( *name , models.RoleAdmin )
	if err != nil { return }

	bootstrap.PrintLoginLink( cfg , fmt.Sprintf( "admin #%d %q" , user.ID , user.DisplayName ) , user.Credential )
	return
}

func commandCreateLogin( back backend , cfg *config.Config , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "create-login" , flag.ExitOnError )
	name := set.String( "name" , "" , "display name" )
	role := set.String( "role" , models.RoleUser , "admin or user" )
	set.Parse( arguments )

	if models.ValidDisplayName( *name ) == false {
		err = fmt.Errorf( "-name is required (1-80 characters)" )
		return
	}
	if models.ValidRole( *role ) == false {
		err = fmt.Errorf( "-role must be admin or user" )
		return
	}

	user , err := back.CreateUser( *name , *role )
	if err != nil { return }

	bootstrap.PrintLoginLink( cfg , fmt.Sprintf( "%s #%d %q" , user.Role , user.ID , user.DisplayName ) , user.Credential )
	return
}

func commandReissueLogin( back backend , cfg *config.Config , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "reissue-login" , flag.ExitOnError )
	user_id := set.Uint64( "user-id" , 0 , "id of an existing user" )
	set.Parse( arguments )

	user , err := back.ReissueLogin( *user_id )
	if err != nil { return }

	bootstrap.PrintLoginLink( cfg , fmt.Sprintf( "%s #%d %q" , user.Role , user.ID , user.DisplayName ) , user.Credential )
	return
}

func commandBackup( back backend , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "backup" , flag.ExitOnError )
	out := set.String( "out" , "" , "a file to write, or a folder to write into (default: the backups folder)" )
	include_key := set.Bool( "include-key" , false , "put secret.key in the backup: anyone with the file can then read everything" )
	set.Parse( arguments )

	// A running server does the writing, and its working directory is not
	// this one, so a relative path has to be settled here.
	target := *out
	if target != "" {
		if target , err = filepath.Abs( target ); err != nil { return }
	}
	result , err := back.Backup( backup.Options{ Out: target , IncludeKey: *include_key } )
	if err != nil { return }

	fmt.Printf( "Backup written: %s (%d bytes)\n" , result.Path , result.Bytes )
	if result.Manifest.ContainsKey {
		fmt.Println( "WARNING: it includes secret.key. Anyone holding this file can read all the data." )
	} else {
		fmt.Printf( "secret.key is NOT in it. It needs the key with fingerprint %s:\n" , result.Manifest.KeyFingerprint )
		fmt.Println( "keep a copy of secret.key somewhere safe, apart from this file." )
	}
	if result.Manifest.EncryptAtRest == false {
		fmt.Println( "server.encrypt_at_rest is off, so the database in this backup is not encrypted." )
	}
	return
}

func commandRestore( cfg *config.Config , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "restore" , flag.ExitOnError )
	from := set.String( "from" , "" , "the backup file" )
	key_file := set.String( "key-file" , "" , "the key this backup was made with, if it is not the current one" )
	yes := set.Bool( "yes" , false , "confirm: the database and storage are replaced" )
	set.Parse( arguments )

	if *from == "" {
		err = fmt.Errorf( "-from is required" )
		return
	}
	if *yes == false {
		err = fmt.Errorf( "restore replaces the database and storage; pass -yes to confirm" )
		return
	}
	result , err := backup.Restore( cfg , backup.RestoreOptions{ From: *from , KeyFile: *key_file } )
	if err != nil { return }

	fmt.Printf( "Restored the backup from %s.\n" , result.Manifest.CreatedAt.Format( time.RFC3339 ) )
	if result.Rekeyed {
		fmt.Println( "It was made under another key and has been moved onto the current one." )
		fmt.Println( "Everyone has to sign in again, because their cookies were sealed with the other key." )
	}
	if result.SavedDatabase != "" {
		fmt.Printf( "The database it replaced: %s\n" , result.SavedDatabase )
	}
	if result.SavedStorage != "" {
		fmt.Printf( "The storage it replaced:  %s\n" , result.SavedStorage )
	}
	if result.SavedConfig != "" {
		fmt.Printf( "config.yaml was left as it is; the backup's copy is at %s\n" , result.SavedConfig )
	}
	return
}

func commandRotateKey( cfg *config.Config , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "rotate-key" , flag.ExitOnError )
	new_key_file := set.String( "new-key-file" , "" , "the new key, for docker/rotate-key.sh; empty means make one" )
	yes := set.Bool( "yes" , false , "confirm: everyone has to sign in again" )
	set.Parse( arguments )

	// Loading the config just finished a rotation that was cut short, which
	// is what this command was probably run to do. Rotating again on top of
	// it is not.
	if cfg.RotationFinished {
		fmt.Println( "That finished the rotation that was cut short. Run this again to rotate once more." )
		return
	}
	if *yes == false {
		err = fmt.Errorf( "rotate-key signs everyone out and needs the server stopped; pass -yes to confirm" )
		return
	}
	result , err := rotate.Run( cfg , rotate.Options{ NewKeyFile: *new_key_file } )
	if err != nil { return }

	if result.Resumed {
		fmt.Println( "Finished moving the data onto the new key." )
		return
	}
	fmt.Printf( "The data is on the new key (fingerprint %s, was %s).\n" , result.NewFingerprint , result.OldFingerprint )
	if cfg.EncryptAtRest {
		fmt.Printf( "Re-encrypted the database and %d log files.\n" , result.LogFiles )
	}
	if *new_key_file != "" { return }
	fmt.Printf( "The new key is in %s: back it up.\n" , cfg.SecretFile )
	fmt.Println( "Everyone has to sign in again." )
	if result.RetiredKey != "" {
		fmt.Printf( "The old key is kept at %s\n" , result.RetiredKey )
		fmt.Println( "Backups made before now still need it: `manage restore -key-file` takes it. Delete it" )
		fmt.Println( "once those backups no longer matter, and do not keep it beside them." )
	}
	return
}

func existsNote( path string ) ( note string ) {
	if _ , err := os.Stat( path ); err != nil {
		note = "  (absent -- the embedded copy is used)"
	}
	return
}

// commandPaths answers "where did it put my data", which is otherwise a
// question you can only settle by reading the source or the startup log.
func commandLogs( cfg *config.Config , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "logs" , flag.ExitOnError )
	day := set.String( "day" , "" , "a UTC date, YYYY-MM-DD; without it, list the days" )
	query := set.String( "q" , "" , "a search, as typed on the Logs screen" )
	limit := set.Int( "limit" , 50 , "entries to print, newest first (1-1000)" )
	set.Parse( arguments )

	reader := logs.New( cfg.Logs , cfg.SecretKey , cfg.EncryptAtRest )
	parsed := logs.ParseQuery( *query )
	if *day == "" {
		days , total , list_err := reader.Days( parsed )
		if list_err != nil {
			err = list_err
			return
		}
		for _ , row := range days {
			line := fmt.Sprintf( "%s  %7d entries  %5d errors  %9d bytes" , row.Date , row.Entries , row.Errors , row.Bytes )
			if row.Matches != nil {
				line += fmt.Sprintf( "  %d matches" , *row.Matches )
			}
			if row.Compressed {
				line += "  (gzipped)"
			}
			fmt.Println( line )
		}
		fmt.Printf( "%d bytes in %s\n" , total , cfg.Logs.Dir )
		return
	}
	if *limit < 1 || *limit > 1000 {
		err = fmt.Errorf( "-limit must be 1-1000" )
		return
	}
	records , _ , err := reader.ReadDay( *day , parsed , -1 , *limit )
	if err != nil { return }
	encoder := json.NewEncoder( os.Stdout )
	encoder.SetEscapeHTML( false )
	for _ , record := range records {
		encoder.Encode( record )
	}
	return
}

func commandPaths( cfg *config.Config ) ( err error ) {
	fmt.Printf( "%-14s %s\n" , "config" , cfg.ConfigFile )
	fmt.Printf( "%-14s %s  (the secret key: back it up with the database)\n" , "secret" , cfg.SecretFile )
	fmt.Printf( "%-14s %s  (relative paths in the config start here)\n" , "project dir" , cfg.ProjectDir )
	fmt.Printf( "%-14s %s  (from %s)\n" , "url" , cfg.URL , cfg.URLSource )
	fmt.Printf( "%-14s %s\n" , "app dir" , cfg.AppDir )
	fmt.Printf( "%-14s %s\n" , "database" , cfg.DatabasePath )
	fmt.Printf( "%-14s %s\n" , "storage" , cfg.StorageDir )
	fmt.Printf( "%-14s %s\n" , "logs" , cfg.Logs.Dir )
	fmt.Printf( "%-14s %s\n" , "backups" , cfg.Backups.Dir )
	fmt.Printf( "%-14s %s%s\n" , "static" , cfg.StaticDir , existsNote( cfg.StaticDir ) )
	fmt.Printf( "%-14s %s%s\n" , "language" , cfg.LanguageFile , existsNote( cfg.LanguageFile ) )

	// Whether a server is live decides which route every other command
	// takes, so report it here rather than making someone infer it.
	if cfg.ControlSocketEnabled == false {
		fmt.Printf( "%-14s %s\n" , "control" , "disabled (server.control_socket: false)" )
	} else if client , dial_err := control.Dial( cfg ); dial_err == nil {
		client.Close()
		fmt.Printf( "%-14s %s  (server running)\n" , "control" , cfg.ControlSocketPath )
	} else {
		fmt.Printf( "%-14s %s  (no server running)\n" , "control" , cfg.ControlSocketPath )
	}

	if cfg.ConfigWarning != "" {
		fmt.Printf( "%-14s %s\n" , "warning" , cfg.ConfigWarning )
	}

	// Whether the key sits inside the app dir decides what a backup has to
	// cover, so say which case this is rather than leaving it to be worked
	// out from the paths above.
	fmt.Println( "" )
	fmt.Printf( "Change any of these in %s (server.app_dir moves the app dir).\n" , cfg.ConfigFile )
	if filepath.Dir( cfg.SecretFile ) == cfg.AppDir {
		fmt.Println( "Back up the app dir as a unit -- app.db is unreadable without secret.key." )
	} else {
		fmt.Println( "secret.key is NOT in the app dir. Back up config.yaml, secret.key and the app" )
		fmt.Println( "dir together; app.db is unreadable without secret.key." )
	}
	return
}

func commandListUsers( back backend ) ( err error ) {
	users , err := back.ListUsers()
	if err != nil { return }
	if len( users ) == 0 {
		fmt.Println( "No users yet. Create the first admin with: manage bootstrap-admin -name \"Your Name\"" )
		return
	}
	fmt.Printf( "%-6s %-30s %-8s %s\n" , "ID" , "NAME" , "ROLE" , "STATUS" )
	for _ , user := range users {
		status := "active"
		if user.Disabled {
			status = "disabled"
		}
		if user.Owner {
			status += ", owner"
		}
		fmt.Printf( "%-6d %-30s %-8s %s\n" , user.ID , user.DisplayName , user.Role , status )
	}
	return
}

// formatKeyTime keeps the listings narrow. Minute precision is enough for
// "when was this last used" and a full RFC3339 stamp per column would make the
// table wrap on any normal terminal.
func formatKeyTime( value *time.Time , absent string ) ( result string ) {
	result = absent
	if value != nil {
		result = value.Local().Format( "2006-01-02 15:04" )
	}
	return
}

func keyStatus( key control.APIKeyResponse ) ( result string ) {
	switch {
	case key.Revoked:
		result = "revoked"
	case key.Expired:
		result = "expired"
	default:
		result = "active"
	}
	return
}

func commandListKeys( back backend , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "list-keys" , flag.ExitOnError )
	user_id := set.Uint64( "user-id" , 0 , "only this user's keys (default: everyone's)" )
	set.Parse( arguments )

	keys , err := back.ListAPIKeys( *user_id )
	if err != nil { return }
	if len( keys ) == 0 {
		fmt.Println( "No API keys. Create one with: manage create-key -user-id <id> -name \"CI\"" )
		return
	}

	fmt.Printf( "%-18s %-22s %-6s %-20s %-8s %-16s %s\n" ,
		"KEY ID" , "NAME" , "ROLE" , "OWNER" , "STATUS" , "LAST USED" , "EXPIRES" )
	for _ , key := range keys {
		owner := key.DisplayName
		if owner == "" {
			owner = fmt.Sprintf( "#%d" , key.UserID )
		}
		fmt.Printf( "%-18s %-22s %-6s %-20s %-8s %-16s %s\n" ,
			key.ID , key.Name , key.Role , owner , keyStatus( key ) ,
			formatKeyTime( key.LastUsedAt , "never" ) ,
			formatKeyTime( key.ExpiresAt , "never" ) )
	}
	return
}

// commandCreateKey is how a CI system or a cron job gets a credential without
// anyone signing in. The -role flag is what "mirroring admin and non-admin
// permissions" means in practice: -role admin produces a key that can do what
// an admin can, and the default produces one that cannot.
//
// -days is deliberately three-valued: omitted uses the server's default, 0
// means the key never expires, and a number is that many days.
func commandCreateKey( back backend , cfg *config.Config , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "create-key" , flag.ExitOnError )
	user_id := set.Uint64( "user-id" , 0 , "id of the account the key belongs to" )
	name := set.String( "name" , "" , "what this key is for, e.g. \"deploy bot\"" )
	role := set.String( "role" , models.RoleUser , "admin or user (never more than the account has)" )
	days := set.Int( "days" , -1 , "lifetime in days; 0 never expires; omit for the server default" )
	set.Parse( arguments )

	if models.ValidAPIKeyName( *name ) == false {
		err = fmt.Errorf( "-name is required (1-80 characters)" )
		return
	}
	if models.ValidRole( *role ) == false {
		err = fmt.Errorf( "-role must be admin or user" )
		return
	}

	// A negative value is the "flag not given" signal, which the API expresses
	// as an absent field rather than a number.
	var expires_in_days *int
	if *days >= 0 {
		expires_in_days = days
	}

	key , err := back.CreateAPIKey( *user_id , *name , *role , expires_in_days )
	if err != nil { return }

	expires := formatKeyTime( key.ExpiresAt , "never" )
	bootstrap.PrintAPIKey( cfg ,
		fmt.Sprintf( "%s-scoped %q for #%d %q" , key.Role , key.Name , key.UserID , key.DisplayName ) ,
		key.Credential , expires )
	return
}

// commandCreateInvite makes a link a whole group can join through, as the
// admin -user-id: it stops working if that admin is disabled or demoted.
func commandCreateInvite( back backend , cfg *config.Config , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "create-invite" , flag.ExitOnError )
	user_id := set.Uint64( "user-id" , 0 , "id of the admin the link is made as" )
	label := set.String( "label" , "" , "what the link is for, e.g. \"Book club\"" )
	uses := set.Int( "uses" , 10 , "how many people can join through it (1-1000)" )
	days := set.Int( "days" , 30 , "days until it stops working (1-365)" )
	set.Parse( arguments )

	link , err := back.CreateInviteLink( *user_id , *label , *uses , *days )
	if err != nil { return }

	if cfg.InviteLinksEnabled == false {
		fmt.Println( "note: auth.invite_links is off, so this link answers 404 until it is switched on" )
	}
	bootstrap.PrintInviteLink( cfg , fmt.Sprintf( "%q, %d places" , link.Label , link.MaxUses ) ,
		link.Credential , link.ExpiresAt.Local().Format( "2006-01-02 15:04" ) )
	return
}

func commandRevokeKey( back backend , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "revoke-key" , flag.ExitOnError )
	key_id := set.String( "key-id" , "" , "id of the key to revoke (from list-keys)" )
	set.Parse( arguments )

	if *key_id == "" {
		err = fmt.Errorf( "-key-id is required (see: manage list-keys)" )
		return
	}

	key , err := back.RevokeAPIKey( *key_id )
	if err != nil { return }
	fmt.Printf( "api key %s (%q, owner #%d) revoked -- it stops working immediately\n" , key.ID , key.Name , key.UserID )
	return
}

// commandDeleteKey is revoke-key without the record left behind.
func commandDeleteKey( back backend , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "delete-key" , flag.ExitOnError )
	key_id := set.String( "key-id" , "" , "id of the key to delete (from list-keys)" )
	set.Parse( arguments )

	if *key_id == "" {
		err = fmt.Errorf( "-key-id is required (see: manage list-keys)" )
		return
	}

	key , err := back.DeleteAPIKey( *key_id )
	if err != nil { return }
	fmt.Printf( "api key %s (%q, owner #%d) deleted -- it stops working immediately\n" , key.ID , key.Name , key.UserID )
	return
}

// commandDeleteUser asks for -yes because nothing brings the account back:
// the id is never reused and its keys and links are gone with it. Disabling
// is the reversible option, and the error says so.
func commandDeleteUser( back backend , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "delete-user" , flag.ExitOnError )
	user_id := set.Uint64( "user-id" , 0 , "id of an existing user" )
	yes := set.Bool( "yes" , false , "confirm: this cannot be undone" )
	set.Parse( arguments )

	if *yes == false {
		err = fmt.Errorf( "delete-user cannot be undone; re-run with -yes (or use set-disabled -user-id %d to keep the account)" , *user_id )
		return
	}

	removed , err := back.DeleteUser( *user_id )
	if err != nil { return }
	fmt.Printf( "user #%d deleted, with %d sessions, %d login links and %d API keys\n" ,
		*user_id , removed.Sessions , removed.LoginLinks , removed.APIKeys )
	return
}

func commandTransferOwner( back backend , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "transfer-owner" , flag.ExitOnError )
	user_id := set.Uint64( "user-id" , 0 , "id of an enabled admin" )
	set.Parse( arguments )

	user , err := back.TransferOwner( *user_id )
	if err != nil { return }
	fmt.Printf( "user #%d (%s) is now the owner\n" , user.ID , user.DisplayName )
	return
}

func commandSetDisabled( back backend , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "set-disabled" , flag.ExitOnError )
	user_id := set.Uint64( "user-id" , 0 , "id of an existing user" )
	disabled := set.Bool( "disabled" , true , "true to disable, false to re-enable" )
	set.Parse( arguments )

	user , err := back.SetDisabled( *user_id , *disabled )
	if err != nil { return }
	fmt.Printf( "user #%d (%s) disabled=%v\n" , user.ID , user.DisplayName , user.Disabled )
	return
}

// commandResetTwoFactor is the way back for someone with neither their phone
// nor their recovery codes -- the owner included, who no one can reset from
// the web.
func commandResetTwoFactor( back backend , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "reset-2fa" , flag.ExitOnError )
	user_id := set.Uint64( "user-id" , 0 , "id of an existing user" )
	set.Parse( arguments )

	if err = back.ResetTwoFactor( *user_id ); err != nil { return }
	fmt.Printf( "user #%d: two-factor sign-in is off\n" , *user_id )
	return
}

// commandRevokeAccess is the incident-response command: run it when an
// account's credentials may be in someone else's hands. The account stays
// enabled; follow it with reissue-login to let its owner back in.
func commandRevokeAccess( back backend , arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "revoke-access" , flag.ExitOnError )
	user_id := set.Uint64( "user-id" , 0 , "id of an existing user" )
	set.Parse( arguments )

	revoked , err := back.RevokeAccess( *user_id )
	if err != nil { return }
	fmt.Printf( "user #%d: ended %d sessions, deleted %d unused login links, removed %d passwords, revoked %d API keys\n" ,
		*user_id , revoked.Sessions , revoked.LoginLinks , revoked.Passwords , revoked.APIKeys )
	fmt.Printf( "To let them back in: reissue-login -user-id %d\n" , *user_id )
	return
}
