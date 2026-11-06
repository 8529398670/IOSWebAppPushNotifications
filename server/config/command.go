package config

import (
	flag "flag"
	fmt "fmt"
	os "os"
	filepath "path/filepath"
	strconv "strconv"
	strings "strings"
)

const commandUsage = `config -- create, check, change, or read config.yaml

Usage:
  init  [-file ./config/config.yaml | -dir DIR]
                                     write a new config.yaml, and a secret.key
                                     beside it unless one is there (-file -
                                     prints config.yaml instead)
  example [-file ./config/config.example.yaml]
                                     write the committed example: every
                                     default (-file - prints it)
  secret [-file ./config/secret.key] write a new secret.key; never replaces
                                     one (-file - prints a fresh key)
  migrate [-file path | -dir DIR]    move server.secret_key out of an older
                                     config.yaml into secret.key; silent when
                                     there is nothing to do
  check [-file path]                 validate the config in use and its
                                     secret.key, and say which files they are
  set [-file path] section.key value change one setting in place, keeping
                                     every comment; a running server applies
                                     it within seconds. Lists: [a, b] or a,b
  shell [-file path] [-format sh|bat] server|docker|build
                                     print one section as assignments for the
                                     scripts to read: sh (quoted, for eval) or
                                     bat (plain key=value, for for /f).
                                     server is every resolved path and the URL

Without -file, the file is found the way the server finds it:
  ./config/config.yaml, then ~/.config/ipb/config.yaml
`

// CommandUsage prints the config subcommands.
func CommandUsage() {
	fmt.Print( commandUsage )
}

// RunCommand executes `config <subcommand>`. arguments is everything after
// "config".
//
// These exist so that nothing else has to parse YAML. The scripts in docker/ and
// build.sh eval the output of `config shell`, which means the scripts get the
// same defaults, the same strict decoding, and the same validation as the
// server -- a typo in the docker section fails the deploy before anything
// starts, instead of being ignored by a second, looser parser.
func RunCommand( arguments []string ) ( err error ) {
	if len( arguments ) < 1 {
		CommandUsage()
		err = fmt.Errorf( "no config command given" )
		return
	}
	command , rest := arguments[ 0 ] , arguments[ 1: ]
	switch command {
	case "init":
		err = commandInit( rest )
	case "example":
		err = commandExample( rest )
	case "secret":
		err = commandSecret( rest )
	case "migrate":
		err = commandMigrate( rest )
	case "check":
		err = commandCheck( rest )
	case "set":
		err = commandSet( rest )
	case "shell":
		err = commandShell( rest )
	default:
		CommandUsage()
		err = fmt.Errorf( "unknown config command %q" , command )
	}
	return
}

// configPathFlags adds -file and -dir, and resolves them: -dir DIR means
// DIR/config.yaml (and so DIR/secret.key). docker/lib.sh uses -dir with the
// project's config/ folder mounted, which lets the files be created as the
// invoking user.
func configPathFlags( set *flag.FlagSet , default_file string ) ( resolve func() string ) {
	file := set.String( "file" , default_file , "config.yaml to use" )
	dir := set.String( "dir" , "" , "folder for config.yaml and secret.key" )
	resolve = func() ( path string ) {
		path = *file
		if *dir != "" {
			path = filepath.Join( *dir , ConfigFileName )
		}
		return
	}
	return
}

func commandInit( arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "config init" , flag.ExitOnError )
	resolve := configPathFlags( set , filepath.Join( ConfigDirName , ConfigFileName ) )
	set.Parse( arguments )
	path := resolve()

	if path == "-" {
		var content []byte
		content , err = NewFileContent()
		if err != nil { return }
		_ , err = os.Stdout.Write( content )
		return
	}
	secret_created , err := WriteNew( path )
	if err != nil { return }
	fmt.Printf( "wrote %s (mode 0600)\n" , path )
	if secret_created {
		fmt.Printf( "wrote %s (mode 0600, fresh secret key)\n" , SecretPathFor( path ) )
	} else {
		fmt.Printf( "kept  %s (already there)\n" , SecretPathFor( path ) )
	}
	fmt.Println( "Keep both out of version control, and back secret.key up with the app's data." )
	return
}

// commandSecret writes secret.key on its own: for a config.yaml copied from
// config.example.yaml, or a fresh install whose config came from elsewhere.
func commandSecret( arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "config secret" , flag.ExitOnError )
	path := set.String( "file" , filepath.Join( ConfigDirName , SecretFileName ) , "where to write it; - prints a fresh key" )
	set.Parse( arguments )
	if *path == "-" {
		fmt.Println( GenerateSecret() )
		return
	}
	if err = WriteSecret( *path , GenerateSecret() ); err != nil { return }
	fmt.Printf( "wrote %s (mode 0600, fresh secret key -- back it up with the app's data)\n" , *path )
	return
}

// commandMigrate is MigrateLegacySecret from the command line. scripts/run.sh
// and docker/run.sh run it before every start, so it says nothing unless it
// did something.
func commandMigrate( arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "config migrate" , flag.ExitOnError )
	resolve := configPathFlags( set , "" )
	set.Parse( arguments )
	path := resolve()
	if path == "" {
		path , _ = Locate()
	}
	if isFile( path ) == false { return }
	result , err := MigrateLegacySecret( path )
	if err != nil { return }
	if result.Moved {
		fmt.Printf( "MOVED server.secret_key out of %s into %s (mode 0600).\n" , path , result.SecretFile )
		fmt.Println( "  config.yaml holds no secret now; back secret.key up with the app's data." )
	} else if result.Removed {
		fmt.Printf( "Removed server.secret_key from %s; %s already held the same key.\n" , path , result.SecretFile )
	}
	return
}

// commandSet changes one setting the way the Settings screen does: the value
// is checked against the schema, written in place, and the whole file
// validated before anything is written.
func commandSet( arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "config set" , flag.ExitOnError )
	explicit := set.String( "file" , "" , "config file to change (default: the one in use)" )
	set.Parse( arguments )
	if set.NArg() != 2 {
		err = fmt.Errorf( "config set needs a key and a value, e.g. config set server.public_url https://app.example.com" )
		return
	}
	path := *explicit
	if path == "" {
		path , _ = Locate()
	}
	key , found , err := SchemaKey( set.Arg( 0 ) )
	if err != nil { return }
	if found == false {
		err = &UnknownSettingError{ Key: set.Arg( 0 ) }
		return
	}
	value , err := ParseValue( key , set.Arg( 1 ) )
	if err != nil { return }
	raw , err := os.ReadFile( path )
	if err != nil { return }
	edited , unchanged , err := EditChanges( raw , map[string]any{ key.Path: value } , path , false )
	if err != nil { return }
	if len( unchanged ) > 0 {
		fmt.Printf( "%s is already %v in %s\n" , key.Path , value , path )
		return
	}
	in_place := InContainer() && path == pinned.ConfigFile
	backup := ""
	if in_place {
		backup = filepath.Join( pinned.AppDir , BackupFileName )
	}
	if err = writeConfigFile( path , edited , in_place , backup ); err != nil { return }
	switch key.Mode {
	case ModeLive:
		fmt.Printf( "set %s in %s -- a running server applies it within seconds\n" , key.Path , path )
	case ModeScripts:
		fmt.Printf( "set %s in %s -- used the next time the scripts run\n" , key.Path , path )
	default:
		fmt.Printf( "set %s in %s -- takes effect when the server restarts\n" , key.Path , path )
	}
	return
}

// commandExample regenerates config.example.yaml from the embedded defaults,
// so after changing a default the example can be brought back in step with
// one command instead of by hand.
func commandExample( arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "config example" , flag.ExitOnError )
	path := set.String( "file" , filepath.Join( ConfigDirName , ExampleFileName ) , "where to write it; - for stdout" )
	set.Parse( arguments )

	if *path == "-" {
		var content []byte
		content , err = ExampleFileContent()
		if err != nil { return }
		_ , err = os.Stdout.Write( content )
		return
	}
	if err = WriteExample( *path ); err != nil { return }
	fmt.Printf( "wrote %s (no secret key -- safe to commit)\n" , *path )
	return
}

// pickFile resolves -file, or the file the server would use. found is false
// when there is no file, in which case the defaults apply.
func pickFile( explicit string ) ( file *File , path string , found bool , err error ) {
	if explicit == "" {
		file , path , found , err = Current()
		return
	}
	path = explicit
	if isFile( path ) == false {
		file , err = Defaults()
		return
	}
	found = true
	file , err = ReadFile( path )
	return
}

func commandCheck( arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "config check" , flag.ExitOnError )
	explicit := set.String( "file" , "" , "config file to check (default: the one in use)" )
	set.Parse( arguments )

	file , path , found , err := pickFile( *explicit )
	if err != nil { return }
	if found == false {
		if *explicit != "" {
			err = fmt.Errorf( "%s does not exist" , path )
			return
		}
		fmt.Printf( "no config.yaml yet -- the server will create %s on first run (scripts/run.sh writes ./config/config.yaml instead)\n" , path )
		return
	}
	secret_path := SecretPathFor( path )
	if legacy := file.Server.SecretKey; legacy != "" {
		fmt.Printf( "warning: %s still holds server.secret_key -- `config migrate` moves it into %s\n" , path , secret_path )
	} else if _ , err = ReadSecret( secret_path ); err != nil {
		return
	}
	fmt.Printf( "ok  %s\n" , path )
	if isFile( secret_path ) {
		fmt.Printf( "ok  %s\n" , secret_path )
	}
	if warning := permissionWarning( path , secret_path ); warning != "" {
		fmt.Printf( "warning: %s\n" , warning )
	}
	if info , stat_err := os.Stat( path ); stat_err == nil {
		if links , ok := linkCount( info ); ok && links == 0 {
			fmt.Println( "warning: config.yaml was replaced on the host since this container started; restart it to see the new file" )
		}
	}
	return
}

func commandShell( arguments []string ) ( err error ) {
	set := flag.NewFlagSet( "config shell" , flag.ExitOnError )
	explicit := set.String( "file" , "" , "config file to read (default: the one in use)" )
	format := set.String( "format" , "sh" , "sh (single-quoted, for eval) or bat (plain key=value)" )
	set.Parse( arguments )

	if set.NArg() != 1 {
		err = fmt.Errorf( "config shell needs one section: server, docker or build" )
		return
	}
	if *format != "sh" && *format != "bat" {
		err = fmt.Errorf( "unknown -format %q: use sh or bat" , *format )
		return
	}
	file , path , found , err := pickFile( *explicit )
	if err != nil { return }
	if absolute , abs_err := filepath.Abs( path ); abs_err == nil {
		path = absolute
	}

	var lines [][2]string
	switch set.Arg( 0 ) {
	case "server":
		// What the server would use, resolved exactly as Load resolves it,
		// without creating anything. The scripts print these instead of
		// guessing, so what they say is what will happen.
		paths := ResolvePaths( file , path )
		link_url , link_source := ServerURL( file )
		lines = [][2]string{
			{ "config_file" , path },
			{ "config_exists" , strconv.FormatBool( found ) },
			{ "secret_file" , SecretPathFor( path ) },
			{ "secret_exists" , strconv.FormatBool( isFile( SecretPathFor( path ) ) ) },
			{ "project_dir" , paths.ProjectDir },
			{ "app_dir" , paths.AppDir },
			{ "database" , paths.DatabasePath },
			{ "database_exists" , strconv.FormatBool( isFile( paths.DatabasePath ) ) },
			{ "static_dir" , paths.StaticDir },
			{ "static_on_disk" , strconv.FormatBool( isDir( paths.StaticDir ) ) },
			{ "language_file" , paths.LanguageFile },
			{ "language_on_disk" , strconv.FormatBool( isFile( paths.LanguageFile ) ) },
			{ "host" , file.Server.Host },
			{ "port" , strconv.Itoa( file.Server.Port ) },
			{ "url" , link_url },
			{ "url_source" , link_source },
			{ "public_url" , file.Server.PublicURL },
			{ "secure_cookies" , strconv.FormatBool( file.Server.SecureCookies ) },
			{ "trust_proxy" , strconv.FormatBool( file.Server.TrustProxy ) },
			{ "control_socket" , strconv.FormatBool( file.Server.ControlSocket ) },
			{ "control_socket_path" , paths.ControlSocketPath },
		}
	case "docker":
		docker := file.Docker
		// The full -p value is assembled here so the script does not have to
		// know that an IPv6 address needs brackets.
		bind := docker.BindAddress
		if strings.Contains( bind , ":" ) {
			bind = "[" + bind + "]"
		}
		lines = [][2]string{
			{ "docker_image" , docker.Image },
			{ "docker_container" , docker.Container },
			{ "docker_bind_address" , docker.BindAddress },
			{ "docker_host_port" , strconv.Itoa( docker.HostPort ) },
			{ "docker_publish" , fmt.Sprintf( "%s:%d:%d" , bind , docker.HostPort , file.Server.Port ) },
			{ "docker_data_dir" , docker.DataDir },
			{ "docker_restart" , docker.Restart },
			{ "docker_memory" , docker.Memory },
			{ "docker_cpus" , docker.CPUs },
			{ "docker_pids_limit" , strconv.Itoa( docker.PidsLimit ) },
			{ "docker_tmpfs_size" , docker.TmpfsSize },
			{ "server_port" , strconv.Itoa( file.Server.Port ) },
			{ "server_secure_cookies" , strconv.FormatBool( file.Server.SecureCookies ) },
			{ "server_trust_proxy" , strconv.FormatBool( file.Server.TrustProxy ) },
		}
		docker_url , docker_url_source := DockerURL( file )
		lines = append( lines , [2]string{ "docker_url" , docker_url } , [2]string{ "docker_url_source" , docker_url_source } )
	case "build":
		build := file.Build
		lines = [][2]string{
			{ "build_binary_name" , build.BinaryName },
			{ "build_output_dir" , build.OutputDir },
			{ "build_targets" , strings.Join( build.Targets , " " ) },
		}
	default:
		err = fmt.Errorf( "unknown section %q: use server, docker or build" , set.Arg( 0 ) )
		return
	}

	// Never the secret key, only where it is: nothing a script does needs it, and this output
	// tends to end up in terminal scrollback and CI logs.
	for _ , line := range lines {
		if *format == "bat" {
			// cmd has no quoting to undo; for /f "tokens=1,* delims==" splits
			// on the first = and keeps the rest of the line as the value.
			fmt.Printf( "%s=%s\r\n" , line[ 0 ] , strings.NewReplacer( "\r" , " " , "\n" , " " ).Replace( line[ 1 ] ) )
			continue
		}
		fmt.Printf( "%s=%s\n" , line[ 0 ] , shellQuote( line[ 1 ] ) )
	}
	return
}

// shellQuote single-quotes a value for POSIX sh, which makes any content
// inert under eval -- on top of Validate having already rejected anything
// unusual.
func shellQuote( value string ) ( result string ) {
	result = "'" + strings.ReplaceAll( value , "'" , `'\''` ) + "'"
	return
}

func isDir( path string ) ( result bool ) {
	info , err := os.Stat( path )
	result = err == nil && info.IsDir()
	return
}
