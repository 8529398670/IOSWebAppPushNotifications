// Package assets decides where the frontend comes from: the directory on
// disk, or the copy compiled into the binary.
//
// This is what lets one codebase produce two very different things without a
// build flag or a second code path:
//
//   - Running from a source checkout, ./static and ./config/language.yaml are read
//     from disk. Edit a file, refresh, see the change -- the whole point of
//     the no-store serving policy.
//   - A binary built by scripts/build.sh has no source tree next to it, so it falls
//     back to the embedded copy and runs anywhere as a single file.
//
// Disk wins when it is present because that is the only case where someone
// is actively editing. A shipped binary run somewhere with no ./static
// directory silently and correctly uses what is inside it.
package assets

import (
	fmt "fmt"
	fs "io/fs"
	os "os"
	filepath "path/filepath"
)

type Bundle struct {
	// Static is the filesystem the web server serves from, rooted at what
	// would be ./static -- so "css/style.css", not "static/css/style.css".
	Static fs.FS

	// LanguageYAML is the raw language.yaml, already read.
	LanguageYAML []byte

	// Source describes where the above came from, for the startup log. Being
	// able to see "embedded" versus "disk" in the log is the fastest way to
	// explain why an edit did or did not show up.
	Source string
}

func isDirectory( path string ) ( result bool ) {
	info , err := os.Stat( path )
	result = err == nil && info.IsDir()
	return
}

func isRegularFile( path string ) ( result bool ) {
	info , err := os.Stat( path )
	result = err == nil && info.Mode().IsRegular()
	return
}

// Resolve prefers disk and falls back to embedded, independently for the
// static tree and the language file. They are separate on purpose: a
// deployment that wants the shipped UI but its own wording only has to place
// a language.yaml in its app directory.
func Resolve( static_dir string , language_file string , embedded_static fs.FS , embedded_language []byte ) ( bundle Bundle , err error ) {
	static_source := "embedded"
	bundle.Static = embedded_static
	if static_dir != "" && isDirectory( static_dir ) {
		absolute , abs_err := filepath.Abs( static_dir )
		if abs_err != nil {
			err = abs_err
			return
		}
		// os.Root, not os.DirFS. Both re-read on every call, so the
		// always-fresh serving behaviour survives either way -- but os.DirFS
		// follows symlinks wherever they point, so a link in static/ to
		// ../config/config.yaml would hand the secret key to any visitor. A Root
		// refuses to resolve anything, symlinks included, that lands outside
		// the directory. It holds the directory open for the life of the
		// process, so replacing static/ wholesale (rather than the files in
		// it) needs a restart to be seen.
		root , root_err := os.OpenRoot( absolute )
		if root_err != nil {
			err = fmt.Errorf( "could not open static directory %q: %w" , absolute , root_err )
			return
		}
		bundle.Static = root.FS()
		static_source = "disk " + absolute
	}

	language_source := "embedded"
	bundle.LanguageYAML = embedded_language
	if language_file != "" && isRegularFile( language_file ) {
		raw , read_err := os.ReadFile( language_file )
		if read_err != nil {
			err = fmt.Errorf( "could not read language file %q: %w" , language_file , read_err )
			return
		}
		bundle.LanguageYAML = raw
		language_source = "disk " + language_file
	}

	if len( bundle.LanguageYAML ) == 0 {
		err = fmt.Errorf( "no language.yaml found on disk (%q) and none embedded -- the UI would render with no text" , language_file )
		return
	}

	bundle.Source = fmt.Sprintf( "static=%s language=%s" , static_source , language_source )
	return
}
