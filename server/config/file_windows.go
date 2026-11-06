//go:build windows

package config

import (
	os "os"
)

// Windows has no link count in os.FileInfo and no Unix groups; neither
// check applies there. See file_unix.go.
func linkCount( info os.FileInfo ) ( links uint64 , ok bool ) {
	return
}

// OwnedByProcess has nothing to compare on Windows, where the directory ACL
// decides who gets in.
func OwnedByProcess( info os.FileInfo ) ( result bool ) {
	result = true
	return
}

func keepGroup( path string , previous os.FileInfo ) {}
