//go:build !windows

package config

import (
	os "os"
	syscall "syscall"
)

// linkCount is how many directory entries point at the file. Zero means the
// file was deleted or replaced while open -- which is how the container sees
// its mounted config.yaml after a host editor saves by renaming a new file
// over it.
func linkCount( info os.FileInfo ) ( links uint64 , ok bool ) {
	if stat , is_stat := info.Sys().( *syscall.Stat_t ); is_stat {
		links , ok = uint64( stat.Nlink ) , true
	}
	return
}

// OwnedByProcess reports whether this process's user owns the file.
func OwnedByProcess( info os.FileInfo ) ( result bool ) {
	if stat , is_stat := info.Sys().( *syscall.Stat_t ); is_stat {
		result = int( stat.Uid ) == os.Geteuid()
	}
	return
}

// keepGroup gives a rewritten file back the group the old one had.
func keepGroup( path string , previous os.FileInfo ) {
	if stat , is_stat := previous.Sys().( *syscall.Stat_t ); is_stat {
		os.Chown( path , -1 , int( stat.Gid ) )
	}
}
