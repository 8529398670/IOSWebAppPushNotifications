//go:build !windows

// Package disk says how much room a filesystem has. A package of its own only
// because the system call is different on Windows, which scripts/build.sh
// builds for.
package disk

import (
	syscall "syscall"
)

// Space is what the filesystem holding path has: free is what this process may
// use, which leaves out anything reserved for root.
func Space( path string ) ( free uint64 , total uint64 , err error ) {
	var stat syscall.Statfs_t
	if err = syscall.Statfs( path , &stat ); err != nil { return }
	free = uint64( stat.Bavail ) * uint64( stat.Bsize )
	total = uint64( stat.Blocks ) * uint64( stat.Bsize )
	return
}
