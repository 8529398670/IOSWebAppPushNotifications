//go:build windows

package disk

import (
	windows "golang.org/x/sys/windows"
)

// Space is what the filesystem holding path has: free is what this process may
// use, which leaves out anything held back by a disk quota.
func Space( path string ) ( free uint64 , total uint64 , err error ) {
	name , err := windows.UTF16PtrFromString( path )
	if err != nil { return }
	err = windows.GetDiskFreeSpaceEx( name , &free , &total , nil )
	return
}
