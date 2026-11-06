package jobs

import (
	fmt "fmt"

	config "ipb/server/config"
	db "ipb/server/db"
	models "ipb/server/models"
)

// sweepFiles removes what uploads leave behind; see models.SweepFiles. It runs
// with files.enabled off as well: switching uploads off is no reason to keep a
// deleted file past its undo window.
func sweepFiles( store *db.Store , settings *config.Holder ) ( run Func ) {
	run = func() ( note string , err error ) {
		removed , strays , err := models.SweepFiles( store , settings.Get() )
		note = fmt.Sprintf( "removed %d files, %d strays" , removed , strays )
		return
	}
	return
}
