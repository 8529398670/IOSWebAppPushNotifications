// Package healthcheck is the `health` subcommand: the container's HEALTHCHECK.
//
// It lives in the binary rather than as a wget line in the Dockerfile for two
// reasons. The port comes from config/config.yaml, so a hardcoded URL in the image
// would silently go stale the moment someone changed server.port. And the
// runtime image then needs no HTTP client of its own.
package healthcheck

import (
	fmt "fmt"
	http "net/http"
	time "time"

	config "ipb/server/config"
)

// Run asks the local server for /api/health and fails unless it answers 200.
// That endpoint touches nothing, so a slow database query can never get a
// healthy container killed.
func Run() ( err error ) {
	file , _ , _ , err := config.Current()
	if err != nil { return }

	client := &http.Client{ Timeout: 2 * time.Second }
	response , err := client.Get( fmt.Sprintf( "http://127.0.0.1:%d/api/health" , file.Server.Port ) )
	if err != nil { return }
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf( "health endpoint answered %d" , response.StatusCode )
	}
	return
}
