//go:build container

package config

// pinned is the container image's fixed layout. Only the Dockerfile builds
// with -tags container, so this applies inside the image and nowhere else.
//
// These are not settings because they are not choices: they are the paths
// docker/run.sh mounts into. Pinning them in the binary rather than passing
// them through ENV or flags means `docker exec <name> /app/server manage ...`
// finds the same config and database as the server with nothing extra to
// type, and a host-oriented server.app_dir in the shared config.yaml cannot
// point the container at a path that is not mounted.
//
//	/app/config/config.yaml   ./config/config.yaml, mounted writable: the
//	                          Settings screen rewrites it in place. Its
//	                          folder makes /app the project directory, so
//	                          relative paths resolve the same as in a checkout
//	/app/config/secret.key    ./config/secret.key, mounted read-only
//	/app/data                 docker.data_dir, the only writable mount
//	/tmp/control/control.sock the control socket, on the container's tmpfs and
//	                          not in /app/data: a folder shared from the host
//	                          may be unable to hold a socket (colima's cannot).
//	                          `docker exec` shares this tmpfs; a separate
//	                          `docker run` gets its own and finds no server
//	0.0.0.0                   inside the container's own network namespace; what
//	                          is reachable from outside is docker.bind_address
var pinned = layout{
	ConfigFile:    "/app/config/config.yaml",
	AppDir:        "/app/data",
	ControlSocket: "/tmp/control/control.sock",
	Host:          "0.0.0.0",
}
