# Shared by scripts/run.sh and scripts/login.sh. Sourced, not run, from the
# project root.
#
# Nothing here parses config.yaml. read_server_config asks the binary
# (`config shell server`), which resolves every path and the URL exactly the
# way the server will -- so what these scripts print is what will happen, not
# a guess at it. After it runs, every key listed in server/config/command.go
# under "server" is set: config_file, app_dir, database, url, port, ...

BINARY="$( pwd )/ipb"
RUN_DIR="$( pwd )/.run"
PID_FILE="${RUN_DIR}/server.pid"

# Rebuild every time and let Go decide whether that means anything: its build
# cache makes an unchanged tree a near-instant no-op, and catches every input
# that matters -- .go files, go.mod, and the embedded static/ and config/ --
# with no timestamp bookkeeping here to get wrong.
#
# Version metadata is stamped the way scripts/build.sh does it, so
# `scripts/run.sh version` says what is running. No -s -w: this build is for
# debugging, not shipping. The version is the UTC build time
# (2026.10.23-1412): it sorts, it says when, and the commit hash is stamped
# separately alongside it.
build_binary() {
  VERSION="$( date -u +%Y.%m.%d-%H%M )"
  COMMIT="$( git rev-parse --short HEAD 2>/dev/null || echo "unknown" )"
  if ! command -v go >/dev/null 2>&1; then
    echo "ERROR: go is not on PATH. Install Go (https://go.dev/dl/) and re-run." >&2
    exit 1
  fi
  if ! go build -buildvcs=false -trimpath \
         -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT}" \
         -o "$BINARY" .; then
    echo "" >&2
    echo "ERROR: the build failed (above). Nothing was stopped or started." >&2
    exit 1
  fi
}

# Assigned before it is eval'd so that a config error stops the script:
# `eval "$( failing )"` would quietly eval nothing and carry on.
read_server_config() {
  local assignments
  if ! assignments="$( "$BINARY" config shell server )"; then
    echo "" >&2
    echo "ERROR: the config above does not validate. Fix it and re-run." >&2
    exit 1
  fi
  eval "$assignments"
}

# docker_container, docker_url, ... from the same config, for the scripts that
# need to know whether the container is the live deployment.
read_docker_config() {
  local assignments
  assignments="$( "$BINARY" config shell docker )" || exit 1
  eval "$assignments"
}

# The pid of the server this checkout started, if it is still that server. The
# command-line check matters: a pid left behind by a server that has since
# exited can belong to anything by now.
our_server_pid() {
  local pid
  [ -f "$PID_FILE" ] || return 0
  pid="$( cat "$PID_FILE" )"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null \
     && [ "$( ps -p "$pid" -o command= 2>/dev/null )" = "$BINARY" ]; then
    echo "$pid"
  fi
}

# Stop the server this checkout started, if it is running: TERM, then KILL if
# it is still there 20 seconds later. Clears the pid file either way.
stop_our_server() {
  local pid
  pid="$( our_server_pid )"
  if [ -n "$pid" ]; then
    echo "Stopping the server this checkout started (pid ${pid}, running since $( ps -p "$pid" -o lstart= 2>/dev/null | sed 's/  */ /g' ))..."
    kill -TERM "$pid" 2>/dev/null || true
    # It shuts down gracefully within 15 seconds (drainWait and jobStopWait in
    # main.go). Past that, something is stuck, and waiting longer will not
    # unstick it.
    for _ in $( seq 1 80 ); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.25
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "It did not exit in 20 seconds; killing it."
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$PID_FILE"
}

# Start scripts/run.sh detached, its output in .run/server.log, and wait until
# the server answers. On success BACKGROUND_PID is the server's pid; on failure
# the end of the log is shown and the script exits.
LOG_FILE="${RUN_DIR}/server.log"
start_in_background() {
  local launched
  mkdir -p "$RUN_DIR"
  # nohup so closing this terminal does not take the server with it. run.sh
  # execs the server, so the pid it writes is the server's.
  nohup scripts/run.sh > "$LOG_FILE" 2>&1 < /dev/null &
  launched=$!
  for _ in $( seq 1 80 ); do
    sleep 0.25
    BACKGROUND_PID="$( our_server_pid )"
    if [ -n "$BACKGROUND_PID" ] && server_answers; then
      return 0
    fi
    kill -0 "$launched" 2>/dev/null || break
  done
  echo "ERROR: the server did not come up. The end of ${LOG_FILE}:" >&2
  echo "" >&2
  tail -n 20 "$LOG_FILE" | sed 's/^/    /' >&2
  exit 1
}

# "nginx (pid 812)" for whatever is listening on a TCP port, or nothing.
port_owner() {
  local port="$1" pid name
  command -v lsof >/dev/null 2>&1 || return 0
  # || true: lsof exits 1 when nothing listens, which pipefail would pass on.
  pid="$( lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -n 1 || true )"
  [ -n "$pid" ] || return 0
  # The command with its program's directory dropped: "Python -m http.server
  # 8080" says more in one line than a long install path does.
  name="$( ps -p "$pid" -o command= 2>/dev/null | awk '{ n = split( $1 , part , "/" ); $1 = part[ n ]; print }' | cut -c1-100 )"
  echo "${name:-unknown} (pid ${pid})"
}

# Whether a server answers /api/health on server.port, via the binary's own
# healthcheck so the port and path stay in one place.
server_answers() {
  "$BINARY" health >/dev/null 2>&1
}

# The line number of a key in config.yaml, for messages that say exactly
# which line to change.
config_line() {
  grep -n "^[[:space:]]*$1:" "$config_file" 2>/dev/null | head -n 1 | cut -d: -f1
}

# Whether a docker container with this exact name is running. Quiet and
# false when docker is missing or its daemon is not up.
container_running() {
  command -v docker >/dev/null 2>&1 || return 1
  [ -n "$( docker ps --filter "name=^${1}\$" --format '{{.Names}}' 2>/dev/null )" ]
}
