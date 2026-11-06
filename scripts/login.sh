#!/usr/bin/env bash
# Print a one-time login link -- by default for user 1, the owner -- for
# whichever deployment of this checkout is actually live.
#
#   scripts/login.sh               the owner (user 1)
#   scripts/login.sh 3             user 3
#   scripts/login.sh --docker      the docker container, even if a local
#                                  server is running too
#   scripts/login.sh --local       this checkout's local server
#   scripts/login.sh --no-start    never start a server: with none running,
#                                  write the link into the database offline
#   scripts/login.sh --background  with none running, start one detached
#                                  instead of in this terminal
#
# Where the link comes from:
#   - the local server (scripts/run.sh) when it is running: the link goes
#     through its control socket;
#   - otherwise the docker container (docker/run.sh) when it is running:
#     the link goes through `docker exec`;
#   - otherwise this writes the link into the database, prints it, and
#     becomes scripts/run.sh: the server runs in this terminal and Ctrl-C
#     stops it. With no database yet, the server's first start prints the
#     owner's link instead.
# With --background the server starts detached instead (log in
# .run/server.log, stop it with scripts/run.sh stop), and the link comes
# from it once it answers. Use that where nothing can hold a terminal open.
# The local server and the container keep separate databases, so a link from
# one does nothing in the other. This says which one it used.
#
# The URL in the link is server.public_url when set, otherwise the local
# address (see `scripts/run.sh config shell server`).
set -euo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )/.."


USER_ID=1
MODE=auto
START=true
BACKGROUND=false
for argument in "$@"; do
  case "$argument" in
    --docker) MODE=docker ;;
    --local)  MODE=local ;;
    --no-start) START=false ;;
    --background) BACKGROUND=true ;;
    -h|--help) sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *[!0-9]*|"")
      echo "ERROR: expected a numeric user id, --docker, --local, --no-start or --background; got '${argument}'." >&2
      exit 1 ;;
    *) USER_ID="$argument" ;;
  esac
done

source scripts/lib.sh
build_binary
read_server_config
read_docker_config

if [ "$config_exists" != "true" ]; then
  echo "ERROR: no config yet -- ${config_file} does not exist." >&2
  echo "       Run scripts/run.sh first: it writes one, and the first start prints" >&2
  echo "       the owner's login link." >&2
  exit 1
fi

LOCAL_PID="$( our_server_pid )"
DOCKER_UP=false
container_running "$docker_container" && DOCKER_UP=true

if [ "$MODE" = "auto" ]; then
  if [ -n "$LOCAL_PID" ]; then
    MODE=local
    if [ "$DOCKER_UP" = "true" ]; then
      echo "Note: the ${docker_container} container is running too. It has its own database;"
      echo "      this link is for the local server. Use --docker for the container."
      echo ""
    fi
  elif [ "$DOCKER_UP" = "true" ]; then
    MODE=docker
  else
    MODE=local
  fi
fi

if [ "$MODE" = "docker" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is not on PATH." >&2
    exit 1
  fi
  if [ "$DOCKER_UP" != "true" ]; then
    STATE="$( docker ps -a --filter "name=^${docker_container}\$" --format '{{.Status}}' 2>/dev/null || true )"
    echo "ERROR: the ${docker_container} container is not running${STATE:+ (docker: ${STATE})}." >&2
    echo "       Start it with docker/run.sh${STATE:+, or see why it stopped: docker logs ${docker_container}}." >&2
    exit 1
  fi
  echo "Docker container ${docker_container}, served at ${docker_url}"
  case "$docker_data_dir" in
    /*) DATA_DIR="$docker_data_dir" ;;
    *)  DATA_DIR="$( pwd )/${docker_data_dir#./}" ;;
  esac
  echo "  database ${DATA_DIR}/app.db on the host (docker.data_dir)"
  echo ""
  if ! docker exec "$docker_container" /app/server manage reissue-login -user-id "$USER_ID"; then
    echo "" >&2
    echo "Accounts in the container: docker exec ${docker_container} /app/server manage list-users" >&2
    exit 1
  fi
  exit 0
fi

issue_link() {
  if ! "$BINARY" manage reissue-login -user-id "$USER_ID"; then
    echo "" >&2
    echo "Accounts in this database: scripts/run.sh manage list-users" >&2
    exit 1
  fi
}

if [ -n "$LOCAL_PID" ]; then
  echo "Local server (pid ${LOCAL_PID}), served at ${url}"
  echo "  database ${database}"
  echo ""
  issue_link
  exit 0
fi

if [ "$START" != "true" ]; then
  if [ ! -f "$database" ]; then
    echo "ERROR: there is no database yet at ${database}." >&2
    echo "       Start the server with scripts/run.sh -- its first start creates the owner" >&2
    echo "       and prints their login link." >&2
    exit 1
  fi
  echo "No server is running for this checkout, so the link goes straight into"
  echo "the database. It works once you start it: scripts/run.sh"
  echo "  database ${database}"
  echo ""
  issue_link
  exit 0
fi

if [ "$BACKGROUND" != "true" ]; then
  if [ -f "$database" ]; then
    echo "No server is running for this checkout, so the link goes straight into"
    echo "the database, and the server starts right here."
    echo "  database ${database}"
    echo ""
    issue_link
    echo ""
  else
    echo "No database yet: the first start below creates the owner and prints their"
    echo "login link."
    echo ""
  fi
  echo "Starting the server here; Ctrl-C stops it."
  echo ""
  exec scripts/run.sh
fi

if [ "${url#http://}" != "$url" ] && [ "$secure_cookies" = "true" ]; then
  echo "WARNING: server.secure_cookies is true but the URL is ${url}."
  echo "         The browser will drop the session cookie and this link will seem to do"
  echo "         nothing. Set it to false on line $( config_line secure_cookies ) of ${config_file}"
  echo "         for local use, or set server.public_url to the https:// address in front."
  echo ""
fi

# Without the control socket, manage cannot reach a running server and opens
# the database itself -- so the link has to go in before the server starts.
# With no database yet there is nothing to put it in; the server's first
# start creates the owner and prints their link into the log instead.
if [ "$control_socket" != "true" ] && [ -f "$database" ]; then
  echo "server.control_socket is off, so the link goes into the database before the"
  echo "server starts."
  echo ""
  issue_link
  echo ""
fi

echo "No server was running for this checkout; starting one in the background..."
start_in_background
echo "Local server (pid ${BACKGROUND_PID}), served at ${url}"
echo "  database ${database}"
echo "  log      ${LOG_FILE}"
echo "  stop it  scripts/run.sh stop"
echo ""
if [ "$control_socket" = "true" ]; then
  issue_link
elif grep -q "ONE-TIME LOGIN LINK" "$LOG_FILE"; then
  # The first start's link for the owner, as the server printed it.
  grep -B1 -A9 "ONE-TIME LOGIN LINK" "$LOG_FILE"
fi
