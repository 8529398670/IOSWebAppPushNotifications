#!/usr/bin/env bash
# Build and run the server from this checkout, outside Docker.
#
#   scripts/run.sh                    rebuild if anything changed, stop the
#                                     copy this checkout started last, start
#                                     a fresh one here
#   scripts/run.sh stop               stop the copy this checkout started
#                                     (in this terminal, another, or the
#                                     background one login.sh --background
#                                     starts)
#   scripts/run.sh manage <command>   run an admin command against it
#   scripts/run.sh <anything else>    same: passed straight to the binary
#
# The server runs in the foreground: its log streams here and Ctrl-C stops it.
# Running scripts/run.sh again from another terminal stops this one and takes
# over, so "edit, scripts/run.sh, reload the page" is the whole loop.
#
# With arguments it is a one-off instead -- the same build, then the binary
# with those arguments -- and the running server is left alone. That is what
# makes the admin CLI usable while it is up: `manage` talks to the live server
# over its control socket rather than opening the database itself.
#
#   scripts/login.sh                                    owner's login link
#   scripts/run.sh manage list-users
#   scripts/run.sh manage create-login -name "Grace" -role user
#   scripts/run.sh manage create-invite -user-id 1 -label "Book club"
#   scripts/run.sh manage create-key -user-id 1 -name "CI"
#   scripts/run.sh manage paths                         where the state lives
#   scripts/run.sh config check
#   scripts/run.sh config shell server                  every resolved value
#   scripts/run.sh version
#
# This is for development and internal boxes. It is a plain process with your
# permissions -- none of docker/run.sh's read-only filesystem, dropped
# capabilities, or pid and memory limits apply -- so use Docker for anything
# long-lived or internet-facing.
set -euo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )/.."


source scripts/lib.sh

if [ "${1:-}" = "stop" ] && [ $# -eq 1 ]; then
  if [ -z "$( our_server_pid )" ]; then
    echo "No server started by this checkout is running."
  else
    stop_our_server
    echo "Stopped."
  fi
  exit 0
fi

# This happens before anything is stopped, so a build error leaves the server
# that was already running untouched.
build_binary

if [ $# -gt 0 ]; then
  exec "$BINARY" "$@"
fi

# A config.yaml from before secret.key existed has the key inside it. Move it
# out now, before anything starts, so the terminal says so. Silent otherwise.
"$BINARY" config migrate -file ./config/config.yaml

read_server_config

# First run on this checkout: config/config.yaml is gitignored, so a fresh
# clone has none. Without one here the binary would quietly create
# ~/.config/ipb/config.yaml instead, which is the right thing for
# a portable binary and the wrong one for a checkout. Write it here and stop,
# like docker/run.sh, so it gets looked at before the first start.
if [ "$config_exists" != "true" ]; then
  "$BINARY" config init -file ./config/config.yaml >/dev/null
  read_server_config
  echo "First run: wrote ${config_file}"
  echo "  and ${secret_file}"
  echo "  (both mode 0600; secret.key holds a new key -- back it up with the"
  echo "  database, it is the only thing that can read it)."
  echo ""
  echo "It will serve ${url}"
  echo "  (from ${url_source})."
  if [ "${url#http://}" != "$url" ] && [ "$secure_cookies" = "true" ]; then
    echo ""
    echo "server.secure_cookies is true. That is right behind HTTPS, but at ${url}"
    echo "the browser drops a Secure cookie and signing in silently does nothing."
    echo "For local use, change line $( config_line secure_cookies ) of ${config_file}:"
    echo ""
    echo "    secure_cookies: true   ->   secure_cookies: false"
  fi
  echo ""
  echo "Most settings can be changed later while the server runs, from the owner's"
  echo "Settings screen or by editing config.yaml. Then run scripts/run.sh again."
  exit 0
fi

# A config.yaml copied from config.example.yaml comes without a key. The
# server writes one on its first start, but only while there is no database
# -- a new key cannot read an old one.
if [ "$secret_exists" != "true" ] && [ "$database_exists" = "true" ]; then
  echo "ERROR: ${secret_file} is missing, and ${database} exists." >&2
  echo "       Restore secret.key from your backup: a new key cannot read the database." >&2
  exit 1
fi

# Stop the copy this checkout started last.
stop_our_server

# Anything still on the port is not ours, and the server would only die on
# "address already in use" after printing a banner that says it started.
OWNER="$( port_owner "$port" )"
if [ -n "$OWNER" ] || server_answers; then
  echo "ERROR: port ${port} (server.port) is already in use${OWNER:+ by ${OWNER}}." >&2
  echo "" >&2
  echo "       It is not the server this checkout started. Stop it, or change line" >&2
  echo "       $( config_line port ) of ${config_file} to a free port, then re-run." >&2
  read_docker_config
  if container_running "$docker_container" && [ "$docker_host_port" = "$port" ]; then
    echo "" >&2
    echo "       The ${docker_container} docker container publishes port ${docker_host_port} --" >&2
    echo "       that is probably it (docker stop ${docker_container})." >&2
  fi
  exit 1
fi

if [ "${url#http://}" != "$url" ] && [ "$secure_cookies" = "true" ]; then
  echo "WARNING: server.secure_cookies is true but the URL is ${url}."
  echo "         The browser will drop the session cookie and signing in will silently"
  echo "         do nothing. Set it to false on line $( config_line secure_cookies ) of ${config_file}"
  echo "         for local use, or set server.public_url to the https:// address in front."
  echo ""
fi

if [ "$database_exists" = "true" ]; then
  DB_NOTE="existing"
else
  DB_NOTE="new -- the owner's first login link is printed below"
fi
if [ "$static_on_disk" = "true" ]; then
  STATIC_NOTE="${static_dir}  (from disk: frontend edits need only a reload)"
else
  STATIC_NOTE="embedded copy  (no directory at ${static_dir})"
fi
if [ "$language_on_disk" = "true" ]; then
  LANGUAGE_NOTE="${language_file}  (from disk)"
else
  LANGUAGE_NOTE="embedded copy  (no file at ${language_file})"
fi
if [ "$control_socket" = "true" ]; then
  CONTROL_NOTE="${control_socket_path}  (manage works while it runs)"
else
  CONTROL_NOTE="off (server.control_socket: false) -- manage needs the server stopped"
fi

cat <<NOTE
Starting ipb ${VERSION} (commit ${COMMIT})
  url       ${url}
            from ${url_source}
  config    ${config_file}  (edits apply while it runs)
  secret    ${secret_file}
  app dir   ${app_dir}
  database  ${database}  (${DB_NOTE})
  static    ${STATIC_NOTE}
  language  ${LANGUAGE_NOTE}
  control   ${CONTROL_NOTE}

A login link for the owner any time: scripts/login.sh (from another terminal).

NOTE

mkdir -p "$RUN_DIR"

# Say when it is actually answering, not just launched. This runs beside the
# server and outlives the exec below; it gives up after 20 seconds.
(
  for _ in $( seq 1 80 ); do
    sleep 0.25
    if server_answers; then
      echo ""
      echo "Ready: ${url}"
      echo ""
      exit 0
    fi
  done
  echo ""
  echo "Not answering on port ${port} after 20 seconds -- see the log above."
) &

# exec keeps this shell's pid, so the one written here is the server's.
echo $$ > "$PID_FILE"
exec "$BINARY"
