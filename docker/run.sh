#!/usr/bin/env bash
# Build (via docker/lib.sh) and run the container.
#
# There is deliberately no docker-compose here. This app is one container, so
# compose would add a second configuration format that hides the same flags
# behind YAML keys you have to look up. A single `docker run` you can read top
# to bottom is easier to audit, and every hardening choice below is visible on
# the line where it takes effect.
#
# Every value below comes from config/config.yaml: the docker: section for how the
# container runs, and server.port for the container side of the published
# port. Nothing is read from the environment and nothing is passed in with -e
# -- the container reads the same config.yaml, mounted writable so the owner's
# Settings screen can save it, and the key in config/secret.key, mounted
# read-only.
set -euo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )/.."

source docker/lib.sh
build_image

# First run on this checkout: config.yaml is gitignored, so a fresh clone has
# none. Write one and stop rather than starting on defaults nobody has looked
# at -- secure_cookies and trust_proxy both depend on what sits in front of
# this, and only the operator knows that.
if [ ! -f "$CONFIG_FILE" ]; then
  create_config
  cat <<NOTE

Wrote ${CONFIG_FILE}
and ${SECRET_FILE} (both mode 0600; secret.key holds a new key).
config.yaml configures the server, the container, and the portable build.
Review it before the first start, in particular:

  server.secure_cookies   true behind HTTPS; false only for plain http://localhost
  server.trust_proxy      true once a reverse proxy you control is in front,
  server.trusted_proxies  with the address it connects from (see config.yaml)
  docker.bind_address     127.0.0.1 keeps it reachable only from this host
  docker.host_port        the port published there

It will be served at ${docker_url}
(from ${docker_url_source}).

Then run docker/run.sh again. Back config/secret.key up: it is the only thing
that can read the database. Most settings can be changed later from the
owner's Settings screen while the container runs.

NOTE
  exit 0
fi

# A config.yaml from before secret.key existed has the key inside it. Move it
# out on the host, where config/ is writable, before the container -- which
# never writes there -- needs it. Silent when there is nothing to do.
migrate_config

# docker.data_dir is relative to the project directory, like every docker:
# path. It is mounted at /app/data and holds the database and app storage. The
# control socket is not here: it is on the container's tmpfs, because a
# directory shared from the host may be unable to hold one. secret.key is mounted separately and stays outside it, so
# a leaked backup of the data directory alone cannot be decrypted.
resolve_data_dir

# config.yaml is writable from inside the container, so treat docker.data_dir
# as something a compromised container could have chosen: this script hands
# that directory to the container's user (chown -R below). The Settings screen
# refuses to change docker.* from inside the container, but the file itself
# could be written. So: never the root or a home directory, and only a
# directory that is new, empty, or already this app's (it has app.db, or the
# marker this script leaves).
DATA_MARKER=".ipb-data"
case "$DATA_DIR" in
  ""|"/"|"$HOME"|"$( dirname "$HOME" )")
    echo "ERROR: docker.data_dir is ${DATA_DIR:-/}, which would hand that whole directory to" >&2
    echo "       the container. Point it at a directory of its own, e.g. ./data." >&2
    exit 1
    ;;
esac
if [ -d "$DATA_DIR" ] && [ -n "$( ls -A "$DATA_DIR" 2>/dev/null )" ] \
   && [ ! -e "${DATA_DIR}/${DATA_MARKER}" ] && [ ! -e "${DATA_DIR}/app.db" ]; then
  echo "ERROR: docker.data_dir is ${DATA_DIR}, which is not empty and does not look" >&2
  echo "       like this app's data (no app.db, no ${DATA_MARKER})." >&2
  echo "       This script would hand it to the container's user. If it really is" >&2
  echo "       meant for this app, run: touch \"${DATA_DIR}/${DATA_MARKER}\"" >&2
  exit 1
fi
mkdir -p "$DATA_DIR"

# docker: settings changed since the last start are worth a line: they are
# what decides what this script mounts and publishes.
DOCKER_LAST=".run/docker.last"
if [ -f "$DOCKER_LAST" ] && [ "$( cat "$DOCKER_LAST" )" != "$DOCKER_SETTINGS" ]; then
  echo "docker: settings changed since the last run (config/config.yaml):"
  diff <( cat "$DOCKER_LAST" ) <( printf '%s\n' "$DOCKER_SETTINGS" ) | sed -n 's/^< /  was  /p; s/^> /  now  /p'
  echo ""
fi

# secret.key: written with config.yaml on a first run. A config.yaml copied
# from config.example.yaml comes without one -- fine for a fresh install, not
# for a database a new key cannot read.
if [ ! -f "$SECRET_FILE" ]; then
  if [ -f "${DATA_DIR}/app.db" ]; then
    echo "ERROR: ${SECRET_FILE} is missing, and ${DATA_DIR}/app.db exists." >&2
    echo "       Restore secret.key from your backup: a new key cannot read the database." >&2
    exit 1
  fi
  create_secret
  echo "Wrote ${SECRET_FILE} (mode 0600, a new key -- back it up with ${DATA_DIR})."
fi

# The container's unprivileged user. Its uid is read back from the image rather
# than hardcoded here, so this keeps working if the Dockerfile ever changes it.
APP_UID="$( docker run --rm --entrypoint sh "$IMAGE_ID" -c 'id -u app' )"
APP_GID="$( docker run --rm --entrypoint sh "$IMAGE_ID" -c 'id -g app' )"

# Make sure Docker can see this project at all.
#
# Docker Desktop, colima, and friends run the daemon in a VM that shares only
# some host paths with it (colima: your home directory). Mount a path outside
# those and Docker quietly mounts an empty directory from inside the VM
# instead: config.yaml shows up as a directory, and the database would land in
# the VM where no backup of this host will ever find it. Checking that the
# file arrives as a file catches that before anything starts.
if ! docker run --rm -v "${CONFIG_FILE}:/config.yaml:ro" -v "${SECRET_FILE}:/secret.key:ro" \
     --entrypoint sh "$IMAGE_ID" -c 'test -f /config.yaml && test -f /secret.key' >/dev/null 2>&1; then
  echo "" >&2
  echo "ERROR: Docker cannot see ${CONFIG_FILE} and ${SECRET_FILE}" >&2
  echo "" >&2
  echo "       The project is probably outside the paths your Docker VM shares" >&2
  echo "       with this host (colima shares your home directory; Docker Desktop:" >&2
  echo "       Settings > Resources > File sharing). Move the project under a" >&2
  echo "       shared path, or share this one, and re-run." >&2
  echo "" >&2
  exit 1
fi

# Make sure that user can read secret.key, and read and write config.yaml.
#
# Both are 0600 and owned by you, which the container user cannot touch on
# Linux. Giving the image's group access -- read on secret.key (0640), read
# and write on config.yaml (0660, so the Settings screen can save it) --
# rather than handing the files over keeps you their owner, so you can go on
# editing them. The image's uid/gid are fixed at 10001 so that group is very
# unlikely to belong to a real account on the host.
#
# Best effort, because the right answer differs by platform: Docker Desktop's
# file sharing usually ignores guest ownership, so every uid can already use
# them, while colima's sshfs mounts enforce the host's modes and root in the
# container cannot change them -- there, the fix is the sudo line printed
# below. So the result is tested rather than trusted.
docker run --rm --user 0:0 -v "${CONFIG_FILE}:/config.yaml" -v "${SECRET_FILE}:/secret.key" \
  --entrypoint sh "$IMAGE_ID" -c "chgrp ${APP_GID} /config.yaml /secret.key && chmod 660 /config.yaml && chmod 640 /secret.key" >/dev/null 2>&1 || true

if ! docker run --rm --user "${APP_UID}:${APP_GID}" -v "${CONFIG_FILE}:/config.yaml:ro" -v "${SECRET_FILE}:/secret.key:ro" \
     --entrypoint sh "$IMAGE_ID" -c 'test -r /config.yaml && test -r /secret.key' >/dev/null 2>&1; then
  echo "" >&2
  echo "ERROR: the container runs as uid ${APP_UID}, which cannot read" >&2
  echo "       ${CONFIG_FILE} and ${SECRET_FILE}" >&2
  echo "" >&2
  echo "       Grant its group access on the host and re-run:" >&2
  echo "         sudo chgrp ${APP_GID} \"${CONFIG_FILE}\" \"${SECRET_FILE}\"" >&2
  echo "         chmod 660 \"${CONFIG_FILE}\" && chmod 640 \"${SECRET_FILE}\"" >&2
  echo "" >&2
  exit 1
fi

# Writing config.yaml is optional: without it the Settings screen is
# read-only and settings change only by editing the file on the host. The
# probe opens it for writing without writing anything.
if ! docker run --rm --user "${APP_UID}:${APP_GID}" -v "${CONFIG_FILE}:/config.yaml" \
     --entrypoint sh "$IMAGE_ID" -c ': >> /config.yaml' >/dev/null 2>&1; then
  echo "Note: the container cannot write ${CONFIG_FILE}, so the Settings screen"
  echo "      will be read-only. To allow it: sudo chgrp ${APP_GID} \"${CONFIG_FILE}\" && chmod 660 \"${CONFIG_FILE}\""
  echo ""
fi

# Make sure the same user can write the data directory.
#
# A bind mount ignores the image's own ownership: /app/data is chowned to "app"
# at build time, but mounting a host directory over it replaces that with
# whatever the host says. Get this wrong and the container starts, fails to
# create app.db, and crash-loops on "permission denied" -- a slow thing to
# diagnose from the outside, so it is worth settling here.
touch "${DATA_DIR}/${DATA_MARKER}"
docker run --rm --user 0:0 -v "${DATA_DIR}:/data" \
  --entrypoint sh "$IMAGE_ID" -c "chown -R ${APP_UID}:${APP_GID} /data" >/dev/null 2>&1 || true

if ! docker run --rm --user "${APP_UID}:${APP_GID}" -v "${DATA_DIR}:/data" \
     --entrypoint sh "$IMAGE_ID" -c 'touch /data/.probe' >/dev/null 2>&1; then
  echo "" >&2
  echo "ERROR: the container runs as uid ${APP_UID}, which cannot write to" >&2
  echo "       ${DATA_DIR}" >&2
  echo "" >&2
  echo "       Without this the container will crash-loop on 'permission denied'." >&2
  echo "       Grant it on the host and re-run:" >&2
  echo "         sudo chown -R ${APP_UID}:${APP_GID} \"${DATA_DIR}\"" >&2
  echo "" >&2
  exit 1
fi

# The probe the container just wrote must be visible here. If it is not, the
# data directory is outside the paths the Docker VM shares (see above), and
# the database would be written somewhere this host cannot back up.
DATA_SHARED=false
[ -f "${DATA_DIR}/.probe" ] && DATA_SHARED=true
docker run --rm --user "${APP_UID}:${APP_GID}" -v "${DATA_DIR}:/data" \
  --entrypoint sh "$IMAGE_ID" -c 'rm -f /data/.probe' >/dev/null 2>&1 || true
if [ "$DATA_SHARED" != "true" ]; then
  echo "" >&2
  echo "ERROR: Docker cannot see ${DATA_DIR}" >&2
  echo "" >&2
  echo "       A file written there from inside the container did not appear on" >&2
  echo "       this host, so the directory is outside the paths your Docker VM" >&2
  echo "       shares. Point docker.data_dir under a shared path and re-run." >&2
  echo "" >&2
  exit 1
fi

EXISTING="$( docker ps -a --filter "name=^${docker_container}\$" --format '{{.Status}}' )"
if [ -n "$EXISTING" ]; then
  echo "Replacing the existing ${docker_container} container (${EXISTING})..."
  docker rm -f "$docker_container" >/dev/null
fi

# With our own container gone, anything still on the host port is something
# else, and docker run would fail with a bind error after creating the
# container. Name it instead.
if command -v lsof >/dev/null 2>&1; then
  # lsof exits 1 when nothing is listening -- the usual case -- and under
  # pipefail that failure would end this script silently, before it starts
  # the container. An empty answer is the one we want, so swallow it.
  PORT_PID="$( lsof -nP -iTCP:"$docker_host_port" -sTCP:LISTEN -t 2>/dev/null | head -n 1 || true )"
  if [ -n "$PORT_PID" ]; then
    PORT_OWNER="$( ps -p "$PORT_PID" -o command= 2>/dev/null | awk '{ n = split( $1 , part , "/" ); $1 = part[ n ]; print }' | cut -c1-100 )"
    OTHER_CONTAINER="$( docker ps --filter "publish=${docker_host_port}" --format '{{.Names}}' | head -n 1 )"
    echo "" >&2
    echo "ERROR: host port ${docker_host_port} (docker.host_port) is already in use by" >&2
    echo "       ${OTHER_CONTAINER:+container ${OTHER_CONTAINER}, via }${PORT_OWNER:-unknown} (pid ${PORT_PID})." >&2
    echo "" >&2
    echo "       If that is scripts/run.sh serving this checkout locally, stop it first." >&2
    echo "       Otherwise pick a free docker.host_port in ${CONFIG_FILE}." >&2
    exit 1
  fi
fi

echo "Starting ${docker_container} on ${docker_bind_address}:${docker_host_port}..."
docker run -d \
  --name "$docker_container" \
  --restart "$docker_restart" \
  --stop-timeout 20 \
  -p "$docker_publish" \
  -v "${DATA_DIR}:/app/data" \
  -v "${CONFIG_FILE}:${CONTAINER_CONFIG}" \
  -v "${SECRET_FILE}:${CONTAINER_SECRET}:ro" \
  --read-only \
  --tmpfs "/tmp:rw,noexec,nosuid,size=${docker_tmpfs_size}" \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit "$docker_pids_limit" \
  --memory "$docker_memory" \
  --cpus "$docker_cpus" \
  "${docker_image}:latest"

# Running is not the same as working. Wait for the image's own HEALTHCHECK
# (/app/server health) to pass, and if the container dies or turns unhealthy,
# show why instead of announcing success.
echo "Waiting for it to answer (up to 30 seconds)..."
STATUS="starting"
for _ in $( seq 1 60 ); do
  sleep 0.5
  STATE="$( docker inspect -f '{{.State.Status}}' "$docker_container" 2>/dev/null || echo "gone" )"
  if [ "$STATE" != "running" ]; then
    STATUS="$STATE"
    break
  fi
  if docker exec "$docker_container" /app/server health >/dev/null 2>&1; then
    STATUS="healthy"
    break
  fi
done

if [ "$STATUS" != "healthy" ]; then
  echo "" >&2
  if [ "$STATUS" = "starting" ]; then
    echo "ERROR: ${docker_container} is running but not answering after 30 seconds." >&2
  else
    echo "ERROR: ${docker_container} stopped (status: ${STATUS}, exit code $( docker inspect -f '{{.State.ExitCode}}' "$docker_container" 2>/dev/null || echo "?" ))." >&2
  fi
  echo "       Its last log lines:" >&2
  echo "" >&2
  docker logs --tail 40 "$docker_container" 2>&1 | sed 's/^/         /' >&2
  exit 1
fi

mkdir -p .run
printf '%s\n' "$DOCKER_SETTINGS" > "$DOCKER_LAST"

cat <<NOTE

Ready: ${docker_url}
       (from ${docker_url_source})

Three things on the host make up this deployment:

  ${CONFIG_FILE}
      every setting (mounted writable at ${CONTAINER_CONFIG}; the owner's
      Settings screen saves it in place, keeping the previous version in
      ${DATA_DIR}/config.yaml.bak)
  ${SECRET_FILE}
      the key that encrypts the database (mounted read-only)
  ${DATA_DIR}/
      app.db and storage/ (mounted at /app/data)

Back them up: docker exec ${docker_container} /app/server manage backup
writes one file to ${DATA_DIR}/backups while the server runs, and
docker/restore.sh puts one back. secret.key is not in it, so keep a copy of
that apart from your backups -- the database is useless without it.

Editing config.yaml on the host: most settings apply within seconds. Use an
editor that saves in place (vi, nano, VS Code do); one that writes a new file
and renames it over the old leaves the container looking at the old file --
the Settings screen says so, and restarting the container picks it up.

What the flags above are doing:

  -p ${docker_publish}
                     docker.bind_address:docker.host_port:server.port. This
                     app does NOT terminate TLS -- put nginx/Caddy/Traefik in
                     front and let it hold the certificate.
  --read-only        The container cannot write to its own filesystem. Only
                     the data directory and the tmpfs are writable.
  --cap-drop ALL     No Linux capabilities at all.
  --no-new-privileges  A process in here can never gain more rights than it
                     started with, even via a setuid binary.
  (non-root)         Runs as the image's unprivileged "app" user.
  --pids-limit/--memory/--cpus  Blast radius limits (docker.pids_limit,
                     docker.memory, docker.cpus). Raise them deliberately for
                     real load rather than finding out under traffic.

NOTE

if [ "$server_secure_cookies" = "true" ] && [ "${docker_url#http://}" != "$docker_url" ]; then
  echo "WARNING: server.secure_cookies is true but the address is ${docker_url}."
  echo "         Over plain http the browser drops the session cookie and signing in"
  echo "         silently does nothing. Put HTTPS in front and set server.public_url,"
  echo "         or set secure_cookies: false for local use only."
  echo ""
elif [ "$server_secure_cookies" = "false" ]; then
  echo "Note: server.secure_cookies is false. Right for plain http://localhost; wrong"
  echo "      behind an HTTPS proxy, where it should be true."
  echo ""
fi
if [ "$server_trust_proxy" = "false" ]; then
  echo "Note: server.trust_proxy is false. Once a reverse proxy is in front, set it"
  echo "      true and list the proxy's address in server.trusted_proxies, or the"
  echo "      rate limiter sees every client as the proxy."
  echo ""
fi

# A fresh database makes the server create the owner and print their login
# link to its log. Show it here rather than sending someone to dig for it.
FIRST_LINK="$( docker logs "$docker_container" 2>&1 | grep -A 12 "ONE-TIME LOGIN LINK -- first-run" || true )"
if [ -n "$FIRST_LINK" ]; then
  echo "This is a fresh database. The owner's one-time login link:"
  echo ""
  echo "$FIRST_LINK"
  echo ""
else
  echo "Existing database (${DATA_DIR}/app.db)."
fi

cat <<NOTE
A new login link for the owner any time, from this checkout:

  scripts/login.sh --docker

Day to day, mint further logins from the admin panel in the running app. The
CLI works against the running container over the control socket inside it:

  docker exec -it ${docker_container} /app/server manage list-users

If the container is stopped, run a one-off with the same two mounts:

  docker run --rm -v "${DATA_DIR}:/app/data" \\
    -v "${CONFIG_FILE}:${CONTAINER_CONFIG}:ro" \\
    -v "${SECRET_FILE}:${CONTAINER_SECRET}:ro" \\
    ${docker_image}:latest manage reissue-login -user-id 1

NOTE
