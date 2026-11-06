#!/usr/bin/env bash
# Put a backup back into this deployment.
#
#   docker/restore.sh path/to/backup.tar.gz [path/to/old-secret.key]
#
# The second argument is the key the backup was made with, for one made before
# a key rotation (config/secret.key.retired-<date>).
#
# It stops the container, restores in a throwaway container with the same data
# mounted, and starts it again. Everything that can fail happens before the
# data is touched (see restore in server/backup/backup.go): a backup the current key cannot
# read is refused, and what is replaced stays in the data directory as
# app.db.before-restore-<time>.
#
# The backup goes in over stdin rather than as a mount. The file is usually
# 0600 and owned by you, or by the container's uid if it came from the data
# directory, and stdin works the same either way: this shell reads it, and the
# container writes it.
set -euo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )/.."

BACKUP="${1:-}"
OLD_KEY="${2:-}"
if [ -z "$BACKUP" ] || [ ! -f "$BACKUP" ]; then
  echo "usage: docker/restore.sh path/to/backup.tar.gz [path/to/old-secret.key]" >&2
  exit 1
fi
if [ -n "$OLD_KEY" ] && [ ! -f "$OLD_KEY" ]; then
  echo "ERROR: ${OLD_KEY} is not a file." >&2
  exit 1
fi

source docker/lib.sh
build_image
resolve_data_dir

if [ "$( docker ps -q --filter "name=^${docker_container}\$" )" != "" ]; then
  WAS_RUNNING=true
  echo "Stopping ${docker_container}..."
  docker stop "$docker_container" >/dev/null
else
  WAS_RUNNING=false
fi

# The first line of stdin is the old key, or empty; the rest is the backup.
# `read` takes one line and no more, so `cat` gets the backup from its first
# byte. The key stays in this container's tmpfs and goes when it does.
INCOMING="/app/data/.restore-incoming.tar.gz"
RESTORED=true
{ if [ -n "$OLD_KEY" ]; then head -n 1 "$OLD_KEY"; else echo; fi; cat "$BACKUP"; } | \
  docker run --rm -i --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --tmpfs "/tmp:rw,noexec,nosuid,size=1m" \
    -v "${DATA_DIR}:/app/data" \
    -v "${CONFIG_FILE}:${CONTAINER_CONFIG}:ro" \
    -v "${SECRET_FILE}:${CONTAINER_SECRET}:ro" \
    --entrypoint sh "$IMAGE_ID" -c '
      IFS= read -r old_key
      cat > '"$INCOMING"'
      set -- /app/server manage restore -from '"$INCOMING"' -yes
      if [ -n "$old_key" ]; then
        printf "%s\n" "$old_key" > /tmp/old.key
        set -- "$@" -key-file /tmp/old.key
      fi
      "$@"
      status=$?
      rm -f '"$INCOMING"'
      exit $status
    ' || RESTORED=false

if [ "$WAS_RUNNING" = "true" ]; then
  echo "Starting ${docker_container}..."
  docker start "$docker_container" >/dev/null
fi

if [ "$RESTORED" != "true" ]; then
  echo "" >&2
  echo "ERROR: nothing was restored (see above)." >&2
  exit 1
fi
