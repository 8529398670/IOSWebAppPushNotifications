#!/usr/bin/env bash
# Move this deployment to a new secret key.
#
#   docker/rotate-key.sh --yes
#
# The container cannot do this alone: secret.key is mounted read-only, and
# config/ belongs to the host. So the work is split, around the same marker
# file everything else uses (see server/rotate/rotate.go):
#
#   here           writes the new key to config/secret.key.next
#   a container    moves the data onto it, with the app stopped
#   here           retires secret.key, puts the new key in its place, and
#                  clears the marker
#
# Stopped at any point, running it again finishes the same rotation. Until
# then the server refuses to start, rather than start on a key that does not
# match the data.
set -euo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )/.."

if [ "${1:-}" != "--yes" ]; then
  echo "usage: docker/rotate-key.sh --yes" >&2
  echo "" >&2
  echo "Stops the container, re-encrypts the database, two-factor secrets and the" >&2
  echo "activity log with a new key, and starts it again. Everyone has to sign in" >&2
  echo "again. The old key is kept: backups made before now still need it." >&2
  exit 1
fi

source docker/lib.sh
build_image
resolve_data_dir
NEXT_FILE="${SECRET_FILE}.next"

# in_data runs a shell command with the data directory mounted, as the image's
# own user, who owns it. Nothing else here can touch it on a Linux host.
in_data() {
  docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true \
    -v "${DATA_DIR}:/data" --entrypoint sh "$IMAGE_ID" -c "$1"
}

WAS_RUNNING=false
if [ "$( docker ps -q --filter "name=^${docker_container}\$" )" != "" ]; then
  WAS_RUNNING=true
  echo "Stopping ${docker_container}..."
  docker stop "$docker_container" >/dev/null
fi

PENDING="$( in_data 'test -e /data/.rotate/pending && echo yes || echo no' )"

# No new key and no marker: a fresh rotation. A new key with no marker is left
# from one that never got as far as deciding, and is as good as any.
if [ ! -f "$NEXT_FILE" ] && [ "$PENDING" = "no" ]; then
  config_dir_run secret --file /work/secret.key.next >/dev/null
fi

if [ -f "$NEXT_FILE" ]; then
  # The key goes in over stdin and stays in this container's tmpfs: the same
  # file mode problems as a backup in docker/restore.sh, and no copy of it
  # ever sits in the data directory.
  if ! cat "$NEXT_FILE" | docker run --rm -i --network none --read-only --cap-drop ALL \
         --security-opt no-new-privileges:true \
         --tmpfs "/tmp:rw,noexec,nosuid,size=1m" \
         -v "${DATA_DIR}:/app/data" \
         -v "${CONFIG_FILE}:${CONTAINER_CONFIG}:ro" \
         -v "${SECRET_FILE}:${CONTAINER_SECRET}:ro" \
         --entrypoint sh "$IMAGE_ID" -c '
           umask 077
           cat > /tmp/next.key
           exec /app/server manage rotate-key -yes -new-key-file /tmp/next.key
         '; then
    PENDING="$( in_data 'test -e /data/.rotate/pending && echo yes || echo no' )"
    echo "" >&2
    if [ "$PENDING" = "yes" ]; then
      echo "ERROR: the rotation stopped part way. Run docker/rotate-key.sh --yes again to finish it." >&2
    else
      echo "ERROR: nothing was changed (see above)." >&2
      rm -f "$NEXT_FILE"
      if [ "$WAS_RUNNING" = "true" ]; then docker start "$docker_container" >/dev/null; fi
    fi
    exit 1
  fi

  # A new file takes secret.key's owner, group and mode from the old one, which
  # is what lets the container's user go on reading it. It is built beside it
  # and renamed in, so a stop here cannot leave half a key. If the key is
  # already in place, this is a second run finishing the job.
  if ! cmp -s "$NEXT_FILE" "$SECRET_FILE"; then
    RETIRED="${SECRET_FILE}.retired-$( date -u +%Y%m%d-%H%M%S )"
    cp -p "$SECRET_FILE" "$RETIRED"
    chmod 600 "$RETIRED"
    cp -p "$SECRET_FILE" "${SECRET_FILE}.swap"
    cat "$NEXT_FILE" > "${SECRET_FILE}.swap"
    mv "${SECRET_FILE}.swap" "$SECRET_FILE"
    echo "The old key is kept at ${RETIRED}"
    echo "Backups made before now still need it: docker/restore.sh takes it as a second"
    echo "argument. Delete it once those backups no longer matter."
  fi
  rm -f "$NEXT_FILE"
fi

in_data 'rm -rf /data/.rotate'
echo "The new key is in ${SECRET_FILE}: back it up. Everyone has to sign in again."

if [ "$WAS_RUNNING" = "true" ]; then
  # run.sh, not docker start: it sets the new file up for the container.
  exec docker/run.sh
fi
echo "${docker_container} was not running, so it has been left stopped."
