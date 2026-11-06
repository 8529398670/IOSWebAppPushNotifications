# Shared by docker/build.sh and docker/run.sh. Sourced, not run, from the
# project root -- which is also the build context.
#
# build_image builds the image and then reads config.yaml *through it*: the
# binary inside is the YAML parser, so these scripts get exactly the defaults
# and validation the server uses, and the host needs nothing but Docker. That
# ordering is also why the image name -- which lives in config.yaml like
# everything else -- is applied as a tag after the build rather than passed to
# it.
#
# Afterwards these are set: IMAGE_ID, CONFIG_FILE, SECRET_FILE, VERSION,
# DOCKER_SETTINGS (the assignments below, as text), and every docker_* /
# server_* value printed by `config shell docker` (see
# server/config/command.go for the list), including docker_url.

CONFIG_FILE="$( pwd )/config/config.yaml"
SECRET_FILE="$( pwd )/config/secret.key"
DOCKERFILE="docker/Dockerfile"

# The container sees them here (server/config/layout_container.go): config.yaml
# writable, so the owner's Settings screen can save it; secret.key read-only.
CONTAINER_CONFIG="/app/config/config.yaml"
CONTAINER_SECRET="/app/config/secret.key"

# config_dir_run runs the binary with the project's config/ folder mounted at
# /work, as the invoking user: for the commands that create or rewrite files
# there (init, secret, migrate). Mounting the folder rather than single files
# is what lets them create a file, and replace config.yaml by renaming a new
# copy over it, so a failure half way leaves the old file whole.
config_dir_run() {
  docker run --rm --network none --read-only --cap-drop ALL \
    --user "$( id -u ):$( id -g )" \
    -v "$( dirname "$CONFIG_FILE" ):/work" \
    "$IMAGE_ID" config "$@"
}

# config_run runs the freshly built binary in a throwaway container that can do
# nothing but read config.yaml: no network, read-only, no capabilities. It runs
# as the invoking user, so a 0600 config.yaml owned by that user is readable on
# Linux as well as macOS.
#
# The file is only mounted when it exists. Mounting a missing file makes Docker
# create an empty *directory* in its place, which then breaks every later run.
config_run() {
  local mount=()
  if [ -f "$CONFIG_FILE" ]; then
    mount=( -v "${CONFIG_FILE}:${CONTAINER_CONFIG}:ro" )
  fi
  docker run --rm --network none --read-only --cap-drop ALL \
    --user "$( id -u ):$( id -g )" \
    ${mount[@]+"${mount[@]}"} \
    "$IMAGE_ID" config "$@"
}

# build_image [extra-tag]
build_image() {
  local extra_tag="${1:-}"
  local commit build_date id_file assignments

  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is not on PATH. Install Docker (or colima) and re-run." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "ERROR: docker is installed but its daemon is not answering (docker info failed)." >&2
    echo "       Start Docker Desktop, or \`colima start\`, and re-run." >&2
    exit 1
  fi

  local mounted
  for mounted in "$CONFIG_FILE" "$SECRET_FILE"; do
    if [ -d "$mounted" ]; then
      echo "ERROR: ${mounted} is a directory. Docker creates one when asked to" >&2
      echo "       mount a file that does not exist. Remove it and re-run." >&2
      exit 1
    fi
  done

  # Version metadata, stamped into the binary exactly as build.sh does, so
  # `docker exec <name> /app/server version` is as informative as a portable
  # binary's (scripts/build.sh).
  # The version is the UTC build time (2026.10.23-1412): it sorts, it says
  # when, and the commit hash is stamped separately alongside it.
  VERSION="$( date -u +%Y.%m.%d-%H%M )"
  commit="$( git rev-parse --short HEAD 2>/dev/null || echo "unknown" )"
  build_date="$( date -u +%Y-%m-%dT%H:%M:%SZ )"

  id_file="$( mktemp )"
  echo "Building the image from ${DOCKERFILE}, version ${VERSION} (commit ${commit})"
  if [ -f "$CONFIG_FILE" ]; then
    echo "  config  ${CONFIG_FILE}"
  else
    echo "  config  none yet at ${CONFIG_FILE} -- the image is named from the defaults"
  fi
  echo ""
  if ! docker build \
         --file "$DOCKERFILE" \
         --iidfile "$id_file" \
         --build-arg "VERSION=${VERSION}" \
         --build-arg "COMMIT=${commit}" \
         --build-arg "BUILD_DATE=${build_date}" \
         .; then
    rm -f "$id_file"
    echo "" >&2
    echo "ERROR: docker build failed (above). Nothing was started or replaced." >&2
    exit 1
  fi
  IMAGE_ID="$( cat "$id_file" )"
  rm -f "$id_file"

  # With no config.yaml yet this reads the defaults, which is all a CI build
  # needs to name the image. docker/run.sh creates the real file before it
  # starts anything.
  #
  # Assigned before it is eval'd so that a validation error stops the script:
  # `eval "$( failing )"` would quietly eval nothing and carry on.
  assignments="$( config_run shell docker )"
  eval "$assignments"
  DOCKER_SETTINGS="$assignments"

  docker tag "$IMAGE_ID" "${docker_image}:latest"
  if [ -n "$extra_tag" ]; then
    docker tag "$IMAGE_ID" "${docker_image}:${extra_tag}"
    echo "Also tagged ${docker_image}:${extra_tag}"
  fi
  echo "Built ${docker_image}:latest (${VERSION}, image ${IMAGE_ID#sha256:})"
}

# resolve_data_dir sets DATA_DIR. docker.data_dir is relative to the project
# directory, like every docker: path.
resolve_data_dir() {
  case "$docker_data_dir" in
    /*) DATA_DIR="$docker_data_dir" ;;
    *)  DATA_DIR="$( pwd )/${docker_data_dir#./}" ;;
  esac
  DATA_DIR="${DATA_DIR%/}"
}

# create_config writes config.yaml from the image's defaults, and a
# secret.key with a fresh key beside it unless one is there. Both are created
# as the invoking user, mode 0600, and neither ever replaces an existing file.
create_config() {
  mkdir -p "$( dirname "$CONFIG_FILE" )"
  config_dir_run init -dir /work >/dev/null
}

# create_secret writes secret.key alone: for a config.yaml copied from
# config.example.yaml.
create_secret() {
  config_dir_run secret -file /work/secret.key >/dev/null
}

# migrate_config moves server.secret_key out of a config.yaml written before
# secret.key existed. It prints only when it did something.
migrate_config() {
  config_dir_run migrate -dir /work
}
