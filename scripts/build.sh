#!/usr/bin/env bash
# Build portable, self-contained binaries -- one file per platform, each with
# the entire frontend compiled in.
#
# What you get is a single executable with no runtime dependencies at all: no
# Docker, no Go toolchain, no ./static directory, no language.yaml, no libc.
# Copy it to a machine, run it, and it serves the app. That is possible
# because of three choices working together:
#
#   CGO_ENABLED=0   static linking, so there is no libc version to match
#   go:embed        the frontend lives inside the binary (see main.go)
#   bolt            the database is one file the binary creates on first run
#
# Docker is still the better answer for a long-lived internet-facing
# deployment -- it is where the read-only filesystem, dropped capabilities,
# and restart policy come from. These binaries are for everything else:
# handing a colleague a working copy, an internal box with no container
# runtime, a Raspberry Pi, a USB stick.
#
# The binary name, the output directory, and the target list are the build:
# section of config/config.yaml. Targets given on the command line replace
# the list for one run:
#
#   scripts/build.sh                  build every target in build.targets
#   scripts/build.sh linux/amd64      build one
#   scripts/build.sh darwin/arm64 linux/arm64
set -euo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )/.."

# config.yaml is read through the app itself rather than parsed here, so this
# script gets the same defaults and validation as the server -- and Go is
# already required to build. With no config/config.yaml yet (a fresh clone),
# the defaults from config/defaults.yaml apply.
#
# Assigned before it is eval'd so that a config error stops the script:
# `eval "$( failing )"` would quietly eval nothing and carry on.
if ! BUILD_CONFIG="$( go run . config shell -file ./config/config.yaml build )"; then
  echo "ERROR: could not read the build: section of config/config.yaml (above)." >&2
  exit 1
fi
eval "$BUILD_CONFIG"
if [ -f ./config/config.yaml ]; then
  CONFIG_NOTE="$( pwd )/config/config.yaml"
else
  CONFIG_NOTE="none yet -- the defaults in config/defaults.yaml"
fi

BINARY_NAME="$build_binary_name"
OUTPUT_DIR="$build_output_dir"

if [ $# -gt 0 ]; then
  TARGETS=( "$@" )
else
  read -r -a TARGETS <<< "$build_targets"
fi

# Version metadata, stamped into the binary and readable later with
# `./ipb version`. Being able to ask a binary what it is beats
# guessing from a filename once a few copies are in circulation.
# The version is the UTC build time (2026.10.23-1412): it sorts, it says
# when, and the commit hash is stamped separately alongside it.
VERSION="$( date -u +%Y.%m.%d-%H%M )"
COMMIT="$( git rev-parse --short HEAD 2>/dev/null || echo "unknown" )"
# The commit's own timestamp rather than "now", so building the same commit
# twice produces the same bytes. Outside a git checkout there is no commit to
# anchor to, and the current time is the honest answer. (`date -r` is BSD and
# macOS; `date -d @` is GNU.)
BUILD_EPOCH="$( git log -1 --format=%ct 2>/dev/null || date +%s )"
BUILD_DATE="$( date -u -r "$BUILD_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -u -d "@$BUILD_EPOCH" +%Y-%m-%dT%H:%M:%SZ )"

# -s -w drop the symbol and DWARF tables (smaller, less detail for anyone
# poking at a deployed binary). -trimpath keeps build-machine paths out of it,
# which also makes the output reproducible across checkout locations.
LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X main.version=${VERSION}"
LDFLAGS="$LDFLAGS -X main.commit=${COMMIT}"
LDFLAGS="$LDFLAGS -X main.buildDate=${BUILD_DATE}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_ABS="$( cd "$OUTPUT_DIR" && pwd )"

echo "Building ${BINARY_NAME} ${VERSION} (${COMMIT})"
echo "  config   ${CONFIG_NOTE}"
echo "  targets  ${TARGETS[*]}$( [ $# -gt 0 ] && echo "  (from the command line)" || echo "  (build.targets)" )"
echo "  output   ${OUTPUT_ABS}/  (build.output_dir)"
echo ""

FAILED=()
for TARGET in "${TARGETS[@]}"; do
  GOOS="${TARGET%%/*}"
  GOARCH="${TARGET##*/}"

  OUTPUT="${OUTPUT_DIR}/${BINARY_NAME}_${VERSION}_${GOOS}_${GOARCH}"
  [ "$GOOS" = "windows" ] && OUTPUT="${OUTPUT}.exe"

  printf "  %-22s " "${GOOS}/${GOARCH}"
  if CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
       go build -buildvcs=false -trimpath -ldflags="$LDFLAGS" -o "$OUTPUT" . 2>/tmp/build_err_$$; then
    SIZE="$( du -h "$OUTPUT" | cut -f1 | tr -d ' ' )"
    echo "ok  ${SIZE}  ${OUTPUT}"
  else
    echo "FAILED"
    sed 's/^/      /' /tmp/build_err_$$ >&2
    FAILED+=( "$TARGET" )
  fi
  rm -f /tmp/build_err_$$
done

# Checksums, so whoever receives a binary can confirm it is the one you built.
# Handing someone an executable is a trust decision; give them a way to check.
if command -v shasum >/dev/null 2>&1; then
  ( cd "$OUTPUT_DIR" && shasum -a 256 "${BINARY_NAME}"_* > SHA256SUMS 2>/dev/null ) || true
elif command -v sha256sum >/dev/null 2>&1; then
  ( cd "$OUTPUT_DIR" && sha256sum "${BINARY_NAME}"_* > SHA256SUMS 2>/dev/null ) || true
fi

echo ""
if [ ${#FAILED[@]} -gt 0 ]; then
  echo "Failed: ${FAILED[*]}" >&2
  exit 1
fi

cat <<NOTE
Done. ${OUTPUT_DIR}/ holds one self-contained binary per platform, plus
SHA256SUMS.

To run one:

  ./${OUTPUT_DIR}/${BINARY_NAME}_${VERSION}_\$(go env GOOS)_\$(go env GOARCH)

That is the whole command. No files need to sit beside it -- the frontend is
compiled in. Its one config file is ./config/config.yaml if there is one under
the directory it is started from, else ~/.config/ipb/config.yaml,
which it creates on first run along with the rest of its state:

  ~/.config/ipb/
    config.yaml     every setting; the owner can change most of them from
                    the Settings screen while it runs (mode 0600)
    secret.key      the key that encrypts the database (mode 0600)
    app.db          the database
    storage/        application files

server.app_dir in that config.yaml moves the state somewhere else. Ask a
built binary where it is looking with:

  ./${BINARY_NAME} manage paths

Two things to pass on with any binary you hand someone:

  * Back up secret.key together with app.db. It is the key that encrypts the
    database, so app.db without it is unreadable -- and either one alone is
    useless. config.yaml holds no secret.
  * server.secure_cookies must be true anywhere real, behind an HTTPS proxy.
    It defaults to true; set it false only for local http://localhost, or the
    browser will drop the session cookie and login will look like it silently
    does nothing.

The binary is also the admin CLI:

  ./${BINARY_NAME} manage list-users
  ./${BINARY_NAME} manage reissue-login -user-id 1
  ./${BINARY_NAME} version

If a static/ directory sits in the project directory (the folder holding
config/), or a language.yaml in the app directory, those are used instead of the embedded copies -- which is what makes
editing the frontend during development work, and lets an operator reword the
UI without a rebuild.
NOTE
