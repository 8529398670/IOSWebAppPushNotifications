# syntax=docker/dockerfile:1

# --- build stage -----------------------------------------------------------
# Only this stage needs the Go toolchain, the module cache, and the source.
# None of it survives into the shipped image.
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Copy the module files alone first. Docker caches this layer, so an edit to
# the Go source re-runs the build but not the dependency download.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 produces a statically linked binary with no libc dependency,
# which is what lets the runtime image stay this small and avoids the
# musl-vs-glibc surprises that come with cross-compiling against Alpine.
# -trimpath keeps build-machine paths out of the binary; -s -w drop the debug
# symbol tables, which shrinks it and removes a little detail from anyone
# poking at a compromised container.
# Version metadata, passed by docker/lib.sh so that
# `docker exec <name> /app/server version` is as informative as a portable
# binary built by scripts/build.sh.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# One binary. The frontend is compiled into it by go:embed (see main.go),
# and account administration is the "manage" subcommand -- so the image needs
# no static directory, no language.yaml, and no second executable.
#
# -tags container pins the image's fixed layout into the binary
# (server/config/layout_container.go): config at /app/config/config.yaml with
# secret.key beside it, state in /app/data, the control socket on the tmpfs at
# /tmp. That is what replaces setting them through ENV, and it is why
# `docker exec <name> /app/server manage ...` needs nothing extra.
RUN CGO_ENABLED=0 GOOS=linux go build -tags container -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o /out/server .

# --- runtime stage ---------------------------------------------------------
FROM alpine:3.24 AS runtime

# ca-certificates is the only package added: without it any outbound HTTPS
# this app grows later fails with an opaque certificate error.
#
# The uid/gid are fixed at 10001 rather than left to Alpine's system range.
# docker/run.sh grants this user the host's data directory, and this group
# read-write access to config.yaml and read access to secret.key; a number in the low hundreds is likely to belong to a
# real account on a Linux host, and that account would get the same access.
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 10001 app \
 && adduser -S -u 10001 -G app -h /app -s /sbin/nologin app

WORKDIR /app

COPY --from=builder /out/server ./

# There is no ENV here, and no config.yaml or secret.key in the image
# (.dockerignore keeps them out -- an image layer is forever, and a key in
# one is everyone's). docker/run.sh mounts the project's config/config.yaml
# (writable) and config/secret.key (read-only) into /app/config at run time,
# so one image serves any deployment. Most settings apply while it runs --
# from the owner's Settings screen, or by editing config.yaml on the host;
# the rest need a restart, never a rebuild.
#
# server.static_dir (./static, i.e. /app/static) does not exist in this
# image, so the embedded frontend is used. Mounting over it, or putting a
# language.yaml in the data directory, is the supported way to run the shipped
# UI with different wording:
#   -v ./config/language.yaml:/app/data/language.yaml:ro

# Only the data directory is writable, and only by the app user. Everything
# else stays owned by root and read-only to the process -- so even a bug that
# lets someone run code in here cannot rewrite the binary or the frontend.
# docker/run.sh mounts /app/data as a volume and runs the container with
# --read-only, which is what makes that guarantee real rather than a
# convention.
# /app/config is only a mount point for config.yaml and secret.key; it stays
# root's. That is why the container rewrites config.yaml in place rather than
# by renaming a new file over it (see writeConfigFile).
RUN mkdir -p /app/data /app/config && chown app:app /app/data

# Note: this ownership survives into a *named* volume, but a bind mount
# shadows it with the host's ownership. docker/run.sh uses a bind mount, so the
# database stays visible on the host for backups, and chowns that directory to
# this user before starting the container. Running this image against a bind
# mount without that step fails with "permission denied" on app.db.

USER app

# No EXPOSE: the port is server.port in config.yaml, and docker/run.sh
# publishes it from there. A hardcoded EXPOSE would be stale documentation
# the first time someone changed it.
#
# `/app/server health` reads the same config.yaml for the port and asks
# /api/health, which touches nothing -- so a slow database query can never get
# a healthy container killed.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/server", "health"]

ENTRYPOINT ["/app/server"]
