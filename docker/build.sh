#!/usr/bin/env bash
# Build the container image.
#
# Split from docker/run.sh so that building and running are separately
# runnable: CI builds without starting anything, and a redeploy that only
# needs a restart does not have to rebuild. docker/run.sh builds through the
# same function (docker/lib.sh), so the common case is still one command.
#
# The image name is docker.image in config/config.yaml; with no config yet the
# default from config/defaults.yaml is used.
#
# Usage:
#   docker/build.sh              build <docker.image>:latest
#   docker/build.sh v1.2.3       build and additionally tag v1.2.3
set -euo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )/.."

source docker/lib.sh
build_image "$@"
