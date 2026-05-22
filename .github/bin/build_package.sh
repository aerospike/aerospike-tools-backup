#!/usr/bin/env bash
# Thin wrapper so workflows can `source .github/bin/build_package.sh` like other tools repos.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
# shellcheck disable=SC1091
source "${ROOT}/.github/packaging/project/build_package.sh"
