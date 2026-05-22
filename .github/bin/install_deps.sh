#!/usr/bin/env bash
# Thin wrapper so workflows can `source .github/bin/install_deps.sh` like other tools repos.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
# shellcheck disable=SC1091
source "${ROOT}/.github/packaging/project/install_deps.sh"
