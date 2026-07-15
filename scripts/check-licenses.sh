#!/usr/bin/env bash
set -euo pipefail

readonly scanner='github.com/google/go-licenses/v2@v2.0.1'
readonly allowed='AGPL-3.0,Apache-2.0,BSD-2-Clause,BSD-3-Clause,MIT'

go run "$scanner" check ./... \
  --allowed_licenses="$allowed"

echo "Dependency-license check passed with no exceptions."
