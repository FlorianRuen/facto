#!/usr/bin/env bash
# Replaces personal data in a fixture tree with synthetic, format-preserving
# values, consistently across files (scripts/fixtures/sanitize/main.go).
# Usage: scripts/fixtures/sanitize.sh <fixture-dir>
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: $0 <fixture-dir>" >&2
  exit 2
fi
dir=$(cd "$1" && pwd) || { echo "sanitize: not a directory" >&2; exit 2; }
cd "$(dirname "$0")/../.."
exec go run ./scripts/fixtures/sanitize "$dir"
