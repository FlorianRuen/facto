#!/usr/bin/env bash
# Scans a fixture tree for personal data or secrets; must print
# "PII scan: 0 findings" before any commit (scripts/fixtures/scan/main.go).
# Usage: scripts/fixtures/scan.sh <fixture-dir>
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: $0 <fixture-dir>" >&2
  exit 2
fi
dir=$(cd "$1" && pwd) || { echo "scan: not a directory" >&2; exit 2; }
cd "$(dirname "$0")/../.."
exec go run ./scripts/fixtures/scan "$dir"
