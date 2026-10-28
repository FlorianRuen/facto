#!/usr/bin/env bash
# Greps every artifact produced by the test suite for canary secrets.
# Tests create canaries with testsecrets.Canary(t, kind); with FACTO_CANARY=1 they
# are recorded, one per line, in $CANARY_FILE. Artifacts live under $ART_DIR
# (testsecrets.ArtifactDir) and ./testdata (optional).
#
# Exit 0 with "0 canary hits" when nothing leaked; exit 1 with "<n> canary hits"
# (n = number of files containing a canary) otherwise. Any other problem (no
# canary recorded, missing $ART_DIR, grep error) fails and never prints
# "0 canary hits".
set -euo pipefail
CANARY_FILE=${CANARY_FILE:-.cache/canaries.txt}
ART_DIR=${ART_DIR:-.cache/test-artifacts}

# At least one non-empty line: an empty pattern would match everything.
if ! grep -q . "$CANARY_FILE" 2>/dev/null; then
  echo "leakcheck: no canaries recorded in $CANARY_FILE (did tests run with FACTO_CANARY=1?)"
  exit 1
fi
if [[ ! -d $ART_DIR ]]; then
  echo "leakcheck: artifact directory $ART_DIR does not exist"
  exit 2
fi

targets=("$ART_DIR")
[[ -d testdata ]] && targets+=(testdata)

# -F fixed strings, -a binary files (SQLite, PDF) scanned as text, -l one line
# per matching file. grep exits 1 on zero hits and >1 on a real error.
status=0
files=$(grep -r -l -a -F -f <(grep . "$CANARY_FILE") -- "${targets[@]}") || status=$?
if ((status > 1)); then
  echo "leakcheck: grep failed with exit status $status"
  exit 2
fi

if [[ -z $files ]]; then
  hits=0
else
  hits=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
  echo "leakcheck: canary found in:"
  sed 's/^/  /' <<<"$files"
fi
echo "$hits canary hits"
[[ $hits == 0 ]]
