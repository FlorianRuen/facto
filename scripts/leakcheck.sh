#!/usr/bin/env bash
# Greps every artifact produced by the test suite for canary secrets.
# Tests write canaries via testsecrets.Canary(t); the list is exported to $CANARY_FILE.
set -euo pipefail
CANARY_FILE=${CANARY_FILE:-.cache/canaries.txt}
ART_DIR=${ART_DIR:-.cache/test-artifacts}
[[ -s $CANARY_FILE ]] || { echo "leakcheck: no canaries recorded (did tests run with FACTO_CANARY=1?)"; exit 1; }
hits=$(grep -rIlF -f "$CANARY_FILE" "$ART_DIR" testdata 2>/dev/null | wc -l | tr -d ' ')
echo "$hits canary hits"
[[ "$hits" == "0" ]]
