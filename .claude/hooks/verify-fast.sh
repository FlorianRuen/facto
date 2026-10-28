#!/usr/bin/env bash
# Stop hook: quick health report printed into the transcript so the agent and the
# goal evaluator see it. Non-blocking by design (avoids stop/continue loops).
set -uo pipefail
[[ -f go.mod ]] || exit 0
echo "--- verify-fast ---"
unformatted="$(gofmt -l $(git ls-files '*.go' 2>/dev/null) 2>/dev/null)"
[[ -n "$unformatted" ]] && echo "unformatted: $unformatted" || echo "gofmt: ok"
if go vet ./... >/tmp/facto-vet.txt 2>&1; then echo "go vet: ok"; else echo "go vet: FAIL"; tail -n 20 /tmp/facto-vet.txt; fi
if go test -short -count=1 ./... >/tmp/facto-test.txt 2>&1; then echo "go test -short: ok"
else echo "go test -short: FAIL"; grep -E '^(--- FAIL|FAIL|panic)' /tmp/facto-test.txt | head -n 20; fi
exit 0
