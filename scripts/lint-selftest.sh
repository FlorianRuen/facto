#!/usr/bin/env bash
# Proves that the depguard rule banning golang.org/x/crypto/openpgp (ADR 0009)
# is live in .golangci.yml, for production files and test files alike.
#
# It builds a throwaway module under .cache/lint-selftest/ (inside the repo so
# the config's path globs see it as any other file; its own go.mod keeps it out
# of the main module), pinned to the root module's golang.org/x/crypto version,
# resolved from the local module cache only (GOPROXY=off). Then it lints:
#   (a) a clean control package          -> must exit 0
#   (b) a .go file importing openpgp     -> non-zero, depguard names openpgp
#   (c) a _test.go file importing openpgp -> non-zero, depguard names openpgp
#
# Prints "lint-selftest: openpgp import rejected by depguard" and exits 0 on
# success; exits 1 with the offending linter output otherwise.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG="$ROOT/.golangci.yml"
LINT=${GOLANGCI_LINT:-golangci-lint}
GO=${GO:-go}
BANNED=golang.org/x/crypto/openpgp
WORK="$ROOT/.cache/lint-selftest"

fail() {
  echo "lint-selftest: FAIL: $*" >&2
  exit 1
}

cd "$ROOT"
crypto_version=$("$GO" list -m -f '{{.Version}}' golang.org/x/crypto) ||
  fail "cannot read the golang.org/x/crypto version of the root module"
[[ -n $crypto_version ]] || fail "golang.org/x/crypto is not in the root module graph"
go_version=$(sed -n 's/^go //p' go.mod)
sums=$(grep -E "^golang\.org/x/crypto ${crypto_version//./\\.}(/go\.mod)? " go.sum) ||
  fail "golang.org/x/crypto $crypto_version missing from go.sum"

rm -rf "$WORK"
mkdir -p -m 700 "$WORK/control" "$WORK/prod" "$WORK/testonly"

cat >"$WORK/go.mod" <<EOF
module example.invalid/lintselftest

go $go_version

require golang.org/x/crypto $crypto_version
EOF
printf '%s\n' "$sums" >"$WORK/go.sum"

cat >"$WORK/control/control.go" <<'EOF'
// Package control is a clean lint self-test fixture.
package control

// Answer returns a constant.
func Answer() int { return 42 }
EOF

cat >"$WORK/prod/prod.go" <<EOF
// Package prod imports a banned package from production code.
package prod

import "$BANNED"

// Read is a reference to the banned package.
var Read = openpgp.ReadKeyRing
EOF

cat >"$WORK/testonly/testonly.go" <<'EOF'
// Package testonly imports a banned package from a test file only.
package testonly

// Answer returns a constant.
func Answer() int { return 42 }
EOF
cat >"$WORK/testonly/testonly_test.go" <<EOF
package testonly

import (
	"testing"

	"$BANNED"
)

var read = openpgp.ReadKeyRing

func TestBanned(t *testing.T) {
	t.Parallel()
	if read != nil && Answer() != 42 {
		t.Fatal("unreachable")
	}
}
EOF

# Module cache only: nothing is fetched.
export GOPROXY=off GOFLAGS=-mod=mod GOWORK=off

lint() {
  (cd "$WORK" && "$LINT" run --config "$CONFIG" "$@" 2>&1)
}

out=$(lint ./control/...) || fail "control package must lint clean:
$out"

expect_rejected() {
  local name=$1 pkg=$2 out status=0
  out=$(lint "$pkg") || status=$?
  [[ $status -ne 0 ]] || fail "$name: lint exited 0 although it imports $BANNED"
  if ! grep -F "$BANNED" <<<"$out" | grep -qF depguard; then
    fail "$name: no depguard finding naming $BANNED (exit $status):
$out"
  fi
}

expect_rejected "production file" ./prod/...
expect_rejected "test file" ./testonly/...

echo "lint-selftest: openpgp import rejected by depguard"
