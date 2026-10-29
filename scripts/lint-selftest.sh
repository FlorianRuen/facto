#!/usr/bin/env bash
# Proves that two depguard rules of .golangci.yml are live, for production
# and test files alike.
#
# 1. Rule "main" bans golang.org/x/crypto/openpgp (ADR 0009). A throwaway
#    module is built under .cache/lint-selftest/ (inside the repo so the
#    config's path globs see it as any other file; its own go.mod keeps it
#    out of the main module), pinned to the root module's golang.org/x/crypto
#    version, resolved from the local module cache only (GOPROXY=off):
#      (a) a clean control package           -> must exit 0
#      (b) a .go file importing openpgp      -> non-zero, depguard names openpgp
#      (c) a _test.go file importing openpgp -> non-zero, depguard names openpgp
#
# 2. Rule "cdploopback" (ADR 0008, plan J1 T7.1): only internal/browser (and
#    cdploopback itself) may import internal/httpx/cdploopback. A throwaway
#    module cannot import internal/ packages (only a typecheck error would
#    show), so these fixtures live inside the root module. An EXIT trap
#    removes them and .gitignore lists them (a SIGKILL leaves them behind;
#    they are never committable). make runs targets serially (.NOTPARALLEL)
#    so race/lint never see them:
#      (d) internal/browser/zz_lintselftest_cdp.go    -> must exit 0
#      (e) internal/httpx/zz_lintselftest_cdp.go      -> non-zero, depguard names cdploopback
#      (f) internal/lintselftest_cdp/ (.go file)      -> non-zero, depguard names cdploopback
#      (g) internal/lintselftest_cdptest/ (_test.go)  -> non-zero, depguard names cdploopback
#
# Prints "lint-selftest: openpgp import rejected by depguard" and
# "lint-selftest: cdploopback import outside internal/browser rejected by
# depguard" and exits 0 on success; exits 1 with the offending linter output
# otherwise.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG="$ROOT/.golangci.yml"
LINT=${GOLANGCI_LINT:-golangci-lint}
GO=${GO:-go}
BANNED=golang.org/x/crypto/openpgp
WORK="$ROOT/.cache/lint-selftest"
CDP=github.com/FlorianRuen/facto/internal/httpx/cdploopback
CDP_PROD="$ROOT/internal/lintselftest_cdp"
CDP_TEST="$ROOT/internal/lintselftest_cdptest"
CDP_CONTROL="$ROOT/internal/browser/zz_lintselftest_cdp.go"
CDP_HTTPX="$ROOT/internal/httpx/zz_lintselftest_cdp.go"

cleanup() {
  rm -rf "$CDP_PROD" "$CDP_TEST"
  rm -f "$CDP_CONTROL" "$CDP_HTTPX"
}

fail() {
  echo "lint-selftest: FAIL: $*" >&2
  exit 1
}

cd "$ROOT"
for p in "$CDP_PROD" "$CDP_TEST" "$CDP_CONTROL" "$CDP_HTTPX"; do
  [[ ! -e $p ]] || fail "$p already exists: refusing to overwrite it"
done
trap cleanup EXIT
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

mkdir -p -m 700 "$CDP_PROD" "$CDP_TEST"
cat >"$CDP_PROD/prod.go" <<EOF
// Package lintselftestcdp imports cdploopback from outside internal/browser.
package lintselftestcdp

import "$CDP"

// Parse is a reference to the restricted package.
var Parse = cdploopback.ParseTarget
EOF

cat >"$CDP_TEST/testonly.go" <<'EOF'
// Package lintselftestcdptest imports cdploopback from a test file only.
package lintselftestcdptest

// Answer returns a constant.
func Answer() int { return 42 }
EOF
cat >"$CDP_TEST/testonly_test.go" <<EOF
package lintselftestcdptest

import (
	"testing"

	"$CDP"
)

var parse = cdploopback.ParseTarget

func TestRestricted(t *testing.T) {
	t.Parallel()
	if parse != nil && Answer() != 42 {
		t.Fatal("unreachable")
	}
}
EOF

cat >"$CDP_CONTROL" <<EOF
package browser

import "$CDP"

// LintSelftestParse references the restricted package from its one allowed
// importer.
var LintSelftestParse = cdploopback.ParseTarget
EOF

cat >"$CDP_HTTPX" <<EOF
package httpx

import "$CDP"

// LintSelftestParse references the restricted package from internal/httpx,
// which is not an allowed importer.
var LintSelftestParse = cdploopback.ParseTarget
EOF

# Module cache only: nothing is fetched.
export GOPROXY=off GOFLAGS=-mod=mod GOWORK=off

# lint DIR ARGS... runs the linter from DIR (throwaway or root module).
lint() {
  local dir=$1
  shift
  (cd "$dir" && "$LINT" run --config "$CONFIG" "$@" 2>&1)
}

out=$(lint "$WORK" ./control/...) || fail "control package must lint clean:
$out"

# expect_rejected NAME DIR PKG BANNED: linting PKG from DIR must exit non-zero
# with a depguard finding naming BANNED on the same line.
expect_rejected() {
  local name=$1 dir=$2 pkg=$3 banned=$4 out status=0
  out=$(lint "$dir" "$pkg") || status=$?
  [[ $status -ne 0 ]] || fail "$name: lint exited 0 although it imports $banned"
  if ! grep -F "$banned" <<<"$out" | grep -qF depguard; then
    fail "$name: no depguard finding naming $banned (exit $status):
$out"
  fi
}

expect_rejected "production file" "$WORK" ./prod/... "$BANNED"
expect_rejected "test file" "$WORK" ./testonly/... "$BANNED"

echo "lint-selftest: openpgp import rejected by depguard"

out=$(lint "$ROOT" ./internal/browser/...) || fail "internal/browser importing $CDP must lint clean:
$out"
expect_rejected "cdploopback in internal/httpx" "$ROOT" ./internal/httpx "$CDP"
expect_rejected "cdploopback production file" "$ROOT" ./internal/lintselftest_cdp/... "$CDP"
expect_rejected "cdploopback test file" "$ROOT" ./internal/lintselftest_cdptest/... "$CDP"

echo "lint-selftest: cdploopback import outside internal/browser rejected by depguard"
