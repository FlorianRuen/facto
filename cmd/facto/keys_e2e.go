//go:build e2e

package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/FlorianRuen/facto/internal/vault"
	"github.com/FlorianRuen/facto/internal/vault/e2ekey"
)

// e2eKeysSubdir is the directory of the e2e session keys inside the state
// dir (0700, one 0600 file per key, created on first use).
const e2eKeysSubdir = "e2e-keys"

// init makes the e2e build keep session keys in files (J1 T23, ADR 0009
// A3): an e2e binary never consults the OS keyring, so no test run can
// reach the developer's keyring or session bus. Derived from the state dir
// rather than a variable: every e2e run has a sandboxed state dir, and the
// keys live and die with it. Release builds never link this file (`make
// release-e2e-check`).
func init() {
	testKeyBackend = e2eKeyBackend
}

// e2eKeyBackend returns the e2e file key source over
// <stateDir>/e2e-keys. A done ctx, an insecure or non-directory key dir is
// an error (sessions are then ephemeral for the run, one warning).
func e2eKeyBackend(ctx context.Context, _ env, stateDir string) (vault.KeyBackend, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("e2e keys: %w", err)
	}
	src, err := e2ekey.New(filepath.Join(stateDir, e2eKeysSubdir))
	if err != nil {
		return nil, fmt.Errorf("e2e keys: %w", err)
	}
	return src, nil
}
