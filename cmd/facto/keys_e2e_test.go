//go:build e2e

package main

// Tests of the e2e-only session key backend (J1 T23, ADR 0009 A3): an e2e
// build never consults the OS keyring; with no KeyBackend seam it keeps
// session keys in internal/vault/e2ekey under <state_dir>/e2e-keys (0700,
// one 0600 file per key). All values are synthetic.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault"
	"github.com/FlorianRuen/facto/internal/vault/e2ekey"
)

// stateDirFor makes a private state dir for s.
func stateDirFor(t *testing.T, s *sandbox) string {
	t.Helper()
	root, err := fsx.Open(s.home)
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirPrivate(".facto"); err != nil {
		t.Fatalf("setup mkdir: %v", err)
	}
	return s.state
}

func TestProbeKeyBackend_E2EUsesFileKeysInStateDir(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	state := stateDirFor(t, s)
	e := s.env()
	e.KeyBackend = nil // no seam: an e2e build must not reach the OS keyring
	for _, interactive := range []bool{false, true} {
		kb, err := probeKeyBackend(t.Context(), e, state, interactive)
		if err != nil {
			t.Fatalf("probeKeyBackend(interactive=%v): %v", interactive, err)
		}
		if _, ok := kb.(*e2ekey.Source); !ok {
			t.Fatalf("key backend is %T, want *e2ekey.Source", kb)
		}
	}
	dir := filepath.Join(state, e2eKeysSubdir)
	if err := fsx.CheckPrivate(dir); err != nil {
		t.Errorf("key dir %s not private: %v", e2eKeysSubdir, err)
	}
	kb, err := probeKeyBackend(t.Context(), e, state, false)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := secret.ParseRef("keyring://facto/session-synthetic")
	if err != nil {
		t.Fatal(err)
	}
	canary := testsecrets.Canary(t, testsecrets.Token)
	if err := kb.Set(t.Context(), ref, secret.FromString(canary)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := kb.Resolve(t.Context(), ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Expose() != canary {
		t.Error("Resolve did not return the stored key")
	}
	got.Wipe()
	fi, err := os.Lstat(filepath.Join(dir, "facto", "session-synthetic"))
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %#o, want 0600", fi.Mode().Perm())
	}
}

func TestProbeKeyBackend_E2ESeamWins(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	state := stateDirFor(t, s)
	e := s.env()
	keys := newMemKeys()
	e.KeyBackend = keys.factory()
	kb, err := probeKeyBackend(t.Context(), e, state, false)
	if err != nil {
		t.Fatal(err)
	}
	if kb != vault.KeyBackend(keys) {
		t.Errorf("key backend is %T, want the injected seam", kb)
	}
	if _, err := os.Lstat(filepath.Join(state, e2eKeysSubdir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("key dir created although a seam was injected (err %v)", err)
	}
}

func TestProbeKeyBackend_E2EInsecureKeyDirRefused(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	state := stateDirFor(t, s)
	dir := filepath.Join(state, e2eKeysSubdir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	loose := os.FileMode(0o755) // synthetic insecure key dir
	if err := os.Chmod(dir, loose); err != nil {
		t.Fatal(err)
	}
	e := s.env()
	e.KeyBackend = nil
	_, err := probeKeyBackend(t.Context(), e, state, false)
	if !errors.Is(err, fsx.ErrInsecurePerms) {
		t.Errorf("probeKeyBackend over a 0755 key dir = %v, want fsx.ErrInsecurePerms", err)
	}
}
