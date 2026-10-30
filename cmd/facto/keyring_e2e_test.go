//go:build e2e

package main

// The keyring:// secret scheme in an e2e build (J1 T23 review): it is
// served from the e2e file key store under <state_dir>/e2e-keys, never the
// OS keyring (Secret Service bus, macOS Keychain, Windows Credential
// Manager). Without a state dir every call is refused. All values are
// synthetic.

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault/e2ekey"
)

func TestKeyringBackend_E2ENeverTheOSKeyring(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	state := stateDirFor(t, s)
	for _, dir := range []string{state, ""} {
		b := keyringBackend(s.env(), dir)
		if _, ok := b.(e2eKeyringBackend); !ok {
			t.Errorf("keyringBackend(state %q) is %T, want the e2e file backend (never keyring.System)", dir, b)
		}
	}
}

func TestSecretResolver_E2EKeyringRefFromFileStore(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	state := stateDirFor(t, s)
	canary := testsecrets.Canary(t, testsecrets.Password)
	src, err := e2ekey.New(filepath.Join(state, e2eKeysSubdir))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := secret.ParseRef("keyring://facto/x")
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Set(t.Context(), ref, secret.FromString(canary)); err != nil {
		t.Fatal(err)
	}
	r, err := newSecretResolver(t.Context(), s.env(), &config.Config{StateDir: state})
	if err != nil {
		t.Fatalf("newSecretResolver: %v", err)
	}
	defer func() { _ = r.CloseAll() }()
	got, err := r.Resolve(t.Context(), "keyring://facto/x")
	if err != nil {
		t.Fatalf("Resolve keyring://facto/x: %v", err)
	}
	if got.Expose() != canary {
		t.Error("keyring://facto/x did not resolve to the e2e file value")
	}
	got.Wipe()
	if _, err := r.Resolve(t.Context(), "keyring://facto/missing"); !errors.Is(err, secret.ErrSecretNotFound) && !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("missing keyring ref = %v, want not found", err)
	}
}

func TestSecretResolver_E2EKeyringRefusedWithoutStateDir(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	r, err := newSecretResolver(t.Context(), s.env(), &config.Config{})
	if err != nil {
		t.Fatalf("newSecretResolver: %v", err)
	}
	defer func() { _ = r.CloseAll() }()
	v, err := r.Resolve(t.Context(), "keyring://facto/x")
	if err == nil {
		v.Wipe()
		t.Fatal("keyring ref resolved with no state dir, want a refusal")
	}
	if errors.Is(err, keyring.ErrNotFound) || errors.Is(err, secret.ErrSecretNotFound) {
		t.Errorf("refusal = %v, want an error, not a not-found", err)
	}
}
