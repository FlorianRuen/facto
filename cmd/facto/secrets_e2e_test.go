//go:build e2e

// Tests for the e2e-only secret provider registration (J1 T17, ADR 0009 A3).
// Only a -tags e2e build registers the "e2e" scheme; it reads synthetic
// secret files from the directory named by FACTO_E2E_SECRETS_DIR (read
// through env.LookupEnv, never os.Getenv).
//
// Expected API (implementer: follow exactly; package main, e2e build only):
//
//	// e2eDirEnv names the directory of the e2e file provider.
//	const e2eDirEnv = "FACTO_E2E_SECRETS_DIR"
//
// In a //go:build e2e file of this package, secretProviders appends
// e2efile.New(dir) when e2eDirEnv is set (an unset variable adds no
// provider; a set but insecure directory is an error), and that file
// references e2efile.Sentinel and e2ekey.Sentinel so the linker keeps them
// (the release check's self-test finds them with go tool nm).
package main

import (
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// e2eBuild reports a build with -tags e2e.
const e2eBuild = true

// wantSchemes are the secret schemes of an e2e build, sorted. The sandbox
// env sets no FACTO_E2E_SECRETS_DIR, so the e2e provider is absent there.
func wantSchemes() []string { return []string{"bw", "keyring"} }

// TestSecretProviders_E2EFileResolves: in an e2e build with
// FACTO_E2E_SECRETS_DIR set, the resolver serves e2e://<item>/<field> from
// that directory.
func TestSecretProviders_E2EFileResolves(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	base := t.TempDir()
	root, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirPrivate("secrets/synthetic-item"); err != nil {
		t.Fatalf("setup mkdir: %v", err)
	}
	if err := root.WriteAtomic(t.Context(), "secrets/synthetic-item/password", []byte(canary)); err != nil {
		t.Fatalf("setup write: %v", err)
	}
	dir := filepath.Join(base, "secrets")
	e := newSandbox(t).env()
	e.LookupEnv = func(k string) (string, bool) {
		if k == e2eDirEnv {
			return dir, true
		}
		return "", false
	}
	ps, err := secretProviders(e)
	if err != nil {
		t.Fatalf("secretProviders: %v", err)
	}
	found := false
	for _, p := range ps {
		found = found || p.Scheme() == "e2e"
	}
	if !found {
		t.Fatal("e2e build with FACTO_E2E_SECRETS_DIR set: no e2e provider registered")
	}
	r, err := newSecretResolver(t.Context(), e, &config.Config{})
	if err != nil {
		t.Fatalf("newSecretResolver: %v", err)
	}
	defer func() { _ = r.CloseAll() }()
	got, err := r.Resolve(t.Context(), "e2e://synthetic-item/password")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	defer got.Wipe()
	if got.Expose() != canary {
		t.Fatal("Resolve returned another value than the file content")
	}
}
