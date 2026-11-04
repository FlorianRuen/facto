package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/bitwarden"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
)

// bwBinary is the password manager CLI, looked up in PATH when first run.
const bwBinary = "bw"

// bwSessionEnv is the variable holding a session key the user already
// unlocked in this terminal (docs/spec.md "Bitwarden unlock", step 1).
const bwSessionEnv = "BW_SESSION"

// secretResolver is what collect needs from the run's resolver.
// *secret.Resolver satisfies it.
type secretResolver interface {
	connector.SecretResolver
	// CloseAll closes every provider (locks the password manager, wipes
	// session keys).
	CloseAll() error
}

// onceCloser returns a function that closes r (CloseAll, wrapped by
// closeErr) on its first call and returns that same result on every later
// call. collect and login defer it right after building the resolver, so a
// panic still locks the password manager, and also call it on the normal
// path to report the close error: CloseAll runs exactly once either way.
func onceCloser(r secretResolver) func() error {
	return sync.OnceValue(func() error { return closeErr("secrets", r.CloseAll()) })
}

// testSecretProviders returns the providers of test-only schemes. It is nil
// in every build but -tags e2e, where secrets_e2e.go sets it once at package
// initialization (ADR 0009 A3: e2e-only secret sources are absent from
// release builds).
var testSecretProviders func(e env) ([]secret.Provider, error)

// testKeyringBackend is nil in every build but -tags e2e, where
// keyring_e2e.go sets it at package initialization: keyring:// refs are
// then served from the e2e file key store under the state dir, never the
// OS keyring (ADR 0009 A3).
var testKeyringBackend func(e env, stateDir string) keyring.Backend

// keyringBackend returns the backend of the keyring:// scheme: the e2e
// file store in an e2e build, the OS keyring otherwise. Nothing is called.
func keyringBackend(e env, stateDir string) keyring.Backend {
	if testKeyringBackend != nil {
		return testKeyringBackend(e, stateDir)
	}
	return keyring.System()
}

// newSecretResolver is secret.NewResolver over secretProvidersIn(e, the
// configured state dir).
func newSecretResolver(_ context.Context, e env, cfg *config.Config) (secretResolver, error) {
	stateDir := ""
	if cfg != nil {
		stateDir = cfg.StateDir
	}
	ps, err := secretProvidersIn(e, stateDir)
	if err != nil {
		return nil, err
	}
	r, err := secret.NewResolver(ps...)
	if err != nil {
		closeProviders(ps)
		return nil, fmt.Errorf("secret resolver: %w", err)
	}
	return r, nil
}

// secretProviders returns the production providers: bw (over the bw CLI,
// reusing a session key the user unlocked in this terminal) and keyring (the
// OS keyring), plus the e2e file provider in builds with -tags e2e only.
// Constructing them runs nothing: no bw command, no keyring call. No state
// dir is known here: in an e2e build keyring:// refs are refused.
func secretProviders(e env) ([]secret.Provider, error) {
	return secretProvidersIn(e, "")
}

// secretProvidersIn is secretProviders with the configured state dir, where
// an e2e build keeps its keyring:// entries.
func secretProvidersIn(e env, stateDir string) ([]secret.Provider, error) {
	var session secret.Secret
	if e.LookupEnv != nil {
		if v, ok := e.LookupEnv(bwSessionEnv); ok && v != "" {
			session = secret.FromString(v)
		}
	}
	bw, err := bitwarden.New(bitwarden.Options{Runner: bitwarden.ExecRunner{Path: bwBinary}, Session: session})
	if err != nil {
		session.Wipe()
		return nil, fmt.Errorf("bitwarden provider: %w", err)
	}
	ps := []secret.Provider{bw, keyring.New(keyringBackend(e, stateDir))}
	if testSecretProviders != nil {
		extra, err := testSecretProviders(e)
		if err != nil {
			closeProviders(ps)
			return nil, err
		}
		ps = append(ps, extra...)
	}
	return ps, nil
}

// closeProviders closes providers that never reached a resolver. Nothing
// was resolved through them, so there is nothing to lock: errors are
// dropped.
func closeProviders(ps []secret.Provider) {
	for _, p := range ps {
		_ = p.Close()
	}
}
