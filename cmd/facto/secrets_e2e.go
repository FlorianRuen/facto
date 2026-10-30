//go:build e2e

package main

import (
	"errors"
	"fmt"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/e2efile"
	"github.com/FlorianRuen/facto/internal/vault/e2ekey"
)

// e2eDirEnv names the directory of the e2e file provider.
const e2eDirEnv = "FACTO_E2E_SECRETS_DIR"

// init registers the e2e-only secret sources. This file is the only place
// that links internal/secret/e2efile and internal/vault/e2ekey into facto,
// and only with -tags e2e (ADR 0009 A3); `make release-e2e-check` proves
// the release build lacks both.
func init() {
	testSecretProviders = e2eSecretProviders
}

// e2eSecretProviders returns the e2e file provider over the directory
// named by FACTO_E2E_SECRETS_DIR (read through env.LookupEnv). An unset or
// empty variable adds no provider; a set but missing or insecure directory
// is an error.
func e2eSecretProviders(e env) ([]secret.Provider, error) {
	// Reading the sentinels keeps them linked: the release check's go tool
	// nm self-test looks for them in the e2e binary.
	if e2efile.Sentinel == "" || e2ekey.Sentinel == "" {
		return nil, errors.New("e2e: sentinel missing")
	}
	if e.LookupEnv == nil {
		return nil, nil
	}
	dir, ok := e.LookupEnv(e2eDirEnv)
	if !ok || dir == "" {
		return nil, nil
	}
	p, err := e2efile.New(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", e2eDirEnv, err)
	}
	return []secret.Provider{p}, nil
}
