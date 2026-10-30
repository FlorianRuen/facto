//go:build e2e

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/vault/e2ekey"
)

// errNoE2EKeyStore refuses keyring:// refs of an e2e run with no state dir.
var errNoE2EKeyStore = errors.New("e2e keyring: no state dir, keyring refs refused")

// init serves the keyring:// scheme of an e2e build from the e2e file key
// store (J1 T23, ADR 0009 A3): no e2e run can reach the OS keyring through
// a credential reference either. Release builds never link this file.
func init() {
	testKeyringBackend = func(_ env, stateDir string) keyring.Backend {
		return e2eKeyringBackend{stateDir: stateDir}
	}
}

// e2eKeyringBackend is a keyring.Backend over e2ekey under
// <stateDir>/e2e-keys: service is the ref item, user its field. The store
// is opened on each call (nothing happens at construction). An empty
// stateDir refuses every call.
type e2eKeyringBackend struct {
	stateDir string
}

var _ keyring.Backend = e2eKeyringBackend{}

// source opens the store and builds the canonical ref of service/user.
func (b e2eKeyringBackend) source(service, user string) (*e2ekey.Source, secret.Ref, error) {
	if b.stateDir == "" {
		return nil, secret.Ref{}, errNoE2EKeyStore
	}
	ref, err := secret.ParseRef(secret.SchemeKeyring + "://" + service + "/" + user)
	if err != nil {
		return nil, secret.Ref{}, fmt.Errorf("e2e keyring: %w", err)
	}
	src, err := e2ekey.New(filepath.Join(b.stateDir, e2eKeysSubdir))
	if err != nil {
		return nil, secret.Ref{}, fmt.Errorf("e2e keyring: %w", err)
	}
	return src, ref, nil
}

// notFound maps the store's not-found to keyring.ErrNotFound.
func notFound(err error) error {
	if errors.Is(err, secret.ErrSecretNotFound) {
		return keyring.ErrNotFound
	}
	return err
}

// keyring.Backend carries no context: the keyring Provider bounds each
// call with its own timeout, so the store calls get a background context.

// Get returns the stored value.
func (b e2eKeyringBackend) Get(service, user string) (string, error) {
	src, ref, err := b.source(service, user)
	if err != nil {
		return "", err
	}
	v, err := src.Resolve(context.Background(), ref)
	if err != nil {
		return "", notFound(err)
	}
	defer v.Wipe()
	return v.Expose(), nil
}

// Set stores value.
func (b e2eKeyringBackend) Set(service, user, value string) error {
	src, ref, err := b.source(service, user)
	if err != nil {
		return err
	}
	v := secret.FromString(value)
	defer v.Wipe()
	if err := src.Set(context.Background(), ref, v); err != nil {
		return fmt.Errorf("e2e keyring: %w", err)
	}
	return nil
}

// Delete removes the entry; a missing one wraps keyring.ErrNotFound.
func (b e2eKeyringBackend) Delete(service, user string) error {
	src, ref, err := b.source(service, user)
	if err != nil {
		return err
	}
	v, err := src.Resolve(context.Background(), ref) // existence check only
	v.Wipe()
	if err != nil {
		return notFound(err)
	}
	if err := src.Delete(context.Background(), ref); err != nil {
		return fmt.Errorf("e2e keyring: %w", err)
	}
	return nil
}
