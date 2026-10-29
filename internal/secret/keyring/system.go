package keyring

import (
	"errors"
	"fmt"

	gokeyring "github.com/zalando/go-keyring"
)

// System returns the Backend over the OS keyring (macOS Keychain, Windows
// Credential Manager, Linux Secret Service) through go-keyring (ADR 0005).
func System() Backend {
	return goBackend{get: gokeyring.Get}
}

// goBackend adapts a go-keyring style getter to Backend.
type goBackend struct {
	get func(service, user string) (string, error)
}

// Get maps go-keyring's not-found to ErrNotFound. Other errors are returned
// as is; Provider hides their text.
func (b goBackend) Get(service, user string) (string, error) {
	v, err := b.get(service, user)
	if errors.Is(err, gokeyring.ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("go-keyring: %w", err)
	}
	return v, nil
}
