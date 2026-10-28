// Package keyring resolves keyring://<service>/<key> references from the OS
// keyring (docs/spec.md, "Security and credentials"; ADR 0005).
//
// The provider depends on the small Backend interface; System returns the
// adapter over github.com/zalando/go-keyring. Tests use a fake backend and
// never touch the real keyring.
package keyring

import (
	"context"
	"errors"
	"fmt"

	"github.com/FlorianRuen/facto/internal/secret"
)

// ErrNotFound reports a keyring entry that does not exist. Backends return
// it (possibly wrapped) for a missing entry; it wraps
// secret.ErrSecretNotFound.
var ErrNotFound = fmt.Errorf("keyring: entry not found: %w", secret.ErrSecretNotFound)

// Backend reads one entry from a keyring. Get returns an error wrapping
// ErrNotFound when the entry does not exist.
type Backend interface {
	Get(service, user string) (string, error)
}

// Provider resolves keyring references through a Backend. Safe for
// concurrent use when the Backend is.
type Provider struct {
	backend Backend
}

// New returns a provider reading from b.
func New(b Backend) *Provider {
	return &Provider{backend: b}
}

// Scheme returns secret.SchemeKeyring.
func (p *Provider) Scheme() string { return secret.SchemeKeyring }

// Resolve returns the value stored under service ref.Item and user
// ref.Field. A hand-built ref is validated again (errors wrap
// secret.ErrInvalidRef). A missing or empty entry wraps ErrNotFound and
// secret.ErrSecretNotFound. Backend errors are wrapped for errors.Is but
// their text never reaches the returned error: it may echo the value.
func (p *Provider) Resolve(ctx context.Context, ref secret.Ref) (secret.Secret, error) {
	if err := validate(ref); err != nil {
		return secret.Secret{}, err
	}
	if err := ctx.Err(); err != nil {
		return secret.Secret{}, fmt.Errorf("keyring: %w", err)
	}
	v, err := p.backend.Get(ref.Item, ref.Field)
	switch {
	case errors.Is(err, ErrNotFound):
		return secret.Secret{}, ErrNotFound
	case err != nil:
		return secret.Secret{}, &backendError{err: err}
	case v == "":
		return secret.Secret{}, fmt.Errorf("keyring: empty entry: %w", ErrNotFound)
	}
	return secret.FromString(v), nil
}

// Close does nothing: the provider holds no session. It is idempotent.
func (p *Provider) Close() error { return nil }

// validate re-parses a possibly hand-built ref: only the canonical form of a
// keyring reference is accepted.
func validate(ref secret.Ref) error {
	if ref.Scheme != secret.SchemeKeyring {
		return fmt.Errorf("%w: keyring: wrong scheme", secret.ErrInvalidRef)
	}
	parsed, err := secret.ParseRef(ref.String())
	if err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	if parsed != ref {
		return fmt.Errorf("%w: keyring: not canonical", secret.ErrInvalidRef)
	}
	return nil
}

// backendError hides the text of a backend error (which may echo the
// value) while keeping it reachable through errors.Is and errors.As.
type backendError struct {
	err error
}

func (e *backendError) Error() string    { return "keyring: backend error" }
func (e *backendError) GoString() string { return e.Error() }
func (e *backendError) Unwrap() error    { return e.err }
