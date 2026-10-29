// Package keyring resolves, stores and deletes keyring://<service>/<key>
// entries of the OS keyring (docs/spec.md, "Security and credentials";
// ADR 0005, ADR 0009). Every backend call is bounded and cancellable
// (SEC-J0-23).
//
// The provider depends on the small Backend interface; System returns the
// adapter over github.com/zalando/go-keyring. Tests use a fake backend and
// never touch the real keyring.
package keyring

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/FlorianRuen/facto/internal/secret"
)

// ErrNotFound reports a keyring entry that does not exist. Backends return
// it (possibly wrapped) for a missing entry; it wraps
// secret.ErrSecretNotFound.
var ErrNotFound = fmt.Errorf("keyring: entry not found: %w", secret.ErrSecretNotFound)

// ErrTimeout reports a backend call that did not answer within the provider
// timeout. It wraps context.DeadlineExceeded. After a timed-out Set or
// Delete the keyring state is unknown: the abandoned call may still complete
// later (ADR 0009, rotation step 2).
var ErrTimeout = fmt.Errorf("keyring: backend call timed out: %w", context.DeadlineExceeded)

// ErrEmptyValue reports a Set with an empty Secret: the keyring never holds
// an empty entry (Resolve treats one as missing).
var ErrEmptyValue = errors.New("keyring: empty value")

// DefaultTimeout bounds every backend call unless WithTimeout sets another
// bound. go-keyring calls (D-Bus, Keychain, Credential Manager) cannot be
// cancelled, so a hung keyring daemon would otherwise block the caller.
const DefaultTimeout = 10 * time.Second

// Backend reads, writes and deletes entries of a keyring. Get and Delete
// return an error wrapping ErrNotFound when the entry does not exist. Calls
// may block (a hung daemon); the Provider bounds them.
type Backend interface {
	Get(service, user string) (string, error)
	Set(service, user, value string) error
	Delete(service, user string) error
}

// Option configures a Provider.
type Option func(*Provider)

// WithTimeout sets the bound of every backend call. A value <= 0 keeps
// DefaultTimeout.
func WithTimeout(d time.Duration) Option {
	return func(p *Provider) {
		if d > 0 {
			p.timeout = d
		}
	}
}

// WithAfter injects the timer used to bound backend calls (time.After by
// default), so tests can expire it by hand. A nil function keeps the
// default.
func WithAfter(after func(time.Duration) <-chan time.Time) Option {
	return func(p *Provider) {
		if after != nil {
			p.after = after
		}
	}
}

// Provider resolves, stores and deletes keyring references through a
// Backend. Every backend call is bounded by the provider timeout and by the
// caller's context: when either ends first, the call is abandoned (its
// result, if it ever comes, is discarded) and its goroutine exits as soon as
// the backend returns. Safe for concurrent use when the Backend is.
type Provider struct {
	backend Backend
	timeout time.Duration
	after   func(time.Duration) <-chan time.Time
}

// New returns a provider over b, bounded by DefaultTimeout unless an option
// says otherwise.
func New(b Backend, opts ...Option) *Provider {
	p := &Provider{backend: b, timeout: DefaultTimeout, after: time.After}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Scheme returns secret.SchemeKeyring.
func (p *Provider) Scheme() string { return secret.SchemeKeyring }

// Resolve returns the value stored under service ref.Item and user
// ref.Field. A hand-built ref is validated again (errors wrap
// secret.ErrInvalidRef). A missing or empty entry wraps ErrNotFound and
// secret.ErrSecretNotFound. A done ctx wraps ctx.Err(); a backend that does
// not answer within the timeout returns ErrTimeout. Backend errors are
// wrapped for errors.Is but their text never reaches the returned error: it
// may echo the value.
func (p *Provider) Resolve(ctx context.Context, ref secret.Ref) (secret.Secret, error) {
	if err := p.precheck(ctx, ref); err != nil {
		return secret.Secret{}, err
	}
	v, err := p.call(ctx, func() (string, error) { return p.backend.Get(ref.Item, ref.Field) })
	switch {
	case errors.Is(err, ErrNotFound):
		return secret.Secret{}, ErrNotFound
	case err != nil:
		return secret.Secret{}, err
	case v == "":
		return secret.Secret{}, fmt.Errorf("keyring: empty entry: %w", ErrNotFound)
	}
	return secret.FromString(v), nil
}

// Set stores value under service ref.Item and user ref.Field, replacing any
// previous entry. The caller keeps ownership of value: Set neither wipes nor
// keeps it. An invalid ref wraps secret.ErrInvalidRef, an empty value is
// ErrEmptyValue, a done ctx wraps ctx.Err(); in these cases the backend is
// not called. A timeout returns ErrTimeout and leaves the entry in an
// unknown state (the abandoned write may still land). Backend error text is
// hidden as in Resolve.
func (p *Provider) Set(ctx context.Context, ref secret.Ref, value secret.Secret) error {
	if err := validate(ref); err != nil {
		return err
	}
	if value.IsZero() {
		return ErrEmptyValue
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	// Exposed before the call starts: an abandoned call must write what the
	// caller passed, not "" if the caller wipes value after a timeout.
	v := value.Expose()
	_, err := p.call(ctx, func() (string, error) {
		return "", p.backend.Set(ref.Item, ref.Field, v)
	})
	return err
}

// Delete removes the entry under service ref.Item and user ref.Field
// without reading it (ADR 0009, ephemeral mode). It is idempotent: a missing
// entry is not an error, since ephemeral cleanup deletes keys that may never
// have been written. An invalid ref wraps secret.ErrInvalidRef and a done
// ctx wraps ctx.Err(), without calling the backend. A timeout returns
// ErrTimeout and the entry may or may not be gone. Backend error text is
// hidden as in Resolve.
func (p *Provider) Delete(ctx context.Context, ref secret.Ref) error {
	if err := p.precheck(ctx, ref); err != nil {
		return err
	}
	_, err := p.call(ctx, func() (string, error) { return "", p.backend.Delete(ref.Item, ref.Field) })
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// precheck validates ref and refuses a done ctx before any backend call.
func (p *Provider) precheck(ctx context.Context, ref secret.Ref) error {
	if err := validate(ref); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	return nil
}

// result is the outcome of one backend call.
type result struct {
	v   string
	err error
}

// call runs fn on its own goroutine and waits for it, ctx or the provider
// timeout, whichever comes first. The result channel is buffered, so an
// abandoned call's goroutine delivers into it and exits as soon as fn
// returns; nobody reads the late value. ErrNotFound from fn is returned as
// is; any other backend error is wrapped in backendError.
func (p *Provider) call(ctx context.Context, fn func() (string, error)) (string, error) {
	done := make(chan result, 1)
	go func() {
		v, err := fn()
		done <- result{v: v, err: err}
	}()
	timeout := p.after(p.timeout)
	select {
	case r := <-done:
		switch {
		case errors.Is(r.err, ErrNotFound):
			return "", ErrNotFound
		case r.err != nil:
			return "", &backendError{err: r.err}
		}
		return r.v, nil
	case <-ctx.Done():
		return "", fmt.Errorf("keyring: %w", ctx.Err())
	case <-timeout:
		return "", ErrTimeout
	}
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
