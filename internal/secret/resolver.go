package secret

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Sentinel errors. Use errors.Is.
var (
	// ErrInvalidRef reports a malformed reference (or a plaintext value where
	// a reference was expected).
	ErrInvalidRef = errors.New("secret: invalid reference")
	// ErrNoProvider reports a reference whose scheme has no registered provider.
	ErrNoProvider = errors.New("secret: no provider for scheme")
	// ErrDuplicateScheme reports two providers registered for one scheme.
	ErrDuplicateScheme = errors.New("secret: duplicate provider scheme")
	// ErrInvalidProvider reports a nil provider or a malformed scheme.
	ErrInvalidProvider = errors.New("secret: invalid provider")
	// ErrClosed reports a call after Resolver.CloseAll or Provider.Close.
	ErrClosed = errors.New("secret: resolver closed")
	// ErrSecretNotFound is returned by providers when the referenced secret
	// does not exist.
	ErrSecretNotFound = errors.New("secret: secret not found")
)

// Provider resolves references of one scheme ("bw", "keyring"…). The spec
// calls it SecretProvider.
type Provider interface {
	// Scheme is the reference scheme this provider serves.
	Scheme() string
	// Resolve returns the secret ref points to.
	Resolve(ctx context.Context, ref Ref) (Secret, error)
	// Close locks the backend and wipes session keys.
	Close() error
}

// Resolver dispatches references to the provider registered for their
// scheme. Safe for concurrent use.
type Resolver struct {
	// mu is held for reading during a provider call, so CloseAll waits for
	// in-flight resolutions instead of closing a provider under them.
	mu        sync.RWMutex
	providers map[string]Provider
	order     []Provider
	closed    bool
}

// NewResolver registers providers by Scheme(). A nil provider or a scheme not
// matching ^[a-z][a-z0-9]*$ wraps ErrInvalidProvider; two providers with the
// same scheme wrap ErrDuplicateScheme.
func NewResolver(providers ...Provider) (*Resolver, error) {
	r := &Resolver{providers: make(map[string]Provider, len(providers))}
	for i, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("provider %d is nil: %w", i, ErrInvalidProvider)
		}
		scheme := p.Scheme()
		if !isScheme(scheme) {
			return nil, fmt.Errorf("provider %d scheme must match [a-z][a-z0-9]*: %w", i, ErrInvalidProvider)
		}
		if _, dup := r.providers[scheme]; dup {
			return nil, fmt.Errorf("scheme %s: %w", scheme, ErrDuplicateScheme)
		}
		r.providers[scheme] = p
		r.order = append(r.order, p)
	}
	return r, nil
}

// Resolve parses ref with ParseRef (errors wrap ErrInvalidRef) then calls
// ResolveRef.
func (r *Resolver) Resolve(ctx context.Context, ref string) (Secret, error) {
	parsed, err := ParseRef(ref)
	if err != nil {
		return Secret{}, err
	}
	return r.ResolveRef(ctx, parsed)
}

// ResolveRef calls the provider registered for ref.Scheme. It returns an
// error wrapping ctx.Err() when ctx is already done, ErrClosed after
// CloseAll, ErrNoProvider when no provider serves the scheme (the provider is
// not called in these cases), or the provider error wrapped with %w. A
// non-empty Secret returned together with an error is wiped and the zero
// Secret is returned.
func (r *Resolver) ResolveRef(ctx context.Context, ref Ref) (Secret, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, fmt.Errorf("resolve secret: %w", err)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return Secret{}, ErrClosed
	}
	p, ok := r.providers[ref.Scheme]
	if !ok {
		// The scheme of a hand-built Ref is not trusted: not echoed.
		return Secret{}, ErrNoProvider
	}
	s, err := p.Resolve(ctx, ref)
	if err != nil {
		s.Wipe()
		return Secret{}, fmt.Errorf("resolve %s secret: %w", ref.Scheme, err)
	}
	return s, nil
}

// CloseAll closes every provider exactly once, even when some fail, and
// returns their errors joined. Later calls return nil and close nothing.
func (r *Resolver) CloseAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var errs []error
	for _, p := range r.order {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s provider: %w", p.Scheme(), err))
		}
	}
	return errors.Join(errs...)
}

// isScheme reports whether s matches ^[a-z][a-z0-9]*$.
func isScheme(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
