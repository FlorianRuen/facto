package secret

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	// Resolve returns the secret ref points to. It must honour ctx:
	// CloseAll cancels the ctx of in-flight calls and does not wait for
	// them. It returns a fresh Secret the caller owns, never a cached one:
	// copies share storage, so a caller's Wipe would clear the cache too
	// (and the Resolver wipes a Secret that arrives after CloseAll).
	Resolve(ctx context.Context, ref Ref) (Secret, error)
	// Close locks the backend and wipes session keys. It may be called while
	// a Resolve is still in flight (a provider that ignores ctx).
	Close() error
}

// Resolver dispatches references to the provider registered for their
// scheme. Safe for concurrent use.
type Resolver struct {
	// providers and order are set by NewResolver and never change.
	providers map[string]Provider
	order     []Provider

	// mu guards closed, inflight and next. It is never held during a
	// provider call, so a provider that hangs cannot block CloseAll.
	mu     sync.Mutex
	closed bool
	// inflight holds the cancel function of every provider call in
	// progress; CloseAll cancels them all.
	inflight map[uint64]context.CancelFunc
	next     uint64
}

// NewResolver registers providers by Scheme(). A nil provider or a scheme not
// matching ^[a-z][a-z0-9]*$ wraps ErrInvalidProvider; two providers with the
// same scheme wrap ErrDuplicateScheme.
func NewResolver(providers ...Provider) (*Resolver, error) {
	r := &Resolver{
		providers: make(map[string]Provider, len(providers)),
		inflight:  map[uint64]context.CancelFunc{},
	}
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

// ResolveRef calls the provider registered for ref.Scheme. A Bitwarden or
// keyring Ref must be in the form ParseRef returns (wraps ErrInvalidRef
// otherwise; an upper-case UUID is lowered). It returns an
// error wrapping ctx.Err() when ctx is already done, ErrClosed after
// CloseAll, ErrNoProvider when no provider serves the scheme (the provider is
// not called in these cases), or the provider error wrapped with %w. A
// non-empty Secret returned together with an error is wiped and the zero
// Secret is returned. A call still in its provider when CloseAll runs has its
// ctx cancelled and returns ErrClosed whenever the provider answers; a Secret
// the provider hands back after CloseAll is wiped.
func (r *Resolver) ResolveRef(ctx context.Context, ref Ref) (Secret, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, fmt.Errorf("resolve secret: %w", err)
	}
	p, ok := r.providers[ref.Scheme]
	ref, refErr := canonical(ref)
	callCtx, done, err := r.begin(ctx)
	if err != nil {
		return Secret{}, err
	}
	defer done()
	switch {
	case !ok:
		// The scheme of a hand-built Ref is not trusted: not echoed.
		return Secret{}, ErrNoProvider
	case refErr != nil:
		return Secret{}, refErr
	}
	s, err := p.Resolve(callCtx, ref)
	if r.isClosed() {
		s.Wipe()
		return Secret{}, ErrClosed
	}
	if err != nil {
		s.Wipe()
		return Secret{}, fmt.Errorf("resolve %s secret: %w", ref.Scheme, err)
	}
	return s, nil
}

// begin registers one provider call: it returns ErrClosed after CloseAll,
// the ctx error when ctx is done, or a ctx that CloseAll cancels and the
// function that unregisters the call.
func (r *Resolver) begin(ctx context.Context) (context.Context, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("resolve secret: %w", err)
	}
	callCtx, cancel := context.WithCancel(ctx)
	id := r.next
	r.next++
	r.inflight[id] = cancel
	return callCtx, func() {
		cancel()
		r.mu.Lock()
		delete(r.inflight, id)
		r.mu.Unlock()
	}, nil
}

func (r *Resolver) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// CloseAll closes every provider exactly once, even when some fail, and
// returns their errors joined. Later calls return nil and close nothing. It
// does not wait for in-flight resolutions: it cancels their ctx, so a
// provider that hangs (a keyring daemon that never answers) cannot keep the
// password manager unlocked. Such a resolution returns ErrClosed and its
// late Secret is wiped.
func (r *Resolver) CloseAll() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	for _, cancel := range r.inflight {
		cancel()
	}
	r.mu.Unlock()
	var errs []error
	for _, p := range r.order {
		if err := p.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s provider: %w", p.Scheme(), err))
		}
	}
	return errors.Join(errs...)
}

// canonical re-applies the ParseRef checks to a Ref of a known scheme, so a
// hand-built Ref cannot reach a provider with an item name, a field outside
// the set or a keyring item holding "/". Other schemes are left to their
// provider.
func canonical(ref Ref) (Ref, error) {
	if ref.Scheme != SchemeBitwarden && ref.Scheme != SchemeKeyring {
		return ref, nil
	}
	c, err := ParseRef(ref.String())
	if err != nil {
		return Ref{}, err
	}
	if c.Field != ref.Field || !strings.EqualFold(c.Item, ref.Item) {
		return Ref{}, invalid("hand-built reference does not match its canonical form")
	}
	return c, nil
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
