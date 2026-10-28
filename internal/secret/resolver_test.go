package secret_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// fakeProvider is an in-memory Provider recording its calls.
type fakeProvider struct {
	scheme   string
	values   map[secret.Ref]string
	closeErr error
	// leakOnErr makes Resolve return a non-empty Secret together with an
	// error; the Secret is kept in leaked so the test can check it was wiped.
	leakOnErr string

	mu       sync.Mutex
	resolved []secret.Ref
	closes   int
	leaked   secret.Secret
}

func (p *fakeProvider) Scheme() string { return p.scheme }

func (p *fakeProvider) Resolve(_ context.Context, ref secret.Ref) (secret.Secret, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resolved = append(p.resolved, ref)
	if p.leakOnErr != "" {
		p.leaked = secret.FromString(p.leakOnErr)
		return p.leaked, errors.New("provider failed half way")
	}
	v, ok := p.values[ref]
	if !ok {
		return secret.Secret{}, fmt.Errorf("fake %s: %w", p.scheme, secret.ErrSecretNotFound)
	}
	return secret.FromString(v), nil
}

func (p *fakeProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
	return p.closeErr
}

func (p *fakeProvider) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.resolved)
}

func (p *fakeProvider) closeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closes
}

func newProviders() (bw, kr *fakeProvider) {
	bw = &fakeProvider{scheme: "bw", values: map[secret.Ref]string{
		{Scheme: "bw", Item: itemUUID, Field: "password"}: "value-from-bw",
		{Scheme: "bw", Item: itemUUID, Field: "username"}: "user-from-bw",
	}}
	kr = &fakeProvider{scheme: "keyring", values: map[secret.Ref]string{
		{Scheme: "keyring", Item: "facto", Field: "ileo/login"}: "value-from-keyring",
	}}
	return bw, kr
}

func mustResolver(t *testing.T, ps ...secret.Provider) *secret.Resolver {
	t.Helper()
	r, err := secret.NewResolver(ps...)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func TestResolver_DispatchesByScheme(t *testing.T) {
	t.Parallel()
	bw, kr := newProviders()
	r := mustResolver(t, bw, kr)
	tests := []struct {
		ref       string
		want      string
		wantBW    int
		wantKeyrg int
	}{
		{ref: "bw://" + itemUUID + "/password", want: "value-from-bw", wantBW: 1},
		{ref: "bw://" + strings.ToUpper(itemUUID) + "/username", want: "user-from-bw", wantBW: 2},
		{ref: "keyring://facto/ileo/login", want: "value-from-keyring", wantBW: 2, wantKeyrg: 1},
	}
	for _, tc := range tests {
		s, err := r.Resolve(t.Context(), tc.ref)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.ref, err)
		}
		if got := s.Expose(); got != tc.want {
			t.Errorf("Resolve(%q) = %q, want %q", tc.ref, got, tc.want)
		}
		if bw.calls() != tc.wantBW || kr.calls() != tc.wantKeyrg {
			t.Errorf("after %q: bw calls %d, keyring calls %d; want %d, %d",
				tc.ref, bw.calls(), kr.calls(), tc.wantBW, tc.wantKeyrg)
		}
	}
	// Providers receive the parsed, canonical Ref.
	want := secret.Ref{Scheme: "bw", Item: itemUUID, Field: "username"}
	if got := bw.resolved[1]; got != want {
		t.Errorf("provider got %+v, want canonical %+v", got, want)
	}

	// ResolveRef skips parsing.
	s, err := r.ResolveRef(t.Context(), secret.Ref{Scheme: "keyring", Item: "facto", Field: "ileo/login"})
	if err != nil || s.Expose() != "value-from-keyring" {
		t.Errorf("ResolveRef = %q, %v; want value-from-keyring, nil", s.Expose(), err)
	}
}

func TestResolver_Errors(t *testing.T) {
	t.Parallel()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		ref     string
		wantErr error
	}{
		{name: "invalid ref", ctx: context.Background(), ref: "plaintext-value", wantErr: secret.ErrInvalidRef},
		{name: "unknown scheme", ctx: context.Background(), ref: "op://vault/item/field", wantErr: secret.ErrInvalidRef},
		{name: "no provider registered", ctx: context.Background(), ref: "keyring://facto/ileo/login", wantErr: secret.ErrNoProvider},
		{name: "not found passes through", ctx: context.Background(), ref: "bw://" + itemUUID + "/totp", wantErr: secret.ErrSecretNotFound},
		{name: "canceled context", ctx: canceled, ref: "bw://" + itemUUID + "/password", wantErr: context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bw, _ := newProviders()
			r := mustResolver(t, bw) // keyring deliberately not registered
			s, err := r.Resolve(tc.ctx, tc.ref)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve(%q) error = %v, want %v", tc.ref, err, tc.wantErr)
			}
			if !s.IsZero() {
				t.Errorf("Resolve(%q) returned a non-empty Secret with an error", tc.ref)
			}
			if errors.Is(tc.wantErr, context.Canceled) && bw.calls() != 0 {
				t.Errorf("provider called %d times with a canceled context, want 0", bw.calls())
			}
		})
	}
}

func TestResolver_ResolveRefWithoutProvider(t *testing.T) {
	t.Parallel()
	bw, _ := newProviders()
	r := mustResolver(t, bw)
	_, err := r.ResolveRef(t.Context(), secret.Ref{Scheme: "keyring", Item: "facto", Field: "k"})
	if !errors.Is(err, secret.ErrNoProvider) {
		t.Fatalf("ResolveRef(keyring) error = %v, want ErrNoProvider", err)
	}
}

func TestResolver_WipesSecretReturnedWithError(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	p := &fakeProvider{scheme: "bw", leakOnErr: canary}
	r := mustResolver(t, p)
	s, err := r.Resolve(t.Context(), "bw://"+itemUUID+"/password")
	if err == nil {
		t.Fatal("Resolve: nil error, want the provider error")
	}
	if !s.IsZero() {
		t.Error("Resolve returned a non-empty Secret together with an error")
	}
	p.mu.Lock()
	leaked := p.leaked
	p.mu.Unlock()
	if !leaked.IsZero() {
		t.Error("Secret returned by the failing provider was not wiped")
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("error %q contains the secret", err)
	}
}

func TestNewResolver_Rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		providers []secret.Provider
		wantErr   error
	}{
		{name: "duplicate scheme", providers: []secret.Provider{&fakeProvider{scheme: "bw"}, &fakeProvider{scheme: "bw"}}, wantErr: secret.ErrDuplicateScheme},
		{name: "nil provider", providers: []secret.Provider{nil}, wantErr: secret.ErrInvalidProvider},
		{name: "typed nil provider scheme empty", providers: []secret.Provider{&fakeProvider{scheme: ""}}, wantErr: secret.ErrInvalidProvider},
		{name: "scheme with separator", providers: []secret.Provider{&fakeProvider{scheme: "bw://"}}, wantErr: secret.ErrInvalidProvider},
		{name: "uppercase scheme", providers: []secret.Provider{&fakeProvider{scheme: "BW"}}, wantErr: secret.ErrInvalidProvider},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, err := secret.NewResolver(tc.providers...)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NewResolver error = %v, want %v", err, tc.wantErr)
			}
			if r != nil {
				t.Errorf("NewResolver returned a resolver with an error")
			}
		})
	}
	if _, err := secret.NewResolver(); err != nil {
		t.Errorf("NewResolver() with no provider = %v, want nil (every ref then fails with ErrNoProvider)", err)
	}
}

func TestResolver_CloseAllClosesEveryProvider(t *testing.T) {
	t.Parallel()
	errBW := errors.New("bw lock failed")
	errOther := errors.New("other close failed")
	bw := &fakeProvider{scheme: "bw", closeErr: errBW}
	kr := &fakeProvider{scheme: "keyring"}
	other := &fakeProvider{scheme: "other", closeErr: errOther}
	r := mustResolver(t, bw, kr, other)

	err := r.CloseAll()
	if !errors.Is(err, errBW) || !errors.Is(err, errOther) {
		t.Fatalf("CloseAll error = %v, want both provider errors joined", err)
	}
	for _, p := range []*fakeProvider{bw, kr, other} {
		if n := p.closeCount(); n != 1 {
			t.Errorf("%s closed %d times, want 1 (even after another provider failed)", p.scheme, n)
		}
	}

	// Idempotent: nothing closed twice.
	if err := r.CloseAll(); err != nil {
		t.Errorf("second CloseAll = %v, want nil", err)
	}
	for _, p := range []*fakeProvider{bw, kr, other} {
		if n := p.closeCount(); n != 1 {
			t.Errorf("%s closed %d times after second CloseAll, want 1", p.scheme, n)
		}
	}

	// Closed resolver refuses to resolve without calling the provider.
	_, err = r.Resolve(t.Context(), "keyring://facto/ileo/login")
	if !errors.Is(err, secret.ErrClosed) {
		t.Errorf("Resolve after CloseAll error = %v, want ErrClosed", err)
	}
	if kr.calls() != 0 {
		t.Errorf("provider called %d times after CloseAll, want 0", kr.calls())
	}
}

func TestResolver_CloseAllNoError(t *testing.T) {
	t.Parallel()
	bw, kr := newProviders()
	r := mustResolver(t, bw, kr)
	if err := r.CloseAll(); err != nil {
		t.Fatalf("CloseAll = %v, want nil", err)
	}
	if bw.closeCount() != 1 || kr.closeCount() != 1 {
		t.Errorf("closes: bw %d, keyring %d; want 1, 1", bw.closeCount(), kr.closeCount())
	}
}

func TestResolver_ConcurrentResolveAndClose(t *testing.T) {
	t.Parallel()
	// Run with -race.
	bw, kr := newProviders()
	r := mustResolver(t, bw, kr)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			s, err := r.Resolve(context.Background(), "bw://"+itemUUID+"/password")
			if err != nil && !errors.Is(err, secret.ErrClosed) {
				t.Errorf("Resolve: %v", err)
			}
			s.Wipe()
		})
	}
	wg.Go(func() { _ = r.CloseAll() })
	wg.Wait()
	if bw.closeCount() != 1 {
		t.Errorf("bw closed %d times, want 1", bw.closeCount())
	}
}

// A hand-built Ref must not skip the checks ParseRef enforces: Bitwarden items
// by UUID only, the fixed field set, keyring segments without "/" or "..".
func TestResolver_ResolveRefRejectsNonCanonicalRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ref  secret.Ref
	}{
		{name: "bw item name instead of uuid", ref: secret.Ref{Scheme: "bw", Item: "--session=x EDF login", Field: "password"}},
		{name: "bw field outside the set", ref: secret.Ref{Scheme: "bw", Item: itemUUID, Field: "notes"}},
		{name: "bw empty field", ref: secret.Ref{Scheme: "bw", Item: itemUUID}},
		{name: "keyring item with slash", ref: secret.Ref{Scheme: "keyring", Item: "fa/cto", Field: "k"}},
		{name: "keyring dot-dot segment", ref: secret.Ref{Scheme: "keyring", Item: "facto", Field: "../k"}},
		{name: "keyring empty item", ref: secret.Ref{Scheme: "keyring", Field: "k"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bw, kr := newProviders()
			r := mustResolver(t, bw, kr)
			s, err := r.ResolveRef(t.Context(), tc.ref)
			if !errors.Is(err, secret.ErrInvalidRef) {
				t.Fatalf("ResolveRef(%+v) error = %v, want ErrInvalidRef", tc.ref, err)
			}
			if !s.IsZero() {
				t.Errorf("ResolveRef(%+v) returned a non-empty Secret with an error", tc.ref)
			}
			if n := bw.calls() + kr.calls(); n != 0 {
				t.Errorf("providers called %d times, want 0", n)
			}
		})
	}
}

// An upper-case UUID is canonicalized before it reaches the provider.
func TestResolver_ResolveRefCanonicalizesUUID(t *testing.T) {
	t.Parallel()
	bw, kr := newProviders()
	r := mustResolver(t, bw, kr)
	s, err := r.ResolveRef(t.Context(), secret.Ref{Scheme: "bw", Item: strings.ToUpper(itemUUID), Field: "password"})
	if err != nil || s.Expose() != "value-from-bw" {
		t.Fatalf("ResolveRef = %q, %v; want value-from-bw, nil", s.Expose(), err)
	}
	if got, want := bw.resolved[0], (secret.Ref{Scheme: "bw", Item: itemUUID, Field: "password"}); got != want {
		t.Errorf("provider got %+v, want canonical %+v", got, want)
	}
}
