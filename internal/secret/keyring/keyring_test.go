package keyring_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// fakeBackend stands in for the OS keyring (go-keyring). The real keyring is
// never touched by tests.
type fakeBackend struct {
	values map[[2]string]string // {service, user} -> value
	err    error                // returned by every Get when set
	// valueWithErr is returned together with err (a misbehaving backend).
	valueWithErr string

	mu    sync.Mutex
	calls [][2]string
}

func (b *fakeBackend) Get(service, user string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, [2]string{service, user})
	if b.err != nil {
		return b.valueWithErr, b.err
	}
	v, ok := b.values[[2]string{service, user}]
	if !ok {
		return "", fmt.Errorf("fake keyring: %w", keyring.ErrNotFound)
	}
	return v, nil
}

func (b *fakeBackend) callLog() [][2]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][2]string(nil), b.calls...)
}

// The provider depends on this small consumer-side interface, not on
// go-keyring directly.
var _ keyring.Backend = (*fakeBackend)(nil)

// It satisfies the core provider contract.
var _ secret.Provider = (*keyring.Provider)(nil)

func mustRef(t *testing.T, s string) secret.Ref {
	t.Helper()
	r, err := secret.ParseRef(s)
	if err != nil {
		t.Fatalf("ParseRef(%q): %v", s, err)
	}
	return r
}

func TestKeyring_Scheme(t *testing.T) {
	t.Parallel()
	p := keyring.New(&fakeBackend{})
	if got := p.Scheme(); got != "keyring" {
		t.Fatalf("Scheme() = %q, want %q", got, "keyring")
	}
	if _, err := secret.NewResolver(p); err != nil {
		t.Fatalf("NewResolver(keyring provider): %v", err)
	}
}

func TestKeyring_Resolves(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		ref         string
		wantService string
		wantUser    string
		want        string
	}{
		{name: "simple key", ref: "keyring://facto/ileo-password", wantService: "facto", wantUser: "ileo-password", want: "synthetic-value-1"},
		{name: "nested key (spec example)", ref: "keyring://facto/ileo/login", wantService: "facto", wantUser: "ileo/login", want: "synthetic-login"},
		{name: "dots and underscores", ref: "keyring://facto.app/drive_refresh.token", wantService: "facto.app", wantUser: "drive_refresh.token", want: "synthetic-refresh"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := &fakeBackend{values: map[[2]string]string{{tc.wantService, tc.wantUser}: tc.want}}
			s, err := keyring.New(b).Resolve(t.Context(), mustRef(t, tc.ref))
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.ref, err)
			}
			if got := s.Expose(); got != tc.want {
				t.Errorf("Resolve(%q) = %q, want %q", tc.ref, got, tc.want)
			}
			calls := b.callLog()
			if len(calls) != 1 || calls[0] != [2]string{tc.wantService, tc.wantUser} {
				t.Errorf("backend calls = %q, want exactly Get(%q, %q)", calls, tc.wantService, tc.wantUser)
			}
		})
	}
}

func TestKeyring_ThroughResolver(t *testing.T) {
	t.Parallel()
	b := &fakeBackend{values: map[[2]string]string{{"facto", "ileo/login"}: "synthetic-login"}}
	r, err := secret.NewResolver(keyring.New(b))
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	s, err := r.Resolve(t.Context(), "keyring://facto/ileo/login")
	if err != nil || s.Expose() != "synthetic-login" {
		t.Fatalf("Resolve = %q, %v; want synthetic-login, nil", s.Expose(), err)
	}
}

func TestKeyring_RejectsBadInput(t *testing.T) {
	t.Parallel()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		ref     secret.Ref
		wantErr error
	}{
		{name: "other scheme", ctx: context.Background(), ref: secret.Ref{Scheme: "bw", Item: "3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90", Field: "password"}, wantErr: secret.ErrInvalidRef},
		{name: "zero ref", ctx: context.Background(), ref: secret.Ref{}, wantErr: secret.ErrInvalidRef},
		{name: "empty service", ctx: context.Background(), ref: secret.Ref{Scheme: "keyring", Item: "", Field: "k"}, wantErr: secret.ErrInvalidRef},
		{name: "empty key", ctx: context.Background(), ref: secret.Ref{Scheme: "keyring", Item: "facto", Field: ""}, wantErr: secret.ErrInvalidRef},
		{name: "dotdot key built by hand", ctx: context.Background(), ref: secret.Ref{Scheme: "keyring", Item: "facto", Field: "../k"}, wantErr: secret.ErrInvalidRef},
		{name: "canceled context", ctx: canceled, ref: secret.Ref{Scheme: "keyring", Item: "facto", Field: "k"}, wantErr: context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := &fakeBackend{values: map[[2]string]string{{"facto", "k"}: "synthetic"}}
			s, err := keyring.New(b).Resolve(tc.ctx, tc.ref)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve(%+v) error = %v, want %v", tc.ref, err, tc.wantErr)
			}
			if !s.IsZero() {
				t.Error("non-empty Secret returned with an error")
			}
			if calls := b.callLog(); len(calls) != 0 {
				t.Errorf("backend called %q, want no call", calls)
			}
		})
	}
}

func TestKeyring_NotFoundIsErrSecretNotFound(t *testing.T) {
	t.Parallel()
	errBackend := errors.New("dbus: secret service unavailable")
	tests := []struct {
		name         string
		backend      *fakeBackend
		wantNotFound bool
		wantIs       error
	}{
		{name: "missing entry", backend: &fakeBackend{}, wantNotFound: true, wantIs: keyring.ErrNotFound},
		{name: "bare backend ErrNotFound", backend: &fakeBackend{err: keyring.ErrNotFound}, wantNotFound: true, wantIs: keyring.ErrNotFound},
		{name: "empty value is not a usable secret", backend: &fakeBackend{values: map[[2]string]string{{"facto", "k"}: ""}}, wantNotFound: true},
		{name: "other backend error is not not-found", backend: &fakeBackend{err: errBackend}, wantNotFound: false, wantIs: errBackend},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := keyring.New(tc.backend).Resolve(t.Context(), mustRef(t, "keyring://facto/k"))
			if err == nil {
				t.Fatal("Resolve: nil error")
			}
			if got := errors.Is(err, secret.ErrSecretNotFound); got != tc.wantNotFound {
				t.Errorf("errors.Is(%v, ErrSecretNotFound) = %v, want %v", err, got, tc.wantNotFound)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("error %v does not wrap %v", err, tc.wantIs)
			}
			if !s.IsZero() {
				t.Error("non-empty Secret returned with an error")
			}
		})
	}
}

func TestKeyring_ValueNeverInError(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	tests := []struct {
		name    string
		backend *fakeBackend
	}{
		{
			name:    "backend returns the value together with an error",
			backend: &fakeBackend{err: errors.New("keychain: partial read"), valueWithErr: canary},
		},
		{
			name:    "backend error message echoes the value",
			backend: &fakeBackend{err: fmt.Errorf("security: item data %q could not be decoded", canary)},
		},
		{
			name:    "backend not-found message echoes the value",
			backend: &fakeBackend{err: fmt.Errorf("lookup %s: %w", canary, keyring.ErrNotFound)},
		},
	}
	var rendered strings.Builder
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := keyring.New(tc.backend).Resolve(t.Context(), mustRef(t, "keyring://facto/ileo/password"))
			if err == nil {
				t.Fatal("Resolve: nil error")
			}
			if !s.IsZero() {
				t.Error("non-empty Secret returned with an error")
			}
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
				out := fmt.Sprintf(verb, err)
				fmt.Fprintf(&rendered, "%s %s: %s\n", tc.name, verb, out)
				if strings.Contains(out, canary) {
					t.Errorf("error formatted with %s contains the secret value: %s", verb, out)
				}
			}
		})
	}
	writeArtifact(t, "keyring-errors.txt", rendered.String())
}

func TestKeyring_CloseIsIdempotent(t *testing.T) {
	t.Parallel()
	p := keyring.New(&fakeBackend{})
	for i := range 2 {
		if err := p.Close(); err != nil {
			t.Fatalf("Close #%d = %v, want nil", i+1, err)
		}
	}
}

// writeArtifact stores rendered errors under ArtifactDir so make leakcheck
// greps them for canaries.
func writeArtifact(t *testing.T, name, content string) {
	t.Helper()
	r, err := fsx.Open(testsecrets.ArtifactDir(t))
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, []byte(content)); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
}
