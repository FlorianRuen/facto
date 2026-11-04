//go:build e2e

// Tests for the e2e-only file secret provider (J1 T17, ADR 0009 A3). The
// package exists only in builds with -tags e2e and is registered only by a
// //go:build e2e file of cmd/facto; `make release-e2e-check` proves the
// release binary lacks it. Every value is a synthetic canary.
//
// Expected API (implementer: follow exactly; every file of the package
// carries //go:build e2e):
//
//	package e2efile
//
//	// Scheme is the reference scheme served: e2e://<item>/<field>.
//	const Scheme = "e2e"
//
//	// Sentinel is referenced by the e2e registration file of cmd/facto so
//	// the linker keeps it (`go tool nm` self-test of the release check).
//	var Sentinel = "…" // any non-empty, non-secret text
//
//	// Provider is a secret.Provider reading <dir>/<item>/<field> through
//	// internal/fsx. Safe for concurrent use; renders as secret.Masked.
//	type Provider struct{ … }
//
//	// New serves dir, which must exist and be a private directory: a
//	// group/world bit wraps fsx.ErrInsecurePerms, a symlink or a
//	// non-directory wraps fsx.ErrNotDir.
//	func New(dir string) (*Provider, error)
//
//	func (p *Provider) Scheme() string // Scheme
//
//	// Resolve returns the content of <dir>/<item>/<field>, a fresh Secret
//	// the caller owns. ref.Scheme must be Scheme and Item and Field single
//	// segments [A-Za-z0-9._-]+ other than "." and ".." (else
//	// secret.ErrInvalidRef, no file access). A done ctx wraps ctx.Err().
//	// A missing or empty file wraps secret.ErrSecretNotFound; a symlink
//	// wraps fsx.ErrNotRegular; a group/world-readable file wraps
//	// fsx.ErrInsecurePerms; a file over MaxSize is refused. After Close it
//	// returns secret.ErrClosed. Errors never carry the content.
//	func (p *Provider) Resolve(ctx context.Context, ref secret.Ref) (secret.Secret, error)
//
//	// MaxSize caps a secret file.
//	const MaxSize = 64 << 10
//
//	// Close is idempotent.
//	func (p *Provider) Close() error
//
// In an e2e build secret.ParseRef also accepts e2e://<item>/<field> (same
// segment rules), so secret.Resolver.Resolve reaches the provider.
package e2efile_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/e2efile"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

var _ secret.Provider = (*e2efile.Provider)(nil)

// fixture is a private secrets dir holding synthetic-item/password.
type fixture struct {
	dir    string
	canary string
	p      *e2efile.Provider
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := t.TempDir()
	root, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirPrivate("secrets/synthetic-item"); err != nil {
		t.Fatalf("setup mkdir: %v", err)
	}
	canary := testsecrets.Canary(t, testsecrets.Password)
	if err := root.WriteAtomic(t.Context(), "secrets/synthetic-item/password", []byte(canary)); err != nil {
		t.Fatalf("setup write: %v", err)
	}
	dir := filepath.Join(base, "secrets")
	p, err := e2efile.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return &fixture{dir: dir, canary: canary, p: p}
}

func ref(item, field string) secret.Ref {
	return secret.Ref{Scheme: e2efile.Scheme, Item: item, Field: field}
}

func TestProvider_SchemeAndSentinel(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if got := f.p.Scheme(); got != "e2e" {
		t.Fatalf("Scheme() = %q, want e2e", got)
	}
	if e2efile.Sentinel == "" {
		t.Fatal("Sentinel is empty: the release check's nm self-test needs a linked symbol")
	}
}

func TestProvider_ResolvesFile(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	got, err := f.p.Resolve(t.Context(), ref("synthetic-item", "password"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	defer got.Wipe()
	if got.Expose() != f.canary {
		t.Fatal("Resolve returned another value than the file content")
	}
	// Through the resolver, from the reference text of a config.
	r, err := secret.NewResolver(f.p)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	got2, err := r.Resolve(t.Context(), "e2e://synthetic-item/password")
	if err != nil {
		t.Fatalf("Resolver.Resolve(e2e://…): %v", err)
	}
	defer got2.Wipe()
	if got2.Expose() != f.canary {
		t.Fatal("Resolver.Resolve returned another value than the file content")
	}
}

func TestProvider_Errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ref     secret.Ref
		ctx     func(t *testing.T) context.Context
		wantErr error
	}{
		{name: "missing item", ref: ref("other-item", "password"), wantErr: secret.ErrSecretNotFound},
		{name: "missing field", ref: ref("synthetic-item", "username"), wantErr: secret.ErrSecretNotFound},
		{name: "traversal item", ref: ref("..", "password"), wantErr: secret.ErrInvalidRef},
		{name: "traversal field", ref: ref("synthetic-item", "../../etc"), wantErr: secret.ErrInvalidRef},
		{name: "nested field", ref: ref("synthetic-item", "a/b"), wantErr: secret.ErrInvalidRef},
		{name: "absolute item", ref: ref("/etc", "x"), wantErr: secret.ErrInvalidRef},
		{name: "empty item", ref: ref("", "password"), wantErr: secret.ErrInvalidRef},
		{name: "dot field", ref: ref("synthetic-item", "."), wantErr: secret.ErrInvalidRef},
		{name: "backslash", ref: ref("synthetic-item", `..\..\x`), wantErr: secret.ErrInvalidRef},
		{name: "other scheme", ref: secret.Ref{Scheme: secret.SchemeKeyring, Item: "synthetic-item", Field: "password"}, wantErr: secret.ErrInvalidRef},
		{
			name: "done ctx",
			ref:  ref("synthetic-item", "password"),
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			},
			wantErr: context.Canceled,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			ctx := t.Context()
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}
			got, err := f.p.Resolve(ctx, tc.ref)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve(%q) = %v, want %v", tc.ref.String(), err, tc.wantErr)
			}
			if !got.IsZero() {
				t.Fatal("Resolve returned a value together with an error")
			}
		})
	}
}

// TestProvider_RefusesPlantedFiles: symlinked, loosened, empty or oversized
// secret files are refused and their content never returned.
func TestProvider_RefusesPlantedFiles(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		return // POSIX modes and symlinks only
	}
	tests := []struct {
		name    string
		plant   func(t *testing.T, path string)
		wantErr error // nil = any error
	}{
		{
			name: "symlink to an attacker file",
			plant: func(t *testing.T, path string) {
				target := filepath.Join(t.TempDir(), "planted")
				writePlanted(t, target, []byte(testsecrets.Canary(t, testsecrets.Token)))
				if err := os.Remove(path); err != nil {
					t.Fatalf("setup remove: %v", err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("setup symlink: %v", err)
				}
			},
			wantErr: fsx.ErrNotRegular,
		},
		{
			name: "world readable",
			plant: func(t *testing.T, path string) {
				loose := fs.FileMode(0o644) // the insecure mode under test
				if err := os.Chmod(path, loose); err != nil {
					t.Fatalf("setup chmod: %v", err)
				}
			},
			wantErr: fsx.ErrInsecurePerms,
		},
		{
			name: "empty",
			plant: func(t *testing.T, path string) {
				writePlanted(t, path, nil)
			},
			wantErr: secret.ErrSecretNotFound,
		},
		{
			name: "oversized",
			plant: func(t *testing.T, path string) {
				writePlanted(t, path, bytes.Repeat([]byte("A"), e2efile.MaxSize+1))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			tc.plant(t, filepath.Join(f.dir, "synthetic-item", "password"))
			got, err := f.p.Resolve(t.Context(), ref("synthetic-item", "password"))
			if err == nil {
				t.Fatal("Resolve accepted a planted file")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve = %v, want %v", err, tc.wantErr)
			}
			if !got.IsZero() {
				t.Fatal("Resolve returned a value together with an error")
			}
		})
	}
}

func TestNew_RefusesUnsafeDir(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		return // POSIX modes and symlinks only
	}
	tests := []struct {
		name    string
		prepare func(t *testing.T, dir string)
		wantErr error
	}{
		{name: "missing", prepare: func(*testing.T, string) {}, wantErr: fs.ErrNotExist},
		{
			name: "group readable",
			prepare: func(t *testing.T, dir string) {
				if err := os.Mkdir(dir, 0o750); err != nil {
					t.Fatalf("setup mkdir: %v", err)
				}
				loose := fs.FileMode(0o750) // the insecure mode under test
				if err := os.Chmod(dir, loose); err != nil {
					t.Fatalf("setup chmod: %v", err)
				}
			},
			wantErr: fsx.ErrInsecurePerms,
		},
		{
			name: "symlink",
			prepare: func(t *testing.T, dir string) {
				target := t.TempDir()
				if err := os.Symlink(target, dir); err != nil {
					t.Fatalf("setup symlink: %v", err)
				}
			},
			wantErr: fsx.ErrNotDir,
		},
		{
			name: "regular file",
			prepare: func(t *testing.T, dir string) {
				writePlanted(t, dir, []byte("synthetic"))
			},
			wantErr: fsx.ErrNotDir,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "secrets")
			tc.prepare(t, dir)
			if _, err := e2efile.New(dir); !errors.Is(err, tc.wantErr) {
				t.Fatalf("New = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestProvider_ClosedRefuses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if err := f.p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := f.p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := f.p.Resolve(t.Context(), ref("synthetic-item", "password")); !errors.Is(err, secret.ErrClosed) {
		t.Fatalf("Resolve after Close = %v, want ErrClosed", err)
	}
}

// TestProvider_SecretNeverRendered: neither the provider nor its errors
// render a secret value.
func TestProvider_SecretNeverRendered(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	got, err := f.p.Resolve(t.Context(), ref("synthetic-item", "password"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	defer got.Wipe()
	out := fmt.Sprintf("%v %+v %#v %s %q %v", f.p, f.p, f.p, f.p, f.p, got)
	if runtime.GOOS != "windows" {
		loose := fs.FileMode(0o644) // the insecure mode under test
		if err := os.Chmod(filepath.Join(f.dir, "synthetic-item", "password"), loose); err != nil {
			t.Fatalf("setup chmod: %v", err)
		}
		if _, err := f.p.Resolve(t.Context(), ref("synthetic-item", "password")); err != nil {
			out += err.Error()
		}
	}
	if strings.Contains(out, f.canary) {
		t.Fatalf("secret rendered: %s", out)
	}
}

// writePlanted writes path through fsx (its parent must exist), then sets
// mode 0600: the tests plant hostile files on purpose.
func writePlanted(t *testing.T, path string, data []byte) {
	t.Helper()
	root, err := fsx.Open(filepath.Dir(path))
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(t.Context(), filepath.Base(path), data); err != nil {
		t.Fatalf("setup write: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("setup chmod: %v", err)
	}
}
