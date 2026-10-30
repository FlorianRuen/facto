//go:build e2e

// Package e2efile is the e2e-only file secret provider (ADR 0009 A3, J1
// T17): e2e://<item>/<field> resolves to the content of
// <dir>/<item>/<field>, a 0600 file in a private directory, read through
// internal/fsx. The package exists only in builds with -tags e2e and is
// registered only by a //go:build e2e file of cmd/facto; `make
// release-e2e-check` proves the release binary lacks it.
package e2efile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"path/filepath"
	"runtime"
	"sync/atomic"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Scheme is the reference scheme served: e2e://<item>/<field>.
const Scheme = secret.SchemeE2E

// MaxSize caps a secret file.
const MaxSize = 64 << 10

// Sentinel is referenced by the e2e registration file of cmd/facto so the
// linker keeps it: the release check's `go tool nm` self-test finds it in an
// e2e binary and proves it absent from a release one. Not a secret.
var Sentinel = "facto e2e-only file secret provider"

// errTooLarge reports a secret file over MaxSize.
var errTooLarge = errors.New("e2efile: secret file too large")

// Provider is a secret.Provider reading <dir>/<item>/<field> through
// internal/fsx. Safe for concurrent use; renders as secret.Masked.
type Provider struct {
	parent string // directory holding the secrets directory
	base   string // secrets directory name inside parent
	closed atomic.Bool
}

var _ secret.Provider = (*Provider)(nil)

// New serves dir, which must exist and be a private directory: a
// group/world bit wraps fsx.ErrInsecurePerms, a symlink or a non-directory
// wraps fsx.ErrNotDir, a missing dir wraps fs.ErrNotExist.
func New(dir string) (*Provider, error) {
	dir = filepath.Clean(dir)
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	root, err := fsx.Open(parent)
	if err != nil {
		return nil, fmt.Errorf("e2efile: %w", err)
	}
	defer func() { _ = root.Close() }() // read-only use
	fi, err := root.Lstat(base)
	if err != nil {
		return nil, fmt.Errorf("e2efile: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("e2efile: secrets dir mode %v: %w", fi.Mode().Type(), fsx.ErrNotDir)
	}
	if err := fsx.CheckPrivate(dir); err != nil {
		return nil, fmt.Errorf("e2efile: %w", err)
	}
	return &Provider{parent: parent, base: base}, nil
}

// Scheme returns Scheme.
func (p *Provider) Scheme() string { return Scheme }

// Resolve returns the content of <dir>/<item>/<field>, a fresh Secret the
// caller owns. ref.Scheme must be Scheme and Item and Field single segments
// [A-Za-z0-9._-]+ other than "." and ".." (else secret.ErrInvalidRef, no
// file access). A done ctx wraps ctx.Err(). A missing or empty file wraps
// secret.ErrSecretNotFound; a symlink wraps fsx.ErrNotRegular; a
// group/world-readable file wraps fsx.ErrInsecurePerms; a file over MaxSize
// is refused. After Close it returns secret.ErrClosed. Errors never carry
// the content.
func (p *Provider) Resolve(ctx context.Context, ref secret.Ref) (secret.Secret, error) {
	if p.closed.Load() {
		return secret.Secret{}, secret.ErrClosed
	}
	if err := validate(ref); err != nil {
		return secret.Secret{}, err
	}
	if err := ctx.Err(); err != nil {
		return secret.Secret{}, fmt.Errorf("e2efile: %w", err)
	}
	parent, err := fsx.Open(p.parent)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("e2efile: %w", err)
	}
	defer func() { _ = parent.Close() }() // read-only use
	dir, err := parent.OpenDir(p.base)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("e2efile: %w", err)
	}
	defer func() { _ = dir.Close() }() // read-only use
	b, err := readPrivate(dir, ref.Item+"/"+ref.Field)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return secret.Secret{}, fmt.Errorf("e2efile: %w", secret.ErrSecretNotFound)
	case err != nil:
		return secret.Secret{}, err
	case len(b) == 0:
		return secret.Secret{}, fmt.Errorf("e2efile: empty file: %w", secret.ErrSecretNotFound)
	}
	return secret.New(b), nil
}

// readPrivate reads name from dir: a regular file without group/world bits
// of at most MaxSize bytes. The buffer is wiped on error.
func readPrivate(dir *fsx.Root, name string) ([]byte, error) {
	f, err := dir.OpenRegular(name)
	if err != nil {
		return nil, fmt.Errorf("e2efile: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("e2efile: stat: %w", err)
	}
	if insecure(fi.Mode()) {
		return nil, fmt.Errorf("e2efile: secret file mode %#o: %w", fi.Mode().Perm(), fsx.ErrInsecurePerms)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		clear(b)
		return nil, fmt.Errorf("e2efile: read: %w", err)
	}
	if len(b) > MaxSize {
		clear(b)
		return nil, errTooLarge
	}
	return b, nil
}

// Close makes every later Resolve fail with secret.ErrClosed. Idempotent.
func (p *Provider) Close() error {
	p.closed.Store(true)
	return nil
}

// String renders the provider as secret.Masked.
func (p *Provider) String() string { return secret.Masked }

// GoString renders the provider as secret.Masked.
func (p *Provider) GoString() string { return secret.Masked }

// Format renders the provider as secret.Masked for every verb.
func (p *Provider) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, secret.Masked) }

// MarshalJSON renders the provider as secret.Masked.
func (p *Provider) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(secret.Masked)
	if err != nil {
		return nil, fmt.Errorf("e2efile: %w", err)
	}
	return b, nil
}

// LogValue renders the provider as secret.Masked.
func (p *Provider) LogValue() slog.Value { return slog.StringValue(secret.Masked) }

// validate accepts only e2e refs whose item and field are single safe
// segments, the form secret.ParseRef returns in an e2e build.
func validate(ref secret.Ref) error {
	if ref.Scheme != Scheme {
		return fmt.Errorf("%w: e2efile: wrong scheme", secret.ErrInvalidRef)
	}
	parsed, err := secret.ParseRef(ref.String())
	if err != nil {
		return fmt.Errorf("e2efile: %w", err)
	}
	if parsed != ref {
		return fmt.Errorf("%w: e2efile: not canonical", secret.ErrInvalidRef)
	}
	return nil
}

// insecure reports group or world permission bits (POSIX only: Windows
// modes do not carry them).
func insecure(m fs.FileMode) bool {
	return runtime.GOOS != "windows" && m.Perm()&0o077 != 0
}
