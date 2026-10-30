//go:build e2e

// Package e2ekey is the e2e-only file key source of the session vault (ADR
// 0009 "Key source", decision A3, J1 T17): a vault.KeyBackend storing each
// session key in one 0600 file under a 0700 directory, every access through
// internal/fsx. It exists only in builds with -tags e2e and is registered
// only by a //go:build e2e file of cmd/facto; no config value or runtime
// string can select it. `make release-e2e-check` proves the release binary
// lacks it.
package e2ekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"runtime"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Sentinel is referenced by the e2e registration file of cmd/facto so the
// linker keeps it: `go tool nm` finds it in an e2e binary and the release
// check proves it absent from a release one. Not a secret.
var Sentinel = "facto e2e-only file key source"

// maxKeyFile caps a key file (a session key is 43 base64 characters).
const maxKeyFile = 4096

var (
	// errEmptyValue reports a Set with an empty value.
	errEmptyValue = errors.New("e2ekey: empty value")
	// errTooLarge reports a key file over maxKeyFile.
	errTooLarge = errors.New("e2ekey: key file too large")
)

// Source is a vault.KeyBackend over one 0600 file per reference under a
// 0700 directory, every access through internal/fsx. Safe for concurrent
// use (stateless between calls). Every rendering is secret.Masked.
type Source struct {
	parent string // directory holding the key directory
	base   string // key directory name inside parent
}

// New uses dir as the key directory, creating it 0700 through fsx when
// missing (its parent must exist). An existing dir with any group or world
// bit wraps fsx.ErrInsecurePerms; a symlink or a non-directory wraps
// fsx.ErrNotDir. Nothing is read at New.
func New(dir string) (*Source, error) {
	dir = filepath.Clean(dir)
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	root, err := fsx.Open(parent)
	if err != nil {
		return nil, fmt.Errorf("e2ekey: %w", err)
	}
	defer func() { _ = root.Close() }() // no write pending on the root itself
	fi, err := root.Lstat(base)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := root.MkdirPrivate(base); err != nil {
			return nil, fmt.Errorf("e2ekey: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("e2ekey: %w", err)
	case !fi.IsDir():
		return nil, fmt.Errorf("e2ekey: key dir mode %v: %w", fi.Mode().Type(), fsx.ErrNotDir)
	default:
		if err := fsx.CheckPrivate(dir); err != nil {
			return nil, fmt.Errorf("e2ekey: %w", err)
		}
	}
	return &Source{parent: parent, base: base}, nil
}

// Resolve returns the key stored for ref, a fresh Secret the caller owns.
// ref must be a canonical keyring ref (else secret.ErrInvalidRef, nothing
// touched); a done ctx wraps ctx.Err(); a missing or empty entry wraps
// secret.ErrSecretNotFound; a symlink wraps fsx.ErrNotRegular; a
// group/world-readable key file wraps fsx.ErrInsecurePerms. Errors never
// carry a key value.
func (s *Source) Resolve(ctx context.Context, ref secret.Ref) (secret.Secret, error) {
	name, err := precheck(ctx, ref)
	if err != nil {
		return secret.Secret{}, err
	}
	var out secret.Secret
	err = s.withDir(func(dir *fsx.Root) error {
		b, err := readPrivate(dir, name)
		if err != nil {
			return err
		}
		if len(b) == 0 {
			return fmt.Errorf("e2ekey: empty key file: %w", secret.ErrSecretNotFound)
		}
		out = secret.New(b)
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return secret.Secret{}, fmt.Errorf("e2ekey: %w", secret.ErrSecretNotFound)
	}
	if err != nil {
		return secret.Secret{}, err
	}
	return out, nil
}

// Set stores value for ref with fsx WriteAtomic (0600, parents 0700),
// replacing any previous entry. The caller keeps ownership of value. An
// invalid ref wraps secret.ErrInvalidRef, an empty value is refused, a done
// ctx wraps ctx.Err(); in these cases nothing is touched.
func (s *Source) Set(ctx context.Context, ref secret.Ref, value secret.Secret) error {
	name, err := precheck(ctx, ref)
	if err != nil {
		return err
	}
	if value.IsZero() {
		return errEmptyValue
	}
	return s.withDir(func(dir *fsx.Root) error {
		if err := dir.MkdirPrivate(path.Dir(name)); err != nil {
			return fmt.Errorf("e2ekey: %w", err)
		}
		b := []byte(value.Expose())
		defer clear(b)
		if err := dir.WriteAtomic(ctx, name, b); err != nil {
			return fmt.Errorf("e2ekey: %w", err)
		}
		return nil
	})
}

// Delete removes the entry for ref without reading it. A missing entry is
// not an error. An invalid ref wraps secret.ErrInvalidRef and a done ctx
// wraps ctx.Err(), before any file access.
func (s *Source) Delete(ctx context.Context, ref secret.Ref) error {
	name, err := precheck(ctx, ref)
	if err != nil {
		return err
	}
	err = s.withDir(func(dir *fsx.Root) error {
		if err := dir.Remove(name); err != nil {
			return fmt.Errorf("e2ekey: %w", err)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// withDir opens the key directory (never through a symlink) and runs fn on
// it.
func (s *Source) withDir(fn func(dir *fsx.Root) error) error {
	parent, err := fsx.Open(s.parent)
	if err != nil {
		return fmt.Errorf("e2ekey: %w", err)
	}
	defer func() { _ = parent.Close() }() // fn writes through dir, not parent
	dir, err := parent.OpenDir(s.base)
	if err != nil {
		return fmt.Errorf("e2ekey: %w", err)
	}
	defer func() { _ = dir.Close() }() // WriteAtomic syncs before returning
	return fn(dir)
}

// precheck validates ref and refuses a done ctx; it returns the key file
// name, slash-separated and relative to the key directory.
func precheck(ctx context.Context, ref secret.Ref) (string, error) {
	if ref.Scheme != secret.SchemeKeyring {
		return "", fmt.Errorf("%w: e2ekey: wrong scheme", secret.ErrInvalidRef)
	}
	parsed, err := secret.ParseRef(ref.String())
	if err != nil {
		return "", fmt.Errorf("e2ekey: %w", err)
	}
	if parsed != ref {
		return "", fmt.Errorf("%w: e2ekey: not canonical", secret.ErrInvalidRef)
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("e2ekey: %w", err)
	}
	// ParseRef guarantees single safe segments: no "..", no absolute path.
	return ref.Item + "/" + ref.Field, nil
}

// readPrivate reads name from dir: a regular file without group/world bits
// of at most maxKeyFile bytes. The buffer is wiped on error.
func readPrivate(dir *fsx.Root, name string) ([]byte, error) {
	f, err := dir.OpenRegular(name)
	if err != nil {
		return nil, fmt.Errorf("e2ekey: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("e2ekey: stat: %w", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("e2ekey: key file mode %#o: %w", fi.Mode().Perm(), fsx.ErrInsecurePerms)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		clear(b)
		return nil, fmt.Errorf("e2ekey: read: %w", err)
	}
	if len(b) > maxKeyFile {
		clear(b)
		return nil, errTooLarge
	}
	return b, nil
}

// String renders the source as secret.Masked.
func (s *Source) String() string { return secret.Masked }

// GoString renders the source as secret.Masked.
func (s *Source) GoString() string { return secret.Masked }

// Format renders the source as secret.Masked for every verb.
func (s *Source) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, secret.Masked) }

// MarshalJSON renders the source as secret.Masked.
func (s *Source) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(secret.Masked)
	if err != nil {
		return nil, fmt.Errorf("e2ekey: %w", err)
	}
	return b, nil
}

// LogValue renders the source as secret.Masked.
func (s *Source) LogValue() slog.Value { return slog.StringValue(secret.Masked) }
