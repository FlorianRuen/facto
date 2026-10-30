//go:build e2e

// Tests for the e2e-only file key source of the session vault (J1 T17,
// ADR 0009 "Key source", decision A3). The package exists only in builds
// with -tags e2e; `make release-e2e-check` proves the release binary lacks
// it. Every value is a synthetic canary.
//
// Expected API (implementer: follow exactly; every file of the package
// carries //go:build e2e):
//
//	package e2ekey
//
//	// Sentinel is referenced by the e2e registration file of cmd/facto so
//	// the linker keeps it: `go tool nm` finds
//	// github.com/FlorianRuen/facto/internal/vault/e2ekey.Sentinel in an e2e
//	// binary and the release check proves it absent from a release one.
//	var Sentinel = "…" // any non-empty, non-secret text
//
//	// Source is a vault.KeyBackend over one 0600 file per reference under a
//	// 0700 directory, every access through internal/fsx. Safe for
//	// concurrent use. Every rendering (fmt verbs, %#v, JSON, slog) is
//	// secret.Masked.
//	type Source struct{ … }
//
//	// New uses dir as the key directory, creating it 0700 through fsx when
//	// missing (its parent must exist). An existing dir with any group or
//	// world bit wraps fsx.ErrInsecurePerms; a symlink or a non-directory
//	// wraps fsx.ErrNotDir. Nothing is read at New.
//	func New(dir string) (*Source, error)
//
//	// Resolve, Set and Delete have the vault.KeyBackend contract of
//	// *keyring.Provider: refs must be canonical keyring refs
//	// (secret.ParseRef(ref.String()) == ref, else secret.ErrInvalidRef,
//	// nothing touched); a done ctx wraps ctx.Err() before any file access;
//	// a missing entry wraps secret.ErrSecretNotFound on Resolve and is not
//	// an error on Delete; Set with an empty value is refused. Set writes
//	// with fsx WriteAtomic (0600, parents 0700); Resolve reads with fsx
//	// OpenRegular (a symlink wraps fsx.ErrNotRegular, a group/world-readable
//	// key file wraps fsx.ErrInsecurePerms). Errors never carry a key value.
//	func (s *Source) Resolve(ctx context.Context, ref secret.Ref) (secret.Secret, error)
//	func (s *Source) Set(ctx context.Context, ref secret.Ref, value secret.Secret) error
//	func (s *Source) Delete(ctx context.Context, ref secret.Ref) error
package e2ekey_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault"
	"github.com/FlorianRuen/facto/internal/vault/e2ekey"
)

// The file key source plugs into the vault store where the keyring does.
var _ vault.KeyBackend = (*e2ekey.Source)(nil)

// installID is a synthetic 32-hex install id.
const installID = "0123456789abcdef0123456789abcdef"

func keyRef(id string) secret.Ref {
	return secret.Ref{Scheme: secret.SchemeKeyring, Item: vault.KeyringService, Field: installID + "/" + id}
}

// newSource returns a Source over a fresh "keys" dir in a private temp dir.
func newSource(t *testing.T) (*e2ekey.Source, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	s, err := e2ekey.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, dir
}

func TestSentinel_NonEmpty(t *testing.T) {
	t.Parallel()
	if e2ekey.Sentinel == "" {
		t.Fatal("Sentinel is empty: the release check's nm self-test needs a linked symbol")
	}
}

func TestSource_SetResolveDeleteRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s, _ := newSource(t)
	canary := testsecrets.Canary(t, testsecrets.Token)
	ref := keyRef("edf")

	if _, err := s.Resolve(ctx, ref); !errors.Is(err, secret.ErrSecretNotFound) {
		t.Fatalf("Resolve(missing) = %v, want ErrSecretNotFound", err)
	}
	if err := s.Set(ctx, ref, secret.New([]byte(canary))); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Expose() != canary {
		t.Fatal("Resolve returned another value than Set stored")
	}
	got.Wipe()
	// Another connector's entry is independent.
	if _, err := s.Resolve(ctx, keyRef("ileo")); !errors.Is(err, secret.ErrSecretNotFound) {
		t.Fatalf("Resolve(other id) = %v, want ErrSecretNotFound", err)
	}
	if err := s.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Resolve(ctx, ref); !errors.Is(err, secret.ErrSecretNotFound) {
		t.Fatalf("Resolve after Delete = %v, want ErrSecretNotFound", err)
	}
	if err := s.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete(missing) = %v, want nil (idempotent)", err)
	}
}

// TestSource_FilesPrivate: the key dir and every dir under it are 0700, every
// key file 0600.
func TestSource_FilesPrivate(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		return // POSIX modes only; fsx enforces ACLs elsewhere
	}
	ctx := t.Context()
	s, dir := newSource(t)
	for _, id := range []string{"edf", "ileo"} {
		if err := s.Set(ctx, keyRef(id), secret.New([]byte(testsecrets.Canary(t, testsecrets.Token)))); err != nil {
			t.Fatalf("Set %s: %v", id, err)
		}
	}
	files := 0
	err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case fi.IsDir():
			if fi.Mode().Perm() != 0o700 {
				t.Errorf("dir %s mode %v, want 0700", p, fi.Mode().Perm())
			}
		case fi.Mode().IsRegular():
			files++
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("file %s mode %v, want 0600", p, fi.Mode().Perm())
			}
		default:
			t.Errorf("%s: unexpected file type %v", p, fi.Mode().Type())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if files != 2 {
		t.Fatalf("key files = %d, want 2", files)
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
		{
			name: "group and world readable dir",
			prepare: func(t *testing.T, dir string) {
				mkdirRaw(t, dir, 0o755)
			},
			wantErr: fsx.ErrInsecurePerms,
		},
		{
			name: "symlink to a private dir",
			prepare: func(t *testing.T, dir string) {
				target := filepath.Join(filepath.Dir(dir), "elsewhere")
				mkdirRaw(t, target, 0o700)
				if err := os.Symlink(target, dir); err != nil {
					t.Fatalf("setup symlink: %v", err)
				}
			},
			wantErr: fsx.ErrNotDir,
		},
		{
			name: "regular file",
			prepare: func(t *testing.T, dir string) {
				writeRaw(t, dir, []byte("synthetic"), 0o600)
			},
			wantErr: fsx.ErrNotDir,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "keys")
			tc.prepare(t, dir)
			if _, err := e2ekey.New(dir); !errors.Is(err, tc.wantErr) {
				t.Fatalf("New = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestSource_RefusesBadRefs: a hand-built ref that is not a canonical
// keyring ref (traversal, other scheme, empty parts) touches nothing.
func TestSource_RefusesBadRefs(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s, dir := newSource(t)
	val := secret.New([]byte(testsecrets.Canary(t, testsecrets.Token)))
	bad := []secret.Ref{
		{Scheme: secret.SchemeKeyring, Item: vault.KeyringService, Field: "../../escape"},
		{Scheme: secret.SchemeKeyring, Item: "..", Field: "x"},
		{Scheme: secret.SchemeKeyring, Item: vault.KeyringService, Field: installID + "/../../escape"},
		{Scheme: secret.SchemeKeyring, Item: vault.KeyringService, Field: "/abs"},
		{Scheme: secret.SchemeKeyring, Item: vault.KeyringService, Field: ""},
		{Scheme: secret.SchemeBitwarden, Item: "00000000-0000-0000-0000-000000000000", Field: "password"},
		{Scheme: "e2e", Item: "x", Field: "y"},
	}
	for _, ref := range bad {
		if err := s.Set(ctx, ref, val); !errors.Is(err, secret.ErrInvalidRef) {
			t.Errorf("Set(%q) = %v, want ErrInvalidRef", ref.String(), err)
		}
		if _, err := s.Resolve(ctx, ref); !errors.Is(err, secret.ErrInvalidRef) {
			t.Errorf("Resolve(%q) = %v, want ErrInvalidRef", ref.String(), err)
		}
		if err := s.Delete(ctx, ref); !errors.Is(err, secret.ErrInvalidRef) {
			t.Errorf("Delete(%q) = %v, want ErrInvalidRef", ref.String(), err)
		}
	}
	if n := countFiles(t, filepath.Dir(dir)); n != 0 {
		t.Fatalf("%d files written for refused refs, want 0", n)
	}
}

func TestSource_RefusesEmptyValueAndDoneCtx(t *testing.T) {
	t.Parallel()
	s, dir := newSource(t)
	if err := s.Set(t.Context(), keyRef("edf"), secret.Secret{}); err == nil {
		t.Error("Set(empty) = nil, want an error")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	val := secret.New([]byte(testsecrets.Canary(t, testsecrets.Token)))
	if err := s.Set(ctx, keyRef("edf"), val); !errors.Is(err, context.Canceled) {
		t.Errorf("Set(done ctx) = %v, want context.Canceled", err)
	}
	if _, err := s.Resolve(ctx, keyRef("edf")); !errors.Is(err, context.Canceled) {
		t.Errorf("Resolve(done ctx) = %v, want context.Canceled", err)
	}
	if err := s.Delete(ctx, keyRef("edf")); !errors.Is(err, context.Canceled) {
		t.Errorf("Delete(done ctx) = %v, want context.Canceled", err)
	}
	if n := countFiles(t, dir); n != 0 {
		t.Fatalf("%d files written, want 0", n)
	}
}

// TestSource_RefusesPlantedKeyFiles: a key file replaced by a symlink or
// loosened to group/world-readable is refused, its content never returned.
func TestSource_RefusesPlantedKeyFiles(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		return // POSIX modes and symlinks only
	}
	tests := []struct {
		name    string
		plant   func(t *testing.T, path string)
		wantErr error
	}{
		{
			name: "symlink to an attacker file",
			plant: func(t *testing.T, path string) {
				target := filepath.Join(t.TempDir(), "planted")
				writeRaw(t, target, []byte(testsecrets.Canary(t, testsecrets.Token)), 0o600)
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
			name: "world readable key file",
			plant: func(t *testing.T, path string) {
				loose := fs.FileMode(0o644) // the insecure mode under test
				if err := os.Chmod(path, loose); err != nil {
					t.Fatalf("setup chmod: %v", err)
				}
			},
			wantErr: fsx.ErrInsecurePerms,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			s, dir := newSource(t)
			if err := s.Set(ctx, keyRef("edf"), secret.New([]byte(testsecrets.Canary(t, testsecrets.Token)))); err != nil {
				t.Fatalf("Set: %v", err)
			}
			files := regularFiles(t, dir)
			if len(files) != 1 {
				t.Fatalf("key files = %q, want exactly one", files)
			}
			tc.plant(t, files[0])
			got, err := s.Resolve(ctx, keyRef("edf"))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve = %v, want %v", err, tc.wantErr)
			}
			if !got.IsZero() {
				t.Fatal("Resolve returned a value together with an error")
			}
		})
	}
}

// TestSource_KeyNeverRendered: no rendering of the source and no error it
// returns carries a key value.
func TestSource_KeyNeverRendered(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s, dir := newSource(t)
	canary := testsecrets.Canary(t, testsecrets.Token)
	if err := s.Set(ctx, keyRef("edf"), secret.New([]byte(canary))); err != nil {
		t.Fatalf("Set: %v", err)
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "%v %+v %#v %s %q", s, s, s, s, s)
	if b, err := json.Marshal(s); err == nil {
		out.Write(b)
	}
	slog.New(slog.NewTextHandler(&out, nil)).Info("source", "src", s)
	// Errors from a loosened key file must not quote it.
	if runtime.GOOS != "windows" {
		for _, p := range regularFiles(t, dir) {
			loose := fs.FileMode(0o644) // the insecure mode under test
			if err := os.Chmod(p, loose); err != nil {
				t.Fatalf("setup chmod: %v", err)
			}
		}
		if _, err := s.Resolve(ctx, keyRef("edf")); err != nil {
			out.WriteString(err.Error())
		}
	}
	if strings.Contains(out.String(), canary) {
		t.Fatalf("key rendered:\n%s", out.String())
	}
}

// TestSource_BacksVaultStore: a vault.Store over the file key source saves
// and loads a session, and the session canary never lands in clear in the
// key dir or the state dir.
func TestSource_BacksVaultStore(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	mkdirRaw(t, state, 0o700)
	src, err := e2ekey.New(filepath.Join(base, "keys"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st, err := vault.NewStore(ctx, vault.Options{StateDir: state, Mode: vault.Persistent, Keyring: src, Rand: rand.Reader})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if !st.Persistent() {
		t.Fatal("store over the file key source is not persistent")
	}
	canary := testsecrets.Canary(t, testsecrets.Session)
	if err := st.Save(ctx, "edf", secret.New([]byte(canary))); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := st.Load(ctx, "edf")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Expose() != canary {
		t.Fatal("Load returned another session than Save stored")
	}
	got.Wipe()
	for _, p := range regularFiles(t, base) {
		b, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if bytes.Contains(b, []byte(canary)) {
			t.Fatalf("session canary in clear in %s", p)
		}
	}
}

// --- helpers ------------------------------------------------------------------

// mkdirRaw creates dir with mode m, bypassing fsx on purpose (to plant an
// unsafe directory).
func mkdirRaw(t *testing.T, dir string, m fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(dir, m); err != nil {
		t.Fatalf("setup mkdir: %v", err)
	}
	if err := os.Chmod(dir, m); err != nil { // umask
		t.Fatalf("setup chmod: %v", err)
	}
}

// writeRaw writes a planted file through fsx, then sets mode m.
func writeRaw(t *testing.T, path string, data []byte, m fs.FileMode) {
	t.Helper()
	root, err := fsx.Open(filepath.Dir(path))
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(t.Context(), filepath.Base(path), data); err != nil {
		t.Fatalf("setup write: %v", err)
	}
	if err := os.Chmod(path, m); err != nil {
		t.Fatalf("setup chmod: %v", err)
	}
}

func regularFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	return len(regularFiles(t, dir))
}
