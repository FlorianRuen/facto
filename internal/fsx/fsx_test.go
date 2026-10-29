// Tests for package fsx core (J0 task T2). Permission and symlink tests live in
// fsx_unix_test.go.
//
// Expected API (implementer: follow exactly):
//
//	// Sentinel errors.
//	var ErrInvalidName    error // name is empty, ".", absolute, or escapes the root lexically ("..", "a/../../b")
//	var ErrInsecurePerms  error // file or directory has group or world permission bits (mode & 0o077 != 0)
//
//	// Root confines every operation to one directory, using os.Root, so that
//	// neither ".." nor symlinks can reach outside it.
//	type Root struct{ /* wraps *os.Root */ }
//
//	// Open opens an existing directory as a Root. It does not create it and
//	// does not check its permissions (use CheckPrivate). Missing dir: wraps fs.ErrNotExist.
//	func Open(dir string) (*Root, error)
//	func (r *Root) Close() error // later calls fail with an error wrapping os.ErrClosed
//
//	// WriteAtomic writes data to name (slash-separated, relative to the root):
//	// temp file in the same directory, created 0600, write, fsync, close, rename.
//	// The final file is 0600 even if it replaced a broader file. On any error
//	// (canceled ctx, failed write, failed rename) the previous content of name is
//	// untouched and no temp file is left behind. The parent directory must exist
//	// (no implicit mkdir): otherwise the error wraps fs.ErrNotExist.
//	func (r *Root) WriteAtomic(ctx context.Context, name string, data []byte) error
//	// WriteAtomicFrom is WriteAtomic streaming from r (used for downloads).
//	// An error from the reader is wrapped (errors.Is works on it).
//	func (r *Root) WriteAtomicFrom(ctx context.Context, name string, src io.Reader) error
//
//	// MkdirPrivate creates name and missing parents with mode 0700. It is
//	// idempotent on an existing 0700 directory, fails with ErrInsecurePerms if the
//	// existing directory has group/world bits, and fails if name is not a directory.
//	func (r *Root) MkdirPrivate(name string) error
//
//	// AppendPrivate appends data to name, creating it 0600 if missing. It refuses
//	// (ErrInsecurePerms) to append to an existing file with group/world bits and
//	// leaves it unchanged. Missing parent: wraps fs.ErrNotExist.
//	func (r *Root) AppendPrivate(name string, data []byte) error
//
//	// Remove removes a file or an empty directory. Missing: wraps fs.ErrNotExist.
//	func (r *Root) Remove(name string) error
//
//	// CheckPrivate reports ErrInsecurePerms when path (file or directory, symlinks
//	// followed) has any group or world permission bit. Missing: wraps fs.ErrNotExist.
//	func CheckPrivate(path string) error
//
// Every Root method rejects lexically invalid names with ErrInvalidName before
// touching the disk; symlink escapes are refused by os.Root and must return a
// non-nil error with nothing changed outside the root.
package fsx_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// openRoot opens a fresh temp dir as a Root and closes it at test end.
func openRoot(t *testing.T) (*fsx.Root, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, dir
}

// entries lists the names in dir, sorted. Used to prove no temp file is left.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	names := make([]string, 0, len(des))
	for _, de := range des {
		names = append(names, de.Name())
	}
	slices.Sort(names)
	return names
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return b
}

func mustWriteRaw(t *testing.T, path string, data []byte, perm fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("setup WriteFile(%q): %v", path, err)
	}
	// WriteFile is subject to umask; force the exact mode under test.
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("setup Chmod(%q): %v", path, err)
	}
}

func TestOpen(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	file := filepath.Join(base, "file")
	mustWriteRaw(t, file, []byte("x"), 0o600)

	tests := []struct {
		name    string
		dir     string
		wantErr error // nil = success; errAny = any non-nil error
	}{
		{name: "existing directory", dir: base},
		{name: "missing directory", dir: filepath.Join(base, "missing"), wantErr: fs.ErrNotExist},
		{name: "regular file", dir: file, wantErr: errAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, err := fsx.Open(tt.dir)
			checkErr(t, "Open", err, tt.wantErr)
			if err == nil {
				if cerr := r.Close(); cerr != nil {
					t.Fatalf("Close: %v", cerr)
				}
			}
		})
	}
}

func TestRoot_ClosedRefusesOperations(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := r.WriteAtomic(context.Background(), "a", []byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("WriteAtomic after Close: err = %v, want os.ErrClosed", err)
	}
	if err := r.AppendPrivate("a", []byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("AppendPrivate after Close: err = %v, want os.ErrClosed", err)
	}
	if err := r.MkdirPrivate("d"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("MkdirPrivate after Close: err = %v, want os.ErrClosed", err)
	}
	if err := r.Remove("a"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Remove after Close: err = %v, want os.ErrClosed", err)
	}
	if got := entries(t, dir); len(got) != 0 {
		t.Fatalf("closed root wrote %v", got)
	}
}

func TestWriteAtomic_WritesContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, r *fsx.Root, dir string)
		path  string // name passed to WriteAtomic
		data  []byte
	}{
		{name: "new file", path: "invoice.pdf", data: []byte("%PDF-1.7 synthetic")},
		{name: "empty file", path: "empty", data: []byte{}},
		{
			name: "replaces existing content entirely",
			setup: func(t *testing.T, _ *fsx.Root, dir string) {
				mustWriteRaw(t, filepath.Join(dir, "report.json"), bytes.Repeat([]byte("old"), 1000), 0o600)
			},
			path: "report.json",
			data: []byte(`{"new":true}`),
		},
		{
			name: "nested in existing subdirectory",
			setup: func(t *testing.T, r *fsx.Root, _ string) {
				if err := r.MkdirPrivate("2026/energy/edf"); err != nil {
					t.Fatalf("MkdirPrivate: %v", err)
				}
			},
			path: "2026/energy/edf/2026-01-31_edf_invoice.pdf",
			data: []byte("pdf"),
		},
		{name: "large payload", path: "big.bin", data: bytes.Repeat([]byte{0xAB}, 3<<20)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			if tt.setup != nil {
				tt.setup(t, r, dir)
			}
			if err := r.WriteAtomic(context.Background(), tt.path, tt.data); err != nil {
				t.Fatalf("WriteAtomic(%q): %v", tt.path, err)
			}
			full := filepath.Join(dir, filepath.FromSlash(tt.path))
			if got := readFile(t, full); !bytes.Equal(got, tt.data) {
				t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(tt.data))
			}
			parent := filepath.Dir(full)
			want := []string{filepath.Base(full)}
			if got := entries(t, parent); !slices.Equal(got, want) {
				t.Fatalf("entries(%q) = %v, want %v (temp file left behind?)", parent, got, want)
			}
		})
	}
}

func TestWriteAtomicFrom_StreamsContent(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	data := bytes.Repeat([]byte("0123456789"), 100_000)
	if err := r.WriteAtomicFrom(context.Background(), "stream.bin", bytes.NewReader(data)); err != nil {
		t.Fatalf("WriteAtomicFrom: %v", err)
	}
	if got := readFile(t, filepath.Join(dir, "stream.bin")); !bytes.Equal(got, data) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(data))
	}
	if got, want := entries(t, dir), []string{"stream.bin"}; !slices.Equal(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
}

// Many writers race on the same name: the final file must be exactly one of the
// payloads (never interleaved or truncated) and no temp file may remain.
func TestWriteAtomic_ConcurrentWritersNeverInterleave(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	const writers = 8
	payloads := make([][]byte, writers)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 256<<10)
	}

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Go(func() {
			errs <- r.WriteAtomic(context.Background(), "shared.bin", payloads[i])
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("WriteAtomic: %v", err)
		}
	}

	got := readFile(t, filepath.Join(dir, "shared.bin"))
	if !slices.ContainsFunc(payloads, func(p []byte) bool { return bytes.Equal(p, got) }) {
		t.Fatalf("final content (%d bytes) is not one complete payload", len(got))
	}
	if names, want := entries(t, dir), []string{"shared.bin"}; !slices.Equal(names, want) {
		t.Fatalf("entries = %v, want %v", names, want)
	}
}

var errBoom = errors.New("synthetic read failure")

// failingReader returns n bytes then errBoom.
type failingReader struct{ n int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errBoom
	}
	k := min(len(p), f.n)
	for i := range k {
		p[i] = 'z'
	}
	f.n -= k
	return k, nil
}

func TestWriteAtomic_NoPartialFileOnError(t *testing.T) {
	t.Parallel()

	const old = "previous complete content"

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name      string
		existing  bool // pre-create target with `old`
		write     func(r *fsx.Root) error
		wantErr   error
		wantNames []string // entries of the root after the failure
	}{
		{
			name: "reader fails mid-stream, new file",
			write: func(r *fsx.Root) error {
				return r.WriteAtomicFrom(context.Background(), "t.pdf", &failingReader{n: 64 << 10})
			},
			wantErr:   errBoom,
			wantNames: []string{},
		},
		{
			name:     "reader fails mid-stream, existing file kept",
			existing: true,
			write: func(r *fsx.Root) error {
				return r.WriteAtomicFrom(context.Background(), "t.pdf", &failingReader{n: 64 << 10})
			},
			wantErr:   errBoom,
			wantNames: []string{"t.pdf"},
		},
		{
			name:      "context canceled, new file",
			write:     func(r *fsx.Root) error { return r.WriteAtomic(canceled, "t.pdf", []byte("new")) },
			wantErr:   context.Canceled,
			wantNames: []string{},
		},
		{
			name:      "context canceled, existing file kept",
			existing:  true,
			write:     func(r *fsx.Root) error { return r.WriteAtomic(canceled, "t.pdf", []byte("new")) },
			wantErr:   context.Canceled,
			wantNames: []string{"t.pdf"},
		},
		{
			name:      "context canceled while streaming",
			existing:  true,
			write:     func(r *fsx.Root) error { return r.WriteAtomicFrom(canceled, "t.pdf", strings.NewReader("new")) },
			wantErr:   context.Canceled,
			wantNames: []string{"t.pdf"},
		},
		{
			name:      "parent directory missing",
			write:     func(r *fsx.Root) error { return r.WriteAtomic(context.Background(), "nodir/t.pdf", []byte("new")) },
			wantErr:   fs.ErrNotExist,
			wantNames: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			target := filepath.Join(dir, "t.pdf")
			if tt.existing {
				mustWriteRaw(t, target, []byte(old), 0o600)
			}

			err := tt.write(r)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want errors.Is %v", err, tt.wantErr)
			}
			if got := entries(t, dir); !slices.Equal(got, tt.wantNames) {
				t.Fatalf("entries = %v, want %v (partial or temp file left)", got, tt.wantNames)
			}
			if tt.existing {
				if got := readFile(t, target); string(got) != old {
					t.Fatalf("existing content = %q, want %q", got, old)
				}
			}
		})
	}
}

// Rename fails when the target is a non-empty directory: the temp file must be
// cleaned up and the directory left intact.
func TestWriteAtomic_RenameFailureCleansTemp(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	if err := r.MkdirPrivate("target"); err != nil {
		t.Fatalf("MkdirPrivate: %v", err)
	}
	if err := r.WriteAtomic(context.Background(), "target/keep", []byte("k")); err != nil {
		t.Fatalf("WriteAtomic setup: %v", err)
	}

	if err := r.WriteAtomic(context.Background(), "target", []byte("new")); err == nil {
		t.Fatal("WriteAtomic over a non-empty directory: err = nil, want error")
	}
	if got, want := entries(t, dir), []string{"target"}; !slices.Equal(got, want) {
		t.Fatalf("entries = %v, want %v (temp file left behind)", got, want)
	}
	if got, want := entries(t, filepath.Join(dir, "target")), []string{"keep"}; !slices.Equal(got, want) {
		t.Fatalf("target dir entries = %v, want %v", got, want)
	}
}

func TestAppendPrivate_AppendsAndCreates(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	for _, chunk := range []string{"line 1\n", "line 2\n", "", "line 3\n"} {
		if err := r.AppendPrivate("run.log", []byte(chunk)); err != nil {
			t.Fatalf("AppendPrivate(%q): %v", chunk, err)
		}
	}
	if got, want := string(readFile(t, filepath.Join(dir, "run.log"))), "line 1\nline 2\nline 3\n"; got != want {
		t.Fatalf("content = %q, want %q", got, want)
	}
}

// TestAppendPrivate_ConcurrentCreate proves concurrent first appends to the
// same missing file all succeed and never interleave. On macOS, openat with
// O_CREAT may spuriously fail with ENOENT while another writer creates the
// same name; AppendPrivate must absorb that.
func TestAppendPrivate_ConcurrentCreate(t *testing.T) {
	t.Parallel()

	const rounds, writers = 20, 8
	for round := range rounds {
		r, dir := openRoot(t)
		name := fmt.Sprintf("race-%d.log", round)
		errs := make(chan error, writers)
		var wg sync.WaitGroup
		for w := range writers {
			wg.Go(func() { errs <- r.AppendPrivate(name, []byte(fmt.Sprintf("writer %d\n", w))) })
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d: AppendPrivate: %v", round, err)
			}
		}
		lines := strings.Split(strings.TrimSuffix(string(readFile(t, filepath.Join(dir, name))), "\n"), "\n")
		if len(lines) != writers {
			t.Fatalf("round %d: %d lines, want %d: %q", round, len(lines), writers, lines)
		}
	}
}

func TestAppendPrivate_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, r *fsx.Root)
		target  string
		wantErr error
	}{
		{name: "parent missing", target: "nodir/run.log", wantErr: fs.ErrNotExist},
		{
			name: "target is a directory",
			setup: func(t *testing.T, r *fsx.Root) {
				if err := r.MkdirPrivate("logs"); err != nil {
					t.Fatalf("MkdirPrivate: %v", err)
				}
			},
			target:  "logs",
			wantErr: errAny,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := openRoot(t)
			if tt.setup != nil {
				tt.setup(t, r)
			}
			checkErr(t, "AppendPrivate", r.AppendPrivate(tt.target, []byte("x")), tt.wantErr)
		})
	}
}

func TestMkdirPrivate_CreatesNestedAndIsIdempotent(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	for range 2 {
		if err := r.MkdirPrivate("a/b/c"); err != nil {
			t.Fatalf("MkdirPrivate: %v", err)
		}
	}
	fi, err := os.Stat(filepath.Join(dir, "a", "b", "c"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("a/b/c is not a directory")
	}
}

func TestMkdirPrivate_RefusesExistingFile(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	mustWriteRaw(t, filepath.Join(dir, "f"), []byte("x"), 0o600)
	if err := r.MkdirPrivate("f"); err == nil {
		t.Fatal("MkdirPrivate on a regular file: err = nil, want error")
	}
	if err := r.MkdirPrivate("f/sub"); err == nil {
		t.Fatal("MkdirPrivate under a regular file: err = nil, want error")
	}
}

func TestRemove(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setup     func(t *testing.T, r *fsx.Root)
		target    string
		wantErr   error
		wantNames []string
	}{
		{
			name: "file",
			setup: func(t *testing.T, r *fsx.Root) {
				mustAtomic(t, r, "inbox.pdf")
			},
			target:    "inbox.pdf",
			wantNames: []string{},
		},
		{
			name: "empty directory",
			setup: func(t *testing.T, r *fsx.Root) {
				mustMkdir(t, r, "empty")
			},
			target:    "empty",
			wantNames: []string{},
		},
		{
			name: "nested file keeps parent",
			setup: func(t *testing.T, r *fsx.Root) {
				mustMkdir(t, r, "inbox/impots")
				mustAtomic(t, r, "inbox/impots/a.pdf")
			},
			target:    "inbox/impots/a.pdf",
			wantNames: []string{"inbox"},
		},
		{
			name:      "missing",
			target:    "missing.pdf",
			wantErr:   fs.ErrNotExist,
			wantNames: []string{},
		},
		{
			name: "non-empty directory is refused",
			setup: func(t *testing.T, r *fsx.Root) {
				mustMkdir(t, r, "full")
				mustAtomic(t, r, "full/keep")
			},
			target:    "full",
			wantErr:   errAny,
			wantNames: []string{"full"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			if tt.setup != nil {
				tt.setup(t, r)
			}
			checkErr(t, "Remove", r.Remove(tt.target), tt.wantErr)
			if got := entries(t, dir); !slices.Equal(got, tt.wantNames) {
				t.Fatalf("entries = %v, want %v", got, tt.wantNames)
			}
		})
	}
}

// Security negative: every Root method rejects names that are absolute or
// escape lexically, before touching the disk.
func TestRoot_RejectsInvalidNames(t *testing.T) {
	t.Parallel()

	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "victim")
	mustWriteRaw(t, outsideFile, []byte("untouched"), 0o600)

	names := []string{
		"",
		".",
		"..",
		"../victim",
		"a/../../victim",
		"./../victim",
		outsideFile, // absolute
		"/etc/passwd",
	}
	ops := []struct {
		name string
		do   func(r *fsx.Root, n string) error
	}{
		{"WriteAtomic", func(r *fsx.Root, n string) error { return r.WriteAtomic(context.Background(), n, []byte("pwned")) }},
		{"WriteAtomicFrom", func(r *fsx.Root, n string) error {
			return r.WriteAtomicFrom(context.Background(), n, strings.NewReader("pwned"))
		}},
		{"AppendPrivate", func(r *fsx.Root, n string) error { return r.AppendPrivate(n, []byte("pwned")) }},
		{"MkdirPrivate", func(r *fsx.Root, n string) error { return r.MkdirPrivate(n) }},
		{"Remove", func(r *fsx.Root, n string) error { return r.Remove(n) }},
	}

	for _, op := range ops {
		for _, n := range names {
			t.Run(fmt.Sprintf("%s/%q", op.name, n), func(t *testing.T) {
				// Not parallel with siblings: all share outsideFile.
				r, dir := openRoot(t)
				err := op.do(r, n)
				if !errors.Is(err, fsx.ErrInvalidName) {
					t.Fatalf("%s(%q): err = %v, want fsx.ErrInvalidName", op.name, n, err)
				}
				if got := entries(t, dir); len(got) != 0 {
					t.Fatalf("root modified: %v", got)
				}
				if got := readFile(t, outsideFile); string(got) != "untouched" {
					t.Fatalf("outside file modified: %q", got)
				}
			})
		}
	}
}

func TestCheckPrivate_Missing(t *testing.T) {
	t.Parallel()

	err := fsx.CheckPrivate(filepath.Join(t.TempDir(), "missing"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("CheckPrivate(missing): err = %v, want fs.ErrNotExist", err)
	}
}

// errAny marks a table case that must fail without a specific sentinel.
var errAny = errors.New("any error")

func checkErr(t *testing.T, op string, err, want error) {
	t.Helper()
	switch {
	case want == nil && err != nil:
		t.Fatalf("%s: unexpected error: %v", op, err)
	case errors.Is(want, errAny) && err == nil:
		t.Fatalf("%s: err = nil, want an error", op)
	case want != nil && !errors.Is(want, errAny) && !errors.Is(err, want):
		t.Fatalf("%s: err = %v, want errors.Is %v", op, err, want)
	}
}

func mustAtomic(t *testing.T, r *fsx.Root, name string) {
	t.Helper()
	if err := r.WriteAtomic(context.Background(), name, []byte("synthetic")); err != nil {
		t.Fatalf("WriteAtomic(%q): %v", name, err)
	}
}

func mustMkdir(t *testing.T, r *fsx.Root, name string) {
	t.Helper()
	if err := r.MkdirPrivate(name); err != nil {
		t.Fatalf("MkdirPrivate(%q): %v", name, err)
	}
}
