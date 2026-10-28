// Tests for package local (J0 task T21): the local-folder destination. Spec:
// docs/spec.md "Destinations: local folder and Google Drive" (atomic write:
// temp file then rename) and "Threat model" (no path escape, private files).
// Unix permission and symlink tests live in local_unix_test.go.
//
// Expected API (implementer: follow exactly; types from internal/dest):
//
//	// Local files documents under one output folder, through internal/fsx
//	// (os.Root confinement, 0600 files, 0700 directories). Safe for
//	// concurrent use.
//	type Local struct{ … }
//	var _ dest.Destination = (*Local)(nil)
//
//	// New opens the existing output folder dir (fsx.Open). It does not create
//	// it: a missing dir wraps fs.ErrNotExist.
//	func New(dir string) (*Local, error)
//	func (l *Local) Close() error // later Put/Exists fail
//
//	func (l *Local) Name() string // "local"
//
//	// Put runs dest.ValidatePath first (ErrInvalidPath, nothing touched),
//	// creates missing directories of doc.Path.Dir with fsx.MkdirPrivate
//	// (0700), then streams r to a temp file in the target directory and
//	// publishes it under doc.Path.File atomically and WITHOUT replacement
//	// (e.g. os.Root.Link of the fsynced temp file, then remove the temp): if
//	// anything (file, directory, symlink, even dangling) is already at that
//	// name, Put fails with dest.ErrExists and leaves it untouched, also when
//	// two Puts race. The file is never visible at its final name before it
//	// is complete. On any error (validation, ctx canceled before or during
//	// the copy, reader error, ErrExists) no file and no temp file is left
//	// behind and RemoteRef is zero; a reader error and ctx.Err() are
//	// wrapped (errors.Is works). Symlinks never lead outside dir.
//	// On success: RemoteRef{Destination: "local", ID: doc.Path.Rel()}.
//	func (l *Local) Put(ctx context.Context, doc dest.NormalizedDoc, r io.Reader) (dest.RemoteRef, error)
//
//	// Exists reports whether a regular file is at doc.Path inside dir. It
//	// runs dest.ValidatePath (ErrInvalidPath) and never follows a symlink
//	// out of dir (never reports true for a file outside). Missing: false,
//	// nil. A canceled ctx returns an error wrapping ctx.Err().
//	func (l *Local) Exists(ctx context.Context, doc dest.NormalizedDoc) (bool, error)
package local_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/dest/local"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

var _ dest.Destination = (*local.Local)(nil)

const (
	docDir  = "2026/housing/fournisseur-exemple"
	docFile = "2026-03-14_fournisseur-exemple_invoice_84.12EUR.pdf"
)

var content = []byte("%PDF-1.7\n% synthetic facto test document\n%%EOF\n")

// newLocal returns a Local over a fresh output folder "out" inside a temp
// dir; base is that temp dir, so tests can check nothing appeared next to
// the output folder.
func newLocal(t *testing.T) (l *local.Local, out, base string) {
	t.Helper()
	base = t.TempDir()
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate("out"); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}
	out = filepath.Join(base, "out")
	l, err = local.New(out)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, out, base
}

func newDoc(dir, file string) dest.NormalizedDoc {
	return dest.NormalizedDoc{
		Doc:  normalize.Doc{Provider: "fournisseur-exemple", Category: "housing"},
		Path: normalize.Path{Dir: dir, File: file},
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// regularFiles lists every non-directory entry under dir (relative, slash).
func regularFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

func wantNoFiles(t *testing.T, dir string) {
	t.Helper()
	if files := regularFiles(t, dir); len(files) != 0 {
		t.Fatalf("files left under %s: %v", dir, files)
	}
}

func TestNew_MissingDir(t *testing.T) {
	t.Parallel()

	_, err := local.New(filepath.Join(t.TempDir(), "missing"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("New(missing): err = %v, want fs.ErrNotExist", err)
	}
}

func TestLocal_Name(t *testing.T) {
	t.Parallel()

	l, _, _ := newLocal(t)
	if got := l.Name(); got != "local" {
		t.Fatalf("Name() = %q, want %q", got, "local")
	}
}

func TestLocal_ExistsAfterPut(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dir  string
	}{
		{name: "default layout", dir: docDir},
		{name: "file at the root", dir: ""},
		{name: "accented dir", dir: "2026/logement/électricité"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l, out, _ := newLocal(t)
			doc := newDoc(tt.dir, docFile)

			ok, err := l.Exists(t.Context(), doc)
			if err != nil || ok {
				t.Fatalf("Exists before Put = %v, %v; want false, nil", ok, err)
			}
			ref, err := l.Put(t.Context(), doc, bytes.NewReader(content))
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			if want := (dest.RemoteRef{Destination: "local", ID: doc.Path.Rel()}); ref != want {
				t.Fatalf("Put ref = %+v, want %+v", ref, want)
			}
			ok, err = l.Exists(t.Context(), doc)
			if err != nil || !ok {
				t.Fatalf("Exists after Put = %v, %v; want true, nil", ok, err)
			}
			if got := readFile(t, filepath.Join(out, filepath.FromSlash(doc.Path.Rel()))); !bytes.Equal(got, content) {
				t.Fatalf("stored content = %q, want %q", got, content)
			}
			if files := regularFiles(t, out); len(files) != 1 || files[0] != doc.Path.Rel() {
				t.Fatalf("files under output = %v, want only %s (no temp file left)", files, doc.Path.Rel())
			}

			other := newDoc(tt.dir, "2026-04-14_fournisseur-exemple_invoice.pdf")
			if ok, err := l.Exists(t.Context(), other); err != nil || ok {
				t.Fatalf("Exists(other) = %v, %v; want false, nil", ok, err)
			}
		})
	}
}

func TestLocal_ExistsIgnoresDirectories(t *testing.T) {
	t.Parallel()

	l, _, _ := newLocal(t)
	if _, err := l.Put(t.Context(), newDoc(docDir, docFile), bytes.NewReader(content)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// "2026/housing" + "fournisseur-exemple" is a directory, not a document.
	ok, err := l.Exists(t.Context(), newDoc("2026/housing", "fournisseur-exemple"))
	if ok {
		t.Fatalf("Exists(directory) = true, %v; want false", err)
	}
}

func TestLocal_PutIsAtomic(t *testing.T) {
	t.Parallel()

	l, out, _ := newLocal(t)
	doc := newDoc(docDir, docFile)
	final := filepath.Join(out, filepath.FromSlash(doc.Path.Rel()))

	// The reader checks, while Put is still copying, that nothing is visible
	// at the final name yet.
	var checked bool
	r := &probeReader{chunks: [][]byte{content[:10], content[10:]}, probe: func() {
		if _, err := os.Lstat(final); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("final file visible during the copy: Lstat err = %v", err)
		}
		if ok, err := l.Exists(context.Background(), doc); ok || err != nil {
			t.Errorf("Exists during the copy = %v, %v; want false, nil", ok, err)
		}
		checked = true
	}}
	if _, err := l.Put(t.Context(), doc, r); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !checked {
		t.Fatal("probe never ran")
	}
	if got := readFile(t, final); !bytes.Equal(got, content) {
		t.Fatalf("stored content = %q, want %q", got, content)
	}
}

// probeReader returns chunks one by one and runs probe before the second.
type probeReader struct {
	chunks [][]byte
	probe  func()
	n      int
}

func (p *probeReader) Read(b []byte) (int, error) {
	if p.n == 1 && p.probe != nil {
		p.probe()
	}
	if p.n >= len(p.chunks) {
		return 0, io.EOF
	}
	c := p.chunks[p.n]
	p.n++
	return copy(b, c), nil
}

func TestLocal_NoSilentOverwrite(t *testing.T) {
	t.Parallel()

	t.Run("second Put of the same path", func(t *testing.T) {
		t.Parallel()
		l, out, _ := newLocal(t)
		doc := newDoc(docDir, docFile)
		if _, err := l.Put(t.Context(), doc, bytes.NewReader(content)); err != nil {
			t.Fatalf("first Put: %v", err)
		}
		ref, err := l.Put(t.Context(), doc, strings.NewReader("%PDF-1.7 corrected synthetic"))
		if !errors.Is(err, dest.ErrExists) {
			t.Fatalf("second Put: err = %v, want ErrExists", err)
		}
		if ref != (dest.RemoteRef{}) {
			t.Fatalf("second Put ref = %+v, want zero", ref)
		}
		if got := readFile(t, filepath.Join(out, filepath.FromSlash(doc.Path.Rel()))); !bytes.Equal(got, content) {
			t.Fatalf("content replaced: %q", got)
		}
		if files := regularFiles(t, out); len(files) != 1 {
			t.Fatalf("files under output = %v, want 1 (no temp left)", files)
		}
	})

	t.Run("directory at the final name", func(t *testing.T) {
		t.Parallel()
		l, out, _ := newLocal(t)
		if _, err := l.Put(t.Context(), newDoc(docDir+"/sub", "x.pdf"), bytes.NewReader(content)); err != nil {
			t.Fatalf("setup Put: %v", err)
		}
		_, err := l.Put(t.Context(), newDoc(docDir, "sub"), bytes.NewReader(content))
		if !errors.Is(err, dest.ErrExists) {
			t.Fatalf("Put over a directory: err = %v, want ErrExists", err)
		}
		if fi, err := os.Lstat(filepath.Join(out, filepath.FromSlash(docDir), "sub")); err != nil || !fi.IsDir() {
			t.Fatalf("directory replaced: %v, %v", fi, err)
		}
	})

	t.Run("concurrent Puts of the same path", func(t *testing.T) {
		t.Parallel()
		l, out, _ := newLocal(t)
		doc := newDoc(docDir, docFile)
		const n = 8
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			winners []int
			errs    []error
		)
		for i := range n {
			wg.Go(func() {
				body := fmt.Sprintf("%%PDF-1.7 synthetic writer %d %s", i, strings.Repeat("x", 64<<10))
				_, err := l.Put(context.Background(), doc, strings.NewReader(body))
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					winners = append(winners, i)
				} else {
					errs = append(errs, err)
				}
			})
		}
		wg.Wait()
		if len(winners) != 1 {
			t.Fatalf("%d Puts succeeded (%v), want exactly 1; errors: %v", len(winners), winners, errs)
		}
		for _, err := range errs {
			if !errors.Is(err, dest.ErrExists) {
				t.Fatalf("losing Put: err = %v, want ErrExists", err)
			}
		}
		got := readFile(t, filepath.Join(out, filepath.FromSlash(doc.Path.Rel())))
		if want := fmt.Sprintf("%%PDF-1.7 synthetic writer %d ", winners[0]); !bytes.HasPrefix(got, []byte(want)) {
			t.Fatalf("stored content is not the winner's: %.40q", got)
		}
		if files := regularFiles(t, out); len(files) != 1 {
			t.Fatalf("files under output = %v, want 1 (no temp left)", files)
		}
	})
}

func TestLocal_RejectsInvalidPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path normalize.Path
	}{
		{name: "dir traversal", path: normalize.Path{Dir: "../escape", File: "x.pdf"}},
		{name: "inner traversal", path: normalize.Path{Dir: "2026/../../escape", File: "x.pdf"}},
		{name: "file traversal", path: normalize.Path{Dir: "2026", File: "../../escape.pdf"}},
		{name: "absolute dir", path: normalize.Path{Dir: "/tmp", File: "x.pdf"}},
		{name: "backslash traversal", path: normalize.Path{Dir: "2026", File: `..\..\escape.pdf`}},
		{name: "NUL in file", path: normalize.Path{Dir: "2026", File: "x\x00.pdf"}},
		{name: "empty file", path: normalize.Path{Dir: "2026"}},
		{name: "hidden file", path: normalize.Path{Dir: "2026", File: ".escape.pdf"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l, _, base := newLocal(t)
			doc := dest.NormalizedDoc{Path: tt.path}
			ref, err := l.Put(t.Context(), doc, bytes.NewReader(content))
			if !errors.Is(err, dest.ErrInvalidPath) {
				t.Fatalf("Put(%+v): err = %v, want ErrInvalidPath", tt.path, err)
			}
			if ref != (dest.RemoteRef{}) {
				t.Fatalf("Put ref = %+v, want zero", ref)
			}
			if ok, err := l.Exists(t.Context(), doc); ok || !errors.Is(err, dest.ErrInvalidPath) {
				t.Fatalf("Exists(%+v) = %v, %v; want false, ErrInvalidPath", tt.path, ok, err)
			}
			wantNoFiles(t, base)
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatalf("read base: %v", err)
			}
			if len(entries) != 1 || entries[0].Name() != "out" {
				t.Fatalf("entries next to the output folder: %v", entries)
			}
		})
	}
}

func TestLocal_ContextCanceled(t *testing.T) {
	t.Parallel()

	t.Run("before Put", func(t *testing.T) {
		t.Parallel()
		l, out, _ := newLocal(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		ref, err := l.Put(ctx, newDoc(docDir, docFile), bytes.NewReader(content))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Put(canceled): err = %v, want context.Canceled", err)
		}
		if ref != (dest.RemoteRef{}) {
			t.Fatalf("Put ref = %+v, want zero", ref)
		}
		wantNoFiles(t, out)
	})

	t.Run("during the copy", func(t *testing.T) {
		t.Parallel()
		l, out, _ := newLocal(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		r := &probeReader{chunks: [][]byte{content[:10], content[10:20], content[20:]}, probe: cancel}
		_, err := l.Put(ctx, newDoc(docDir, docFile), r)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Put(canceled mid-copy): err = %v, want context.Canceled", err)
		}
		wantNoFiles(t, out)
		// Nothing left blocks a later Put.
		if _, err := l.Put(t.Context(), newDoc(docDir, docFile), bytes.NewReader(content)); err != nil {
			t.Fatalf("Put after canceled Put: %v", err)
		}
	})

	t.Run("Exists", func(t *testing.T) {
		t.Parallel()
		l, _, _ := newLocal(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if ok, err := l.Exists(ctx, newDoc(docDir, docFile)); ok || !errors.Is(err, context.Canceled) {
			t.Fatalf("Exists(canceled) = %v, %v; want false, context.Canceled", ok, err)
		}
	})
}

var errReader = errors.New("synthetic read failure")

type failingReader struct{ prefix []byte }

func (f *failingReader) Read(p []byte) (int, error) {
	if len(f.prefix) > 0 {
		n := copy(p, f.prefix)
		f.prefix = f.prefix[n:]
		return n, nil
	}
	return 0, errReader
}

func TestLocal_ReaderErrorLeavesNothing(t *testing.T) {
	t.Parallel()

	l, out, _ := newLocal(t)
	doc := newDoc(docDir, docFile)
	ref, err := l.Put(t.Context(), doc, &failingReader{prefix: content[:12]})
	if !errors.Is(err, errReader) {
		t.Fatalf("Put: err = %v, want it to wrap the reader error", err)
	}
	if ref != (dest.RemoteRef{}) {
		t.Fatalf("Put ref = %+v, want zero", ref)
	}
	wantNoFiles(t, out)
	if ok, err := l.Exists(t.Context(), doc); ok || err != nil {
		t.Fatalf("Exists after failed Put = %v, %v; want false, nil", ok, err)
	}
	if _, err := l.Put(t.Context(), doc, bytes.NewReader(content)); err != nil {
		t.Fatalf("Put after failed Put: %v", err)
	}
}

func TestLocal_ClosedRefusesOperations(t *testing.T) {
	t.Parallel()

	l, out, _ := newLocal(t)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := l.Put(t.Context(), newDoc(docDir, docFile), bytes.NewReader(content)); err == nil {
		t.Fatal("Put after Close succeeded")
	}
	if _, err := l.Exists(t.Context(), newDoc(docDir, docFile)); err == nil {
		t.Fatal("Exists after Close succeeded")
	}
	wantNoFiles(t, out)
}
