//go:build unix

// Permission-mode and symlink tests for package local (J0 task T21). See
// local_test.go for the expected API.
package local_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/dest/local"
	"github.com/FlorianRuen/facto/internal/fsx"
)

func perm(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", path, err)
	}
	return fi.Mode().Perm()
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("setup Symlink(%q -> %q): %v", link, target, err)
	}
}

// outsideDir creates "outside" next to the output folder, holding one
// synthetic file, and returns its path.
func outsideDir(t *testing.T, base string) string {
	t.Helper()
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate("outside"); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	if err := r.WriteAtomic(t.Context(), "outside/victim.pdf", []byte("outside, must stay unchanged")); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	return filepath.Join(base, "outside")
}

func wantOutsideUnchanged(t *testing.T, outside string) {
	t.Helper()
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatalf("read outside: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "victim.pdf" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("outside dir now holds %v, want only victim.pdf", names)
	}
	if got := readFile(t, filepath.Join(outside, "victim.pdf")); string(got) != "outside, must stay unchanged" {
		t.Fatalf("outside file modified: %q", got)
	}
}

func TestLocal_PutAtomicPrivate(t *testing.T) {
	t.Parallel()

	l, out, _ := newLocal(t)
	doc := newDoc(docDir, docFile)
	if _, err := l.Put(t.Context(), doc, bytes.NewReader(content)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := perm(t, filepath.Join(out, filepath.FromSlash(doc.Path.Rel()))); got != 0o600 {
		t.Errorf("file mode = %o, want 600", got)
	}
	for _, d := range []string{"2026", "2026/housing", docDir} {
		if got := perm(t, filepath.Join(out, filepath.FromSlash(d))); got != 0o700 {
			t.Errorf("dir %s mode = %o, want 700", d, got)
		}
	}
	if files := regularFiles(t, out); len(files) != 1 {
		t.Fatalf("files under output = %v, want 1 (no temp left)", files)
	}

	// A second document in an existing directory: same guarantees.
	doc2 := newDoc(docDir, "2026-04-14_fournisseur-exemple_invoice.pdf")
	if _, err := l.Put(t.Context(), doc2, bytes.NewReader(content)); err != nil {
		t.Fatalf("Put second: %v", err)
	}
	if got := perm(t, filepath.Join(out, filepath.FromSlash(doc2.Path.Rel()))); got != 0o600 {
		t.Errorf("second file mode = %o, want 600", got)
	}
}

func TestLocal_RefusesSymlinkEscape(t *testing.T) {
	t.Parallel()

	t.Run("dir component links outside", func(t *testing.T) {
		t.Parallel()
		l, out, base := newLocal(t)
		outside := outsideDir(t, base)
		mustSymlink(t, outside, filepath.Join(out, "2026"))

		doc := newDoc("2026", "victim.pdf")
		if ok, err := l.Exists(t.Context(), doc); ok {
			t.Fatalf("Exists through an escaping symlink = true (%v), want false or error", err)
		}
		_, err := l.Put(t.Context(), newDoc("2026/housing/fournisseur-exemple", docFile), bytes.NewReader(content))
		if err == nil {
			t.Fatal("Put through an escaping dir symlink succeeded")
		}
		_, err = l.Put(t.Context(), newDoc("2026", docFile), bytes.NewReader(content))
		if err == nil {
			t.Fatal("Put into an escaping dir symlink succeeded")
		}
		wantOutsideUnchanged(t, outside)
	})

	t.Run("final name links to an outside file", func(t *testing.T) {
		t.Parallel()
		l, out, base := newLocal(t)
		outside := outsideDir(t, base)
		r, err := fsx.Open(out)
		if err != nil {
			t.Fatalf("fsx.Open: %v", err)
		}
		if err := r.MkdirPrivate(docDir); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		_ = r.Close()
		mustSymlink(t, filepath.Join(outside, "victim.pdf"), filepath.Join(out, filepath.FromSlash(docDir), docFile))

		doc := newDoc(docDir, docFile)
		if ok, err := l.Exists(t.Context(), doc); ok {
			t.Fatalf("Exists on an escaping symlink = true (%v), want false or error", err)
		}
		_, err = l.Put(t.Context(), doc, bytes.NewReader(content))
		if err == nil {
			t.Fatal("Put over an escaping file symlink succeeded")
		}
		wantOutsideUnchanged(t, outside)
		if fi, err := os.Lstat(filepath.Join(out, filepath.FromSlash(docDir), docFile)); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			t.Fatalf("symlink at the final name was replaced: %v, %v", fi, err)
		}
	})

	t.Run("final name is a dangling link to outside", func(t *testing.T) {
		t.Parallel()
		l, out, base := newLocal(t)
		outside := outsideDir(t, base)
		r, err := fsx.Open(out)
		if err != nil {
			t.Fatalf("fsx.Open: %v", err)
		}
		if err := r.MkdirPrivate(docDir); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		_ = r.Close()
		mustSymlink(t, filepath.Join(outside, "created.pdf"), filepath.Join(out, filepath.FromSlash(docDir), docFile))

		_, err = l.Put(t.Context(), newDoc(docDir, docFile), bytes.NewReader(content))
		if !errors.Is(err, dest.ErrExists) {
			t.Fatalf("Put over a dangling symlink: err = %v, want ErrExists", err)
		}
		wantOutsideUnchanged(t, outside)
	})

	t.Run("output folder itself may be a symlink", func(t *testing.T) {
		t.Parallel()
		// Users point output at e.g. a Drive-synced folder through a link:
		// only links *inside* the output folder are confined.
		_, out, base := newLocal(t)
		link := filepath.Join(base, "link-to-out")
		mustSymlink(t, out, link)
		l, err := local.New(t.Context(), link)
		if err != nil {
			t.Fatalf("New(symlinked output): %v", err)
		}
		t.Cleanup(func() { _ = l.Close() })
		if _, err := l.Put(t.Context(), newDoc(docDir, docFile), bytes.NewReader(content)); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if got := readFile(t, filepath.Join(out, filepath.FromSlash(docDir), docFile)); !bytes.Equal(got, content) {
			t.Fatalf("content = %q", got)
		}
	})
}
