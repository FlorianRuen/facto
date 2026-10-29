//go:build unix

// Permission-mode and symlink tests for package fsx (J0 task T2). See
// fsx_test.go for the expected API.
package fsx_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func mustMkdirRaw(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatalf("setup Mkdir(%q): %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setup Chmod(%q): %v", path, err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("setup Symlink(%q -> %q): %v", link, target, err)
	}
}

func TestWriteAtomic_PrivateAndAtomic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		oldMode fs.FileMode // 0 = no existing file
	}{
		{name: "new file is 0600"},
		{name: "replacing a 0644 file yields 0600", oldMode: 0o644},
		{name: "replacing a 0666 file yields 0600", oldMode: 0o666},
		{name: "replacing a 0400 file yields 0600", oldMode: 0o400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			target := filepath.Join(dir, "doc.pdf")
			if tt.oldMode != 0 {
				mustWriteRaw(t, target, []byte("old"), tt.oldMode)
			}
			if err := r.WriteAtomic(context.Background(), "doc.pdf", []byte("new")); err != nil {
				t.Fatalf("WriteAtomic: %v", err)
			}
			if got := perm(t, target); got != 0o600 {
				t.Fatalf("mode = %#o, want 0600", got)
			}
			if got := string(readFile(t, target)); got != "new" {
				t.Fatalf("content = %q, want %q", got, "new")
			}
			if got := entries(t, dir); len(got) != 1 {
				t.Fatalf("entries = %v, want only doc.pdf", got)
			}
		})
	}
}

func TestWriteAtomicFrom_Private(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	if err := r.WriteAtomicFrom(context.Background(), "s.pdf", strings.NewReader("pdf")); err != nil {
		t.Fatalf("WriteAtomicFrom: %v", err)
	}
	if got := perm(t, filepath.Join(dir, "s.pdf")); got != 0o600 {
		t.Fatalf("mode = %#o, want 0600", got)
	}
}

func TestMkdirPrivate_Mode(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	if err := r.MkdirPrivate("state/sessions/x"); err != nil {
		t.Fatalf("MkdirPrivate: %v", err)
	}
	for _, p := range []string{"state", "state/sessions", "state/sessions/x"} {
		if got := perm(t, filepath.Join(dir, filepath.FromSlash(p))); got != 0o700 {
			t.Fatalf("%s mode = %#o, want 0700", p, got)
		}
	}
}

func TestMkdirPrivate_RefusesExistingBroadDir(t *testing.T) {
	t.Parallel()

	for _, mode := range []fs.FileMode{0o755, 0o750, 0o701, 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			path := filepath.Join(dir, "shared")
			mustMkdirRaw(t, path, mode)

			err := r.MkdirPrivate("shared")
			if !errors.Is(err, fsx.ErrInsecurePerms) {
				t.Fatalf("MkdirPrivate on %#o dir: err = %v, want fsx.ErrInsecurePerms", mode, err)
			}
			if got := perm(t, path); got != mode {
				t.Fatalf("mode changed to %#o, want untouched %#o", got, mode)
			}
		})
	}
}

func TestAppendPrivate_Mode(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	if err := r.AppendPrivate("canaries.txt", []byte("a\n")); err != nil {
		t.Fatalf("AppendPrivate: %v", err)
	}
	if err := r.AppendPrivate("canaries.txt", []byte("b\n")); err != nil {
		t.Fatalf("AppendPrivate: %v", err)
	}
	if got := perm(t, filepath.Join(dir, "canaries.txt")); got != 0o600 {
		t.Fatalf("mode = %#o, want 0600", got)
	}
}

func TestAppendPrivate_RefusesBroadExistingFile(t *testing.T) {
	t.Parallel()

	for _, mode := range []fs.FileMode{0o644, 0o640, 0o604, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			path := filepath.Join(dir, "run.log")
			mustWriteRaw(t, path, []byte("old\n"), mode)

			err := r.AppendPrivate("run.log", []byte("new\n"))
			if !errors.Is(err, fsx.ErrInsecurePerms) {
				t.Fatalf("AppendPrivate on %#o file: err = %v, want fsx.ErrInsecurePerms", mode, err)
			}
			if got := string(readFile(t, path)); got != "old\n" {
				t.Fatalf("content = %q, want unchanged %q", got, "old\n")
			}
		})
	}
}

func TestCheckPrivate_RejectsBroadPerms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dir     bool
		mode    fs.FileMode
		wantErr error
	}{
		{name: "file 0600", mode: 0o600},
		{name: "file 0400", mode: 0o400},
		{name: "file 0700", mode: 0o700},
		{name: "file 0640 group read", mode: 0o640, wantErr: fsx.ErrInsecurePerms},
		{name: "file 0620 group write", mode: 0o620, wantErr: fsx.ErrInsecurePerms},
		{name: "file 0604 world read", mode: 0o604, wantErr: fsx.ErrInsecurePerms},
		{name: "file 0644", mode: 0o644, wantErr: fsx.ErrInsecurePerms},
		{name: "file 0666", mode: 0o666, wantErr: fsx.ErrInsecurePerms},
		{name: "dir 0700", dir: true, mode: 0o700},
		{name: "dir 0500", dir: true, mode: 0o500},
		{name: "dir 0710 group traverse", dir: true, mode: 0o710, wantErr: fsx.ErrInsecurePerms},
		{name: "dir 0701 world traverse", dir: true, mode: 0o701, wantErr: fsx.ErrInsecurePerms},
		{name: "dir 0750", dir: true, mode: 0o750, wantErr: fsx.ErrInsecurePerms},
		{name: "dir 0755", dir: true, mode: 0o755, wantErr: fsx.ErrInsecurePerms},
		{name: "dir 0777", dir: true, mode: 0o777, wantErr: fsx.ErrInsecurePerms},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "x")
			if tt.dir {
				// Empty, so TempDir cleanup removes it even at 0500.
				mustMkdirRaw(t, path, tt.mode)
			} else {
				mustWriteRaw(t, path, []byte("x"), tt.mode)
			}
			err := fsx.CheckPrivate(path)
			checkErr(t, "CheckPrivate", err, tt.wantErr)
		})
	}
}

// A private-looking symlink must not hide a broad target: CheckPrivate follows it.
func TestCheckPrivate_FollowsSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	mustWriteRaw(t, target, []byte("x"), 0o644)
	link := filepath.Join(dir, "link")
	mustSymlink(t, target, link)

	if err := fsx.CheckPrivate(link); !errors.Is(err, fsx.ErrInsecurePerms) {
		t.Fatalf("CheckPrivate(link to 0644): err = %v, want fsx.ErrInsecurePerms", err)
	}
}

// Security negative: symlinks inside the root that point outside it must never
// let a write, append, mkdir or remove reach the outside directory.
func TestRoot_RefusesSymlinkEscape(t *testing.T) {
	t.Parallel()

	type layout struct {
		root, outside string
	}
	// Each case builds root/ and outside/ (siblings) and a hostile symlink.
	tests := []struct {
		name  string
		link  func(l layout) (target, linkName string) // symlink created at root/linkName
		op    func(r *fsx.Root) error
		check func(t *testing.T, l layout) // proves outside is untouched
	}{
		{
			name: "WriteAtomic through absolute dir symlink",
			link: func(l layout) (string, string) { return l.outside, "esc" },
			op:   func(r *fsx.Root) error { return r.WriteAtomic(context.Background(), "esc/planted", []byte("pwned")) },
			check: func(t *testing.T, l layout) {
				assertAbsent(t, filepath.Join(l.outside, "planted"))
			},
		},
		{
			name: "WriteAtomic through relative dir symlink",
			link: func(_ layout) (string, string) { return "../outside", "esc" },
			op:   func(r *fsx.Root) error { return r.WriteAtomic(context.Background(), "esc/planted", []byte("pwned")) },
			check: func(t *testing.T, l layout) {
				assertAbsent(t, filepath.Join(l.outside, "planted"))
			},
		},
		{
			name: "WriteAtomicFrom through dir symlink",
			link: func(l layout) (string, string) { return l.outside, "esc" },
			op: func(r *fsx.Root) error {
				return r.WriteAtomicFrom(context.Background(), "esc/planted", strings.NewReader("pwned"))
			},
			check: func(t *testing.T, l layout) {
				assertAbsent(t, filepath.Join(l.outside, "planted"))
			},
		},
		{
			name: "AppendPrivate through file symlink",
			link: func(l layout) (string, string) { return filepath.Join(l.outside, "victim"), "log" },
			op:   func(r *fsx.Root) error { return r.AppendPrivate("log", []byte("pwned")) },
			check: func(t *testing.T, l layout) {
				assertContent(t, filepath.Join(l.outside, "victim"), "untouched")
			},
		},
		{
			name: "AppendPrivate through dir symlink",
			link: func(l layout) (string, string) { return l.outside, "esc" },
			op:   func(r *fsx.Root) error { return r.AppendPrivate("esc/victim", []byte("pwned")) },
			check: func(t *testing.T, l layout) {
				assertContent(t, filepath.Join(l.outside, "victim"), "untouched")
			},
		},
		{
			name: "MkdirPrivate through dir symlink",
			link: func(l layout) (string, string) { return l.outside, "esc" },
			op:   func(r *fsx.Root) error { return r.MkdirPrivate("esc/newdir") },
			check: func(t *testing.T, l layout) {
				assertAbsent(t, filepath.Join(l.outside, "newdir"))
			},
		},
		{
			name: "Remove through dir symlink",
			link: func(l layout) (string, string) { return l.outside, "esc" },
			op:   func(r *fsx.Root) error { return r.Remove("esc/victim") },
			check: func(t *testing.T, l layout) {
				assertContent(t, filepath.Join(l.outside, "victim"), "untouched")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			l := layout{root: filepath.Join(base, "root"), outside: filepath.Join(base, "outside")}
			mustMkdirRaw(t, l.root, 0o700)
			mustMkdirRaw(t, l.outside, 0o700)
			mustWriteRaw(t, filepath.Join(l.outside, "victim"), []byte("untouched"), 0o600)
			target, name := tt.link(l)
			mustSymlink(t, target, filepath.Join(l.root, name))

			r, err := fsx.Open(l.root)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = r.Close() })

			if err := tt.op(r); err == nil {
				t.Fatal("err = nil, want an error for a symlink escaping the root")
			}
			tt.check(t, l)
			if got := entries(t, l.outside); len(got) != 1 || got[0] != "victim" {
				t.Fatalf("outside entries = %v, want [victim]", got)
			}
		})
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s exists outside the root (err = %v)", path, err)
	}
}

func assertContent(t *testing.T, path, want string) {
	t.Helper()
	if got := string(readFile(t, path)); got != want {
		t.Fatalf("%s content = %q, want %q", path, got, want)
	}
}
