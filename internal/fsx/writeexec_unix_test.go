//go:build unix

// Tests for (*Root).WriteAtomicExec (J1 task T11): the 0700 atomic write the
// Chrome for Testing unzip uses for executables (ADR 0008, "Chrome for
// Testing (A10)"). Helpers (openRoot, entries, readFile, mustWriteRaw, perm,
// mustMkdirRaw, mustSymlink, assertContent, failingReader, errBoom) live in
// fsx_test.go and fsx_unix_test.go.
//
// Expected API (implementer: follow exactly):
//
//	// WriteAtomicExec is WriteAtomicFrom for executables: same temp file in
//	// the same directory, fsync, close, rename, but the final file mode is
//	// exactly 0700 whatever the umask or the mode of a replaced file (never
//	// setuid, setgid, sticky, group or world bits). It replaces an existing
//	// regular file. It refuses, with nothing changed, when name already
//	// exists as a symlink (dangling or not, never followed) or as anything
//	// other than a regular file (directory, FIFO...). On any error the
//	// previous content of name is untouched and no temp file is left
//	// behind. Invalid names wrap ErrInvalidName; a missing parent wraps
//	// fs.ErrNotExist; a canceled ctx wraps ctx.Err().
//	func (r *Root) WriteAtomicExec(ctx context.Context, name string, src io.Reader) error
package fsx_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestWriteAtomicExec_Mode0700(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		oldMode fs.FileMode // 0: no existing file
	}{
		{name: "new file is 0700"},
		{name: "replacing a 0600 file yields 0700", oldMode: 0o600},
		{name: "replacing a 0644 file yields 0700", oldMode: 0o644},
		{name: "replacing a 0755 file yields 0700", oldMode: 0o755},
		{name: "replacing a 0777 file yields 0700", oldMode: 0o777},
		{name: "replacing a setuid file yields 0700 without setuid", oldMode: 0o4755},
		{name: "replacing a setgid file yields 0700 without setgid", oldMode: 0o2755},
		{name: "replacing a sticky file yields 0700 without sticky", oldMode: 0o1755},
		{name: "replacing a 0400 file yields 0700", oldMode: 0o400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			mustMkdir(t, r, "bin")
			target := filepath.Join(dir, "bin", "chrome")
			if tt.oldMode != 0 {
				mustWriteRaw(t, target, []byte("old"), tt.oldMode)
			}
			if err := r.WriteAtomicExec(t.Context(), "bin/chrome", strings.NewReader("#!synthetic\n")); err != nil {
				t.Fatalf("WriteAtomicExec: %v", err)
			}
			fi, err := os.Lstat(target)
			if err != nil {
				t.Fatalf("Lstat: %v", err)
			}
			if !fi.Mode().IsRegular() {
				t.Fatalf("type = %v, want a regular file", fi.Mode().Type())
			}
			if got := fi.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky); got != 0o700 {
				t.Fatalf("mode = %v, want exactly 0700 (no setuid/setgid/sticky)", fi.Mode())
			}
			if got := string(readFile(t, target)); got != "#!synthetic\n" {
				t.Fatalf("content = %q, want the new content", got)
			}
			if got := entries(t, filepath.Join(dir, "bin")); !slices.Equal(got, []string{"chrome"}) {
				t.Fatalf("entries = %v, want [chrome] (no temp left)", got)
			}
		})
	}
}

func TestWriteAtomicExec_RefusesExistingSymlink(t *testing.T) {
	t.Parallel()

	type layout struct{ root, outside string }
	tests := []struct {
		name string
		// link returns the symlink target and its name under root.
		link func(l layout) (target, linkName string)
		file string // name passed to WriteAtomicExec
	}{
		{
			name: "absolute symlink to a file outside the root",
			link: func(l layout) (string, string) { return filepath.Join(l.outside, "victim"), "chrome" },
			file: "chrome",
		},
		{
			name: "relative symlink to a file outside the root",
			link: func(layout) (string, string) { return "../outside/victim", "chrome" },
			file: "chrome",
		},
		{
			name: "symlink to a file inside the root",
			link: func(layout) (string, string) { return "inside", "chrome" },
			file: "chrome",
		},
		{
			name: "dangling symlink",
			link: func(l layout) (string, string) { return filepath.Join(l.outside, "missing"), "chrome" },
			file: "chrome",
		},
		{
			name: "symlink to a directory outside the root",
			link: func(l layout) (string, string) { return l.outside, "chrome" },
			file: "chrome",
		},
		{
			name: "parent directory is a symlink outside the root",
			link: func(l layout) (string, string) { return l.outside, "esc" },
			file: "esc/victim",
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
			mustWriteRaw(t, filepath.Join(l.root, "inside"), []byte("inside untouched"), 0o600)
			target, linkName := tt.link(l)
			mustSymlink(t, target, filepath.Join(l.root, linkName))

			r, err := fsx.Open(l.root)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = r.Close() })

			if err := r.WriteAtomicExec(t.Context(), tt.file, strings.NewReader("pwned")); err == nil {
				t.Fatal("err = nil, want a refusal: an existing symlink must never be replaced or followed")
			}
			got, err := os.Readlink(filepath.Join(l.root, linkName))
			if err != nil {
				t.Fatalf("symlink was replaced or removed: %v", err)
			}
			if got != target {
				t.Fatalf("symlink target = %q, want %q", got, target)
			}
			assertContent(t, filepath.Join(l.outside, "victim"), "untouched")
			assertContent(t, filepath.Join(l.root, "inside"), "inside untouched")
			if p := perm(t, filepath.Join(l.outside, "victim")); p != 0o600 {
				t.Fatalf("outside victim mode = %#o, want 0600 (not chmodded through the link)", p)
			}
			if got := entries(t, l.outside); !slices.Equal(got, []string{"victim"}) {
				t.Fatalf("outside entries = %v, want [victim]", got)
			}
			want := []string{"inside", linkName}
			slices.Sort(want)
			if got := entries(t, l.root); !slices.Equal(got, want) {
				t.Fatalf("root entries = %v, want %v (no temp left)", got, want)
			}
		})
	}
}

func TestWriteAtomicExec_Atomic(t *testing.T) {
	t.Parallel()

	const old = "previous complete executable"
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name    string
		ctx     context.Context
		src     func() *failingReader
		wantErr error
	}{
		{
			name:    "reader fails before any byte",
			ctx:     context.Background(),
			src:     func() *failingReader { return &failingReader{n: 0} },
			wantErr: errBoom,
		},
		{
			name:    "reader fails after more than one copy buffer",
			ctx:     context.Background(),
			src:     func() *failingReader { return &failingReader{n: 100 << 10} },
			wantErr: errBoom,
		},
		{
			name:    "canceled context",
			ctx:     canceled,
			src:     func() *failingReader { return &failingReader{n: 1 << 20} },
			wantErr: context.Canceled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			target := filepath.Join(dir, "chrome")
			mustWriteRaw(t, target, []byte(old), 0o700)

			err := r.WriteAtomicExec(tt.ctx, "chrome", tt.src())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want errors.Is %v", err, tt.wantErr)
			}
			if got := string(readFile(t, target)); got != old {
				t.Fatalf("content = %q, want the previous content untouched", got)
			}
			if p := perm(t, target); p != 0o700 {
				t.Fatalf("mode = %#o, want the previous 0700", p)
			}
			if got := entries(t, dir); !slices.Equal(got, []string{"chrome"}) {
				t.Fatalf("entries = %v, want [chrome] (no temp left)", got)
			}
		})
	}

	t.Run("new name not created on failure", func(t *testing.T) {
		t.Parallel()
		r, dir := openRoot(t)
		if err := r.WriteAtomicExec(t.Context(), "chrome", &failingReader{n: 10}); !errors.Is(err, errBoom) {
			t.Fatalf("err = %v, want errors.Is errBoom", err)
		}
		if got := entries(t, dir); len(got) != 0 {
			t.Fatalf("entries = %v, want none", got)
		}
	})
}

func TestWriteAtomicExec_RefusesBadTargets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		file    string
		wantErr error // nil: any non-nil error
	}{
		{name: "empty name", file: "", wantErr: fsx.ErrInvalidName},
		{name: "dot", file: ".", wantErr: fsx.ErrInvalidName},
		{name: "parent escape", file: "../chrome", wantErr: fsx.ErrInvalidName},
		{name: "nested parent escape", file: "a/../../chrome", wantErr: fsx.ErrInvalidName},
		{name: "absolute", file: "/tmp/chrome", wantErr: fsx.ErrInvalidName},
		{name: "NUL byte", file: "chr\x00ome", wantErr: fsx.ErrInvalidName},
		{name: "missing parent", file: "nodir/chrome", wantErr: fs.ErrNotExist},
		{
			name:  "existing directory",
			setup: func(t *testing.T, dir string) { mustMkdirRaw(t, filepath.Join(dir, "chrome"), 0o700) },
			file:  "chrome",
		},
		{
			name: "existing FIFO",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := syscall.Mkfifo(filepath.Join(dir, "chrome"), 0o600); err != nil {
					t.Fatalf("setup Mkfifo: %v", err)
				}
			},
			file: "chrome",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			before := entries(t, dir)
			err := r.WriteAtomicExec(t.Context(), tt.file, strings.NewReader("x"))
			if err == nil {
				t.Fatal("err = nil, want a refusal")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want errors.Is %v", err, tt.wantErr)
			}
			if got := entries(t, dir); !slices.Equal(got, before) {
				t.Fatalf("entries = %v, want %v (nothing created, no temp left)", got, before)
			}
		})
	}
}
