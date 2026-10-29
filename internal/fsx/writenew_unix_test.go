//go:build unix

// Permission and symlink tests for (*Root).WriteNew. See writenew_test.go.
package fsx_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestWriteNew_Private(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	if err := r.WriteNew(t.Context(), "a.pdf", strings.NewReader("synthetic")); err != nil {
		t.Fatalf("WriteNew: %v", err)
	}
	if got := perm(t, filepath.Join(dir, "a.pdf")); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

func TestWriteNew_RefusesSymlinks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// target is relative to the outside dir; "" means the outside dir.
		target string
		link   string // created inside the root
		write  string // name passed to WriteNew
		want   error  // errAny: any error
	}{
		{name: "final name links to an outside file", target: "victim.pdf", link: "a.pdf", write: "a.pdf", want: fs.ErrExist},
		{name: "final name is a dangling link to outside", target: "created.pdf", link: "a.pdf", write: "a.pdf", want: fs.ErrExist},
		{name: "parent links outside", target: "", link: "sub", write: "sub/a.pdf", want: errAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			outside := t.TempDir()
			mustWriteRaw(t, filepath.Join(outside, "victim.pdf"), []byte("outside"), 0o600)
			mustSymlink(t, filepath.Join(outside, tt.target), filepath.Join(dir, tt.link))

			err := r.WriteNew(t.Context(), tt.write, strings.NewReader("attacker"))
			checkErr(t, "WriteNew", err, tt.want)
			if got := entries(t, outside); !slices.Equal(got, []string{"victim.pdf"}) {
				t.Fatalf("outside entries = %v, want only victim.pdf", got)
			}
			assertContent(t, filepath.Join(outside, "victim.pdf"), "outside")
			if fi, err := os.Lstat(filepath.Join(dir, tt.link)); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
				t.Fatalf("symlink replaced: %v, %v", fi, err)
			}
			if got := entries(t, dir); !slices.Equal(got, []string{tt.link}) {
				t.Fatalf("root entries = %v, want only %s (no temp left)", got, tt.link)
			}
		})
	}
}
