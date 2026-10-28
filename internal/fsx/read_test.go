// Tests for the confined read access of package fsx (ReadDir, OpenDir,
// OpenRegular), used by the inbox source (J0 task T22). Symlink and FIFO cases
// live in read_unix_test.go.
package fsx_test

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"reflect"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func dirNames(t *testing.T, r *fsx.Root) []string {
	t.Helper()
	des, err := r.ReadDir()
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	names := make([]string, 0, len(des))
	for _, de := range des {
		names = append(names, de.Name())
	}
	return names
}

func TestReadDir_SortedWithTypes(t *testing.T) {
	t.Parallel()

	r, _ := openRoot(t)
	if got := dirNames(t, r); len(got) != 0 {
		t.Fatalf("empty root lists %v", got)
	}
	mustAtomic(t, r, "b.pdf")
	mustMkdir(t, r, "a")
	mustAtomic(t, r, "a/inner.pdf")
	mustAtomic(t, r, ".hidden")

	des, err := r.ReadDir()
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	type entry struct {
		name string
		dir  bool
	}
	got := make([]entry, 0, len(des))
	for _, de := range des {
		got = append(got, entry{de.Name(), de.IsDir()})
	}
	want := []entry{{".hidden", false}, {"a", true}, {"b.pdf", false}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadDir = %v, want %v (sorted, not recursive)", got, want)
	}
}

func TestOpenDir(t *testing.T) {
	t.Parallel()

	r, _ := openRoot(t)
	mustMkdir(t, r, "d")
	mustMkdir(t, r, "d/e")
	mustAtomic(t, r, "d/f.pdf")

	sub, err := r.OpenDir("d")
	if err != nil {
		t.Fatalf("OpenDir(d): %v", err)
	}
	t.Cleanup(func() { _ = sub.Close() })
	if got, want := dirNames(t, sub), []string{"e", "f.pdf"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sub ReadDir = %v, want %v", got, want)
	}
	nested, err := r.OpenDir("d/e")
	if err != nil {
		t.Fatalf("OpenDir(d/e): %v", err)
	}
	_ = nested.Close()

	tests := []struct {
		name string
		dir  string
		want error
	}{
		{name: "regular file", dir: "d/f.pdf", want: fsx.ErrNotDir},
		{name: "missing", dir: "missing", want: fs.ErrNotExist},
		{name: "escaping", dir: "../x", want: fsx.ErrInvalidName},
		{name: "dot", dir: ".", want: fsx.ErrInvalidName},
		{name: "absolute", dir: "/tmp", want: fsx.ErrInvalidName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sub, err := r.OpenDir(tt.dir)
			if err == nil {
				_ = sub.Close()
			}
			checkErr(t, "OpenDir", err, tt.want)
		})
	}
}

func TestOpenRegular(t *testing.T) {
	t.Parallel()

	r, _ := openRoot(t)
	mustMkdir(t, r, "d")
	mustAtomic(t, r, "d/f.pdf")

	f, err := r.OpenRegular("d/f.pdf")
	if err != nil {
		t.Fatalf("OpenRegular: %v", err)
	}
	b, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(b) != "synthetic" {
		t.Fatalf("read = %q, %v; want the file content", b, err)
	}

	tests := []struct {
		name string
		file string
		want error
	}{
		{name: "directory", file: "d", want: fsx.ErrNotRegular},
		{name: "missing", file: "d/missing.pdf", want: fs.ErrNotExist},
		{name: "escaping", file: "d/../../x", want: fsx.ErrInvalidName},
		{name: "empty", file: "", want: fsx.ErrInvalidName},
		{name: "nul", file: "d/\x00f.pdf", want: fsx.ErrInvalidName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f, err := r.OpenRegular(tt.file)
			if err == nil {
				_ = f.Close()
			}
			checkErr(t, "OpenRegular", err, tt.want)
		})
	}
}

func TestReadAccess_ClosedRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	mustMkdir(t, r, "d")
	mustAtomic(t, r, "f")
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := r.ReadDir(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("ReadDir after Close: err = %v, want os.ErrClosed", err)
	}
	if _, err := r.OpenDir("d"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("OpenDir after Close: err = %v, want os.ErrClosed", err)
	}
	if _, err := r.OpenRegular("f"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("OpenRegular after Close: err = %v, want os.ErrClosed", err)
	}
}
