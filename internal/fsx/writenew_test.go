// Tests for (*Root).WriteNew: an atomic create that never replaces anything
// (needed by the local destination, J0 task T21). Symlink and permission
// tests live in writenew_unix_test.go.
//
//	// WriteNew streams src to a fsynced temp file next to name and publishes
//	// it with a hard link, which fails when anything is already at name. The
//	// error then wraps fs.ErrExist and the existing entry is untouched. On any
//	// error no temp file is left behind and name is not created.
//	func (r *Root) WriteNew(ctx context.Context, name string, src io.Reader) error
package fsx_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestWriteNew_CreatesContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file string
		data []byte
	}{
		{name: "at the root", file: "a.pdf", data: []byte("%PDF-1.7 synthetic")},
		{name: "in a sub directory", file: "sub/b.pdf", data: []byte("synthetic in sub")},
		{name: "empty content", file: "empty.pdf", data: nil},
		{name: "larger than one copy buffer", file: "big.pdf", data: bytes.Repeat([]byte("0123456789"), 10<<10)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			mustMkdir(t, r, "sub")
			if err := r.WriteNew(t.Context(), tt.file, bytes.NewReader(tt.data)); err != nil {
				t.Fatalf("WriteNew(%q): %v", tt.file, err)
			}
			if got := readFile(t, filepath.Join(dir, filepath.FromSlash(tt.file))); !bytes.Equal(got, tt.data) {
				t.Fatalf("content = %.40q, want %.40q", got, tt.data)
			}
			parent := filepath.Dir(filepath.Join(dir, filepath.FromSlash(tt.file)))
			if want := []string{filepath.Base(tt.file)}; !slices.Equal(entriesWithout(t, parent, "sub"), want) {
				t.Fatalf("entries = %v, want %v (no temp left)", entries(t, parent), want)
			}
		})
	}
}

// entriesWithout is entries minus the given names.
func entriesWithout(t *testing.T, dir string, skip ...string) []string {
	t.Helper()
	return slices.DeleteFunc(entries(t, dir), func(n string) bool { return slices.Contains(skip, n) })
}

func TestWriteNew_NeverReplaces(t *testing.T) {
	t.Parallel()

	t.Run("existing file", func(t *testing.T) {
		t.Parallel()
		r, dir := openRoot(t)
		if err := r.WriteNew(t.Context(), "a.pdf", strings.NewReader("first")); err != nil {
			t.Fatalf("first WriteNew: %v", err)
		}
		err := r.WriteNew(t.Context(), "a.pdf", strings.NewReader("second"))
		checkErr(t, "second WriteNew", err, fs.ErrExist)
		if got := readFile(t, filepath.Join(dir, "a.pdf")); string(got) != "first" {
			t.Fatalf("content replaced: %q", got)
		}
		if got := entries(t, dir); !slices.Equal(got, []string{"a.pdf"}) {
			t.Fatalf("entries = %v, want only a.pdf", got)
		}
	})

	t.Run("existing directory", func(t *testing.T) {
		t.Parallel()
		r, dir := openRoot(t)
		mustMkdir(t, r, "d")
		err := r.WriteNew(t.Context(), "d", strings.NewReader("data"))
		checkErr(t, "WriteNew over a directory", err, fs.ErrExist)
		if fi, err := os.Lstat(filepath.Join(dir, "d")); err != nil || !fi.IsDir() {
			t.Fatalf("directory replaced: %v, %v", fi, err)
		}
		if got := entries(t, dir); !slices.Equal(got, []string{"d"}) {
			t.Fatalf("entries = %v, want only d", got)
		}
	})

	t.Run("created while streaming", func(t *testing.T) {
		t.Parallel()
		// The fast pre-check passes; the name appears before the publish:
		// the link itself must refuse it.
		r, dir := openRoot(t)
		src := &hookReader{data: []byte("late writer"), hook: func() {
			mustWriteRaw(t, filepath.Join(dir, "a.pdf"), []byte("winner"), 0o600)
		}}
		err := r.WriteNew(t.Context(), "a.pdf", src)
		checkErr(t, "WriteNew", err, fs.ErrExist)
		if got := readFile(t, filepath.Join(dir, "a.pdf")); string(got) != "winner" {
			t.Fatalf("content replaced: %q", got)
		}
		if got := entries(t, dir); !slices.Equal(got, []string{"a.pdf"}) {
			t.Fatalf("entries = %v, want only a.pdf (no temp left)", got)
		}
	})
}

// hookReader runs hook once, on the first Read, then returns data.
type hookReader struct {
	data []byte
	hook func()
	done bool
}

func (h *hookReader) Read(p []byte) (int, error) {
	if !h.done {
		h.done = true
		h.hook()
	}
	if len(h.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, h.data)
	h.data = h.data[n:]
	return n, nil
}

func TestWriteNew_ConcurrentSingleWinner(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	const n = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []int
		errs    []error
	)
	for i := range n {
		wg.Go(func() {
			body := fmt.Sprintf("writer %d %s", i, strings.Repeat("x", 64<<10))
			err := r.WriteNew(context.Background(), "a.pdf", strings.NewReader(body))
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
		t.Fatalf("%d writers succeeded (%v), want exactly 1; errors: %v", len(winners), winners, errs)
	}
	for _, err := range errs {
		checkErr(t, "losing WriteNew", err, fs.ErrExist)
	}
	if want := fmt.Sprintf("writer %d ", winners[0]); !bytes.HasPrefix(readFile(t, filepath.Join(dir, "a.pdf")), []byte(want)) {
		t.Fatalf("stored content is not the winner's")
	}
	if got := entries(t, dir); !slices.Equal(got, []string{"a.pdf"}) {
		t.Fatalf("entries = %v, want only a.pdf (no temp left)", got)
	}
}

func TestWriteNew_ErrorsLeaveNothing(t *testing.T) {
	t.Parallel()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  func() context.Context
		file string
		src  func(cancel context.CancelFunc) io.Reader
		want error
		// retry: the same name must be writable after the failure.
		retry bool
	}{
		{name: "reader error", file: "a.pdf", src: func(context.CancelFunc) io.Reader { return &failingReader{n: 100} }, want: errBoom, retry: true},
		{name: "canceled before", ctx: func() context.Context { return canceled }, file: "a.pdf", want: context.Canceled, retry: true},
		{name: "canceled mid stream", file: "a.pdf", src: func(c context.CancelFunc) io.Reader {
			return &hookReader{data: []byte("partial"), hook: c}
		}, want: context.Canceled, retry: true},
		{name: "missing parent", file: "missing/a.pdf", want: fs.ErrNotExist},
		{name: "invalid name", file: "../a.pdf", want: fsx.ErrInvalidName},
		{name: "empty name", file: "", want: fsx.ErrInvalidName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.ctx != nil {
				ctx = tt.ctx()
			}
			var src io.Reader = strings.NewReader("synthetic")
			if tt.src != nil {
				src = tt.src(cancel)
			}
			err := r.WriteNew(ctx, tt.file, src)
			checkErr(t, "WriteNew", err, tt.want)
			if got := entries(t, dir); len(got) != 0 {
				t.Fatalf("entries = %v, want none", got)
			}
			// Nothing left blocks a later write.
			if tt.retry {
				if err := r.WriteNew(t.Context(), tt.file, strings.NewReader("ok")); err != nil {
					t.Fatalf("WriteNew after failure: %v", err)
				}
			}
		})
	}
}

func TestWriteNew_ClosedRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.WriteNew(t.Context(), "a.pdf", strings.NewReader("x")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("WriteNew on a closed root: err = %v, want os.ErrClosed", err)
	}
	if got := entries(t, dir); len(got) != 0 {
		t.Fatalf("entries = %v, want none", got)
	}
}
