// Tests for the ErrLinkUnsupported classification (J0 follow-up, decision:
// denylist). A link error that means something other than "this filesystem
// cannot hard-link" (disk full, quota, access denied, read-only, missing
// path, I/O error, name too long, canceled context) must keep its original
// error instead of being reported as ErrLinkUnsupported, which would send the
// user to reformat a disk that is merely full. Errnos are matched through
// errors.As on syscall.Errno, not fs.ErrPermission (which also matches the
// EPERM that FAT returns for "no hard links").
//
// The per-OS errno rows live in linkclass_{unix,windows}_internal_test.go as
// keptLinkErrnos and unsupportedLinkErrnos. These tests swap linkFunc, so
// they are NOT parallel.
package fsx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

type keptLinkErr struct {
	name string
	err  error
}

// keptLinkErrors returns every link error that must not map to
// ErrLinkUnsupported: the OS-specific errnos, bare, inside *os.LinkError and
// wrapped once more, plus canceled or expired contexts.
func keptLinkErrors() []keptLinkErr {
	var out []keptLinkErr
	for _, e := range keptLinkErrnos {
		out = append(out,
			keptLinkErr{name: "bare " + e.name, err: e.errno},
			keptLinkErr{name: "LinkError " + e.name, err: &os.LinkError{Op: "link", Old: "a", New: "b", Err: e.errno}},
			keptLinkErr{name: "wrapped " + e.name, err: fmt.Errorf("outer: %w", &os.LinkError{Op: "link", Old: "a", New: "b", Err: e.errno})},
		)
	}
	return append(out,
		keptLinkErr{name: "canceled", err: context.Canceled},
		keptLinkErr{name: "deadline", err: context.DeadlineExceeded},
		keptLinkErr{name: "wrapped canceled", err: fmt.Errorf("link: %w", context.Canceled)},
	)
}

func TestWriteNew_NonLinkFailuresKeepTheirError(t *testing.T) {
	for _, tt := range keptLinkErrors() {
		t.Run(tt.name, func(t *testing.T) {
			setLinkFunc(t, func(*os.Root, string, string) error { return tt.err })
			r, dir := privateRoot(t)

			err := r.WriteNew(t.Context(), "sub/x.pdf", strings.NewReader(contentMarker))
			if err == nil {
				t.Fatal("WriteNew: nil error, want the link error")
			}
			if errors.Is(err, ErrLinkUnsupported) {
				t.Errorf("WriteNew error = %v, must not wrap ErrLinkUnsupported", err)
			}
			if !errors.Is(err, tt.err) {
				t.Errorf("WriteNew error = %v, want it to wrap the original %v", err, tt.err)
			}
			msg := err.Error()
			if !strings.Contains(msg, "fsx write") || !strings.Contains(msg, "sub") {
				t.Errorf("error %q must keep the fsx context and name %q", msg, "sub")
			}
			if strings.Contains(msg, contentMarker) {
				t.Errorf("error %q leaks the content", msg)
			}
			if got := dirEntries(t, filepath.Join(dir, "sub")); len(got) != 0 {
				t.Errorf("sub entries = %v, want none (no file, no temp)", got)
			}
		})
	}
}

func TestProbeLink_NonLinkFailuresKeepTheirError(t *testing.T) {
	for _, tt := range keptLinkErrors() {
		t.Run(tt.name, func(t *testing.T) {
			setLinkFunc(t, func(*os.Root, string, string) error { return tt.err })
			r, dir := privateRoot(t)
			before := dirEntries(t, dir)

			err := r.ProbeLink(t.Context())
			if err == nil {
				t.Fatal("ProbeLink: nil error, want the link error")
			}
			if errors.Is(err, ErrLinkUnsupported) {
				t.Errorf("ProbeLink error = %v, must not wrap ErrLinkUnsupported", err)
			}
			if !errors.Is(err, tt.err) {
				t.Errorf("ProbeLink error = %v, want it to wrap the original %v", err, tt.err)
			}
			// The directory is quoted with %q: on Windows its backslashes are
			// escaped, so look for the quoted form.
			if msg := err.Error(); !strings.Contains(msg, "fsx probe link") || !strings.Contains(msg, strconv.Quote(dir)) {
				t.Errorf("error %q must keep the fsx context and name %q", msg, dir)
			}
			if after := dirEntries(t, dir); !slices.Equal(after, before) {
				t.Errorf("entries after failed probe = %v, want %v (no temp left)", after, before)
			}
		})
	}
}

// Errnos outside the denylist still mean "no hard links here", and the errno
// stays in the chain next to the sentinel.
func TestLink_OtherErrnosAreErrLinkUnsupported(t *testing.T) {
	for _, e := range unsupportedLinkErrnos {
		t.Run("write new "+e.name, func(t *testing.T) {
			setLinkFunc(t, func(*os.Root, string, string) error {
				return &os.LinkError{Op: "link", Old: "a", New: "b", Err: e.errno}
			})
			r, _ := privateRoot(t)
			err := r.WriteNew(t.Context(), "sub/x.pdf", strings.NewReader(contentMarker))
			if !errors.Is(err, ErrLinkUnsupported) {
				t.Fatalf("WriteNew error = %v, want ErrLinkUnsupported", err)
			}
			var got syscall.Errno
			if !errors.As(err, &got) || got != e.errno {
				t.Errorf("WriteNew error = %v, want the errno %v still in the chain", err, e.errno)
			}
		})
		t.Run("probe "+e.name, func(t *testing.T) {
			setLinkFunc(t, func(*os.Root, string, string) error { return e.errno })
			r, _ := privateRoot(t)
			if err := r.ProbeLink(t.Context()); !errors.Is(err, ErrLinkUnsupported) {
				t.Fatalf("ProbeLink error = %v, want ErrLinkUnsupported", err)
			}
		})
	}
}
