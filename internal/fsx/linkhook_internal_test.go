// Tests for hard-link support in package fsx (J0 review follow-up): WriteNew
// publishes with a hard link, so a filesystem without hard links (FAT,
// exFAT, some network or FUSE mounts) must fail with a clear sentinel, and
// the local destination must be able to probe for it at startup.
//
// Expected API and behaviour (implementer: follow exactly):
//
//		// ErrLinkUnsupported reports that the filesystem holding the target
//		// directory refused to create a hard link (WriteNew needs one).
//		var ErrLinkUnsupported = errors.New(…)
//
//		// linkFunc is the hard-link primitive used by WriteNew and ProbeLink:
//		// (*os.Root).Link in production, replaced by internal tests only.
//		var linkFunc = (*os.Root).Link   // func(*os.Root, string, string) error
//
//		// ProbeLink checks once that the root directory supports hard links:
//		// it creates a temp file in the root directory (0600), hard-links it
//		// to a second temp name through linkFunc, then removes both. On
//		// success the directory is left exactly as it was. When the link fails
//		// the error wraps ErrLinkUnsupported, names the root directory
//		// (os.Root.Name) and no temp file is left behind.
//		func (r *Root) ProbeLink(ctx context.Context) error
//
//	  - WriteNew calls linkFunc to publish. A link error that is fs.ErrExist
//	    keeps today's behaviour (wraps fs.ErrExist, never
//	    ErrLinkUnsupported). Any other link error is mapped to an error
//	    wrapping ErrLinkUnsupported (and not fs.ErrExist) whose message names
//	    the target directory (the parent of name) and never contains the
//	    written content. As for every WriteNew error, name is not created and
//	    no temp file is left behind.
//
// These tests swap the package-level linkFunc, so they are NOT parallel
// (parallel tests of the package only start after them) and restore it with
// t.Cleanup.
package fsx

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// contentMarker is synthetic file content that must never reach an error.
const contentMarker = "content-marker-z8"

// setLinkFunc replaces linkFunc for the duration of the test.
func setLinkFunc(t *testing.T, f func(r *os.Root, oldname, newname string) error) {
	t.Helper()
	prev := linkFunc
	linkFunc = f
	t.Cleanup(func() { linkFunc = prev })
}

// privateRoot opens a fresh 0700 temp dir with an empty "sub" directory.
func privateRoot(t *testing.T) (*Root, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, dir
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, de := range des {
		out = append(out, de.Name())
	}
	return out
}

func TestWriteNew_LinkFailureIsErrLinkUnsupported(t *testing.T) {
	tests := []struct {
		name    string
		linkErr error
	}{
		{name: "unsupported", linkErr: errors.ErrUnsupported},
		{name: "permission (EPERM on FAT)", linkErr: &os.LinkError{Op: "link", Old: "a", New: "b", Err: os.ErrPermission}},
		{name: "cross device", linkErr: &os.LinkError{Op: "link", Old: "a", New: "b", Err: errors.New("invalid cross-device link")}},
		{name: "too many links", linkErr: &os.LinkError{Op: "link", Old: "a", New: "b", Err: errors.New("too many links")}},
		{name: "plain error", linkErr: errors.New("operation not supported")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			setLinkFunc(t, func(*os.Root, string, string) error {
				calls++
				return tt.linkErr
			})
			r, dir := privateRoot(t)

			err := r.WriteNew(t.Context(), "sub/x.pdf", strings.NewReader(contentMarker))
			if calls != 1 {
				t.Fatalf("linkFunc called %d times, want 1 (WriteNew must publish through linkFunc)", calls)
			}
			if !errors.Is(err, ErrLinkUnsupported) {
				t.Fatalf("WriteNew error = %v, want ErrLinkUnsupported", err)
			}
			if errors.Is(err, fs.ErrExist) {
				t.Errorf("WriteNew error = %v, must not wrap fs.ErrExist", err)
			}
			if msg := err.Error(); !strings.Contains(msg, "sub") || strings.Contains(msg, contentMarker) {
				t.Errorf("error %q must name the target dir %q and never the content", msg, "sub")
			}
			if got := dirEntries(t, filepath.Join(dir, "sub")); len(got) != 0 {
				t.Errorf("sub entries = %v, want none (no file, no temp)", got)
			}
		})
	}
}

func TestWriteNew_LinkExistStaysErrExist(t *testing.T) {
	setLinkFunc(t, func(_ *os.Root, oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: fs.ErrExist}
	})
	r, dir := privateRoot(t)
	err := r.WriteNew(t.Context(), "sub/x.pdf", strings.NewReader(contentMarker))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("WriteNew error = %v, want fs.ErrExist", err)
	}
	if errors.Is(err, ErrLinkUnsupported) {
		t.Errorf("WriteNew error = %v, must not wrap ErrLinkUnsupported", err)
	}
	if got := dirEntries(t, filepath.Join(dir, "sub")); len(got) != 0 {
		t.Errorf("sub entries = %v, want none", got)
	}
}

func TestWriteNew_PublishesThroughLinkFunc(t *testing.T) {
	calls := 0
	setLinkFunc(t, func(r *os.Root, oldname, newname string) error {
		calls++
		return r.Link(oldname, newname)
	})
	r, dir := privateRoot(t)
	if err := r.WriteNew(t.Context(), "sub/x.pdf", strings.NewReader(contentMarker)); err != nil {
		t.Fatalf("WriteNew: %v", err)
	}
	if calls != 1 {
		t.Errorf("linkFunc called %d times, want 1", calls)
	}
	if got := dirEntries(t, filepath.Join(dir, "sub")); !slices.Equal(got, []string{"x.pdf"}) {
		t.Errorf("sub entries = %v, want [x.pdf]", got)
	}
}

func TestProbeLink_SupportedLeavesDirUnchanged(t *testing.T) {
	calls := 0
	setLinkFunc(t, func(r *os.Root, oldname, newname string) error {
		calls++
		return r.Link(oldname, newname)
	})
	r, dir := privateRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "keep.pdf"), []byte(contentMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	before := dirEntries(t, dir)

	if err := r.ProbeLink(t.Context()); err != nil {
		t.Fatalf("ProbeLink: %v", err)
	}
	if calls != 1 {
		t.Errorf("linkFunc called %d times, want exactly 1", calls)
	}
	if after := dirEntries(t, dir); !slices.Equal(after, before) {
		t.Errorf("entries after probe = %v, want %v (both probe files removed)", after, before)
	}
	got, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "keep.pdf")))
	if err != nil || string(got) != contentMarker {
		t.Errorf("existing file changed: %q, %v", got, err)
	}
}

func TestProbeLink_UnsupportedIsErrLinkUnsupported(t *testing.T) {
	tests := []struct {
		name    string
		linkErr error
	}{
		{name: "unsupported", linkErr: errors.ErrUnsupported},
		{name: "permission", linkErr: &os.LinkError{Op: "link", Old: "a", New: "b", Err: os.ErrPermission}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setLinkFunc(t, func(*os.Root, string, string) error { return tt.linkErr })
			r, dir := privateRoot(t)
			before := dirEntries(t, dir)

			err := r.ProbeLink(t.Context())
			if !errors.Is(err, ErrLinkUnsupported) {
				t.Fatalf("ProbeLink error = %v, want ErrLinkUnsupported", err)
			}
			if !strings.Contains(err.Error(), dir) {
				t.Errorf("error %q does not name the directory %q", err, dir)
			}
			if after := dirEntries(t, dir); !slices.Equal(after, before) {
				t.Errorf("entries after failed probe = %v, want %v (no temp left)", after, before)
			}
		})
	}
}

func TestProbeLink_CanceledContext(t *testing.T) {
	r, dir := privateRoot(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := r.ProbeLink(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ProbeLink error = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrLinkUnsupported) {
		t.Errorf("a canceled probe must not report ErrLinkUnsupported: %v", err)
	}
	if got := dirEntries(t, dir); !slices.Equal(got, []string{"sub"}) {
		t.Errorf("entries = %v, want [sub]", got)
	}
}
