// Tests for the local destination's hard-link handling (J0 review
// follow-up). fsx.WriteNew publishes with a hard link; an output folder on a
// filesystem without hard links must be refused once, at startup, instead of
// failing on every Put.
//
// Expected API and behaviour (implementer: follow exactly):
//
//		// probeLink and writeNew are the fsx calls New and Put go through:
//		// method expressions in production, replaced by internal tests only.
//		// (fsx's own linkFunc hook is unexported and cannot be reached from
//		// this package.)
//		var probeLink = (*fsx.Root).ProbeLink // func(*fsx.Root, context.Context) error
//		var writeNew = (*fsx.Root).WriteNew   // func(*fsx.Root, context.Context, string, io.Reader) error
//
//	  - New(dir) opens dir, then calls probeLink exactly once. If the probe
//	    fails, New closes the root and returns nil and an error wrapping the
//	    probe error (so errors.Is(err, fsx.ErrLinkUnsupported) holds when the
//	    filesystem has no hard links). Put and Exists never probe again. A
//	    successful probe leaves the output folder exactly as it was.
//	  - Put publishes through writeNew. When the error wraps
//	    fsx.ErrNotDurable (the file WAS published, only the directory fsync
//	    failed), Put returns the RemoteRef{Destination: "local", ID: rel}
//	    TOGETHER with an error wrapping fsx.ErrNotDurable, so the caller can
//	    record the document and retry durability later; the doc comment of
//	    Put must say so. Every other error keeps returning a zero RemoteRef
//	    (an error wrapping fsx.ErrLinkUnsupported included, never
//	    dest.ErrExists).
//
// These tests swap package-level hooks, so they are NOT parallel (parallel
// tests of the package only start after them) and restore them with
// t.Cleanup.
package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

const linkContent = "%PDF-1.7 synthetic link probe"

func setProbeLink(t *testing.T, f func(*fsx.Root, context.Context) error) {
	t.Helper()
	prev := probeLink
	probeLink = f
	t.Cleanup(func() { probeLink = prev })
}

func setWriteNew(t *testing.T, f func(*fsx.Root, context.Context, string, io.Reader) error) {
	t.Helper()
	prev := writeNew
	writeNew = f
	t.Cleanup(func() { writeNew = prev })
}

func linkDoc() dest.NormalizedDoc {
	return dest.NormalizedDoc{Path: normalize.Path{Dir: "2026/edf", File: "2026-03-15_edf_facture_84-12EUR.pdf"}}
}

func names(t *testing.T, dir string) []string {
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

func TestNew_ProbesHardLinksOnce(t *testing.T) {
	calls := 0
	setProbeLink(t, func(r *fsx.Root, ctx context.Context) error {
		calls++
		return r.ProbeLink(ctx)
	})
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if calls != 1 {
		t.Fatalf("probeLink called %d times by New, want 1", calls)
	}
	if got := names(t, dir); len(got) != 0 {
		t.Errorf("output folder after New = %v, want it untouched (empty)", got)
	}

	ctx := t.Context()
	if _, err := l.Put(ctx, linkDoc(), strings.NewReader(linkContent)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := l.Exists(ctx, linkDoc()); err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if calls != 1 {
		t.Errorf("probeLink called %d times after Put/Exists, want still 1", calls)
	}
}

func TestNew_RefusesFolderWithoutHardLinks(t *testing.T) {
	dir := t.TempDir()
	setProbeLink(t, func(*fsx.Root, context.Context) error {
		return fmt.Errorf("fsx probe link %q: %w", dir, fsx.ErrLinkUnsupported)
	})
	l, err := New(dir)
	if !errors.Is(err, fsx.ErrLinkUnsupported) {
		t.Fatalf("New error = %v, want fsx.ErrLinkUnsupported", err)
	}
	if l != nil {
		t.Errorf("New returned %v with an error, want nil", l)
	}
	if got := names(t, dir); len(got) != 0 {
		t.Errorf("output folder = %v, want untouched", got)
	}
}

func TestPut_ReturnsRefWhenPublishedButNotDurable(t *testing.T) {
	syncErr := errors.New("sync dir: input/output error")
	setWriteNew(t, func(r *fsx.Root, ctx context.Context, name string, src io.Reader) error {
		if err := r.WriteNew(ctx, name, src); err != nil {
			return err
		}
		return fmt.Errorf("fsx write %q: %w: %w", name, fsx.ErrNotDurable, syncErr)
	})
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	doc := linkDoc()
	ref, err := l.Put(t.Context(), doc, strings.NewReader(linkContent))
	if !errors.Is(err, fsx.ErrNotDurable) {
		t.Fatalf("Put error = %v, want fsx.ErrNotDurable", err)
	}
	if errors.Is(err, dest.ErrExists) {
		t.Errorf("Put error = %v, must not wrap dest.ErrExists", err)
	}
	if want := (dest.RemoteRef{Destination: "local", ID: doc.Path.Rel()}); ref != want {
		t.Errorf("RemoteRef = %+v, want %+v (the file was published)", ref, want)
	}
	got, rerr := os.ReadFile(filepath.Clean(filepath.Join(dir, filepath.FromSlash(doc.Path.Rel()))))
	if rerr != nil || string(got) != linkContent {
		t.Errorf("published file = %q, %v; want the content", got, rerr)
	}
}

func TestPut_LinkUnsupportedReturnsZeroRef(t *testing.T) {
	setWriteNew(t, func(_ *fsx.Root, _ context.Context, name string, _ io.Reader) error {
		return fmt.Errorf("fsx write %q: %w", name, fsx.ErrLinkUnsupported)
	})
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	ref, err := l.Put(t.Context(), linkDoc(), strings.NewReader(linkContent))
	if !errors.Is(err, fsx.ErrLinkUnsupported) {
		t.Fatalf("Put error = %v, want fsx.ErrLinkUnsupported", err)
	}
	if errors.Is(err, dest.ErrExists) {
		t.Errorf("Put error = %v, must not wrap dest.ErrExists", err)
	}
	if ref != (dest.RemoteRef{}) {
		t.Errorf("RemoteRef = %+v, want zero", ref)
	}
	if got := names(t, filepath.Join(dir, "2026", "edf")); !slices.Equal(got, []string(nil)) {
		t.Errorf("entries = %v, want none", got)
	}
}
