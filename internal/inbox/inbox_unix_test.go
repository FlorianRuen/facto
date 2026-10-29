//go:build unix

// Symlink and special-file tests for package inbox (J0 task T22). See
// inbox_test.go for the expected API. Scan, Open and Done never follow a
// symlink (file or subfolder, pointing inside or outside the inbox) and never
// open a FIFO or device.
package inbox_test

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
)

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("setup Symlink(%q -> %q): %v", link, target, err)
	}
}

// outsideDir creates base/outside next to the output folder with compliant,
// identifiable files, so following a link would visibly produce items.
func outsideDir(t *testing.T, inboxDir string) string {
	t.Helper()
	base := filepath.Dir(filepath.Dir(inboxDir))
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate("outside"); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	for _, n := range []string{"2026-03-14_edf_invoice_outside.pdf", "avis-2026-10-02.pdf"} {
		if err := r.WriteAtomic(t.Context(), "outside/"+n, plainPDF(t, n)); err != nil {
			t.Fatalf("write outside: %v", err)
		}
	}
	return filepath.Join(base, "outside")
}

func TestScan_IgnoresHiddenAndSymlinks(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{
		"2026-03-14_edf_invoice.pdf":  plainPDF(t, "real"),
		".2026-03-14_edf_invoice.pdf": plainPDF(t, "hidden"),
		".cache/avis-2026-10-02.pdf":  plainPDF(t, "hidden dir"),
		"impots/avis-2026-10-02.pdf":  plainPDF(t, "real sub"),
	}
	dir := makeInbox(t, files)
	outside := outsideDir(t, dir)
	beforeOutside := snapshot(t, outside)

	// File symlinks: out of the inbox, inside it, dangling, hidden.
	mustSymlink(t, filepath.Join(outside, "2026-03-14_edf_invoice_outside.pdf"), filepath.Join(dir, "2026-03-14_edf_invoice_out.pdf"))
	mustSymlink(t, "2026-03-14_edf_invoice.pdf", filepath.Join(dir, "2026-03-14_edf_invoice_in.pdf"))
	mustSymlink(t, "missing.pdf", filepath.Join(dir, "2026-03-14_edf_invoice_dangling.pdf"))
	mustSymlink(t, filepath.Join(outside, "avis-2026-10-02.pdf"), filepath.Join(dir, ".hidden-link.pdf"))
	// Symlinks inside a subfolder.
	mustSymlink(t, filepath.Join(outside, "avis-2026-10-02.pdf"), filepath.Join(dir, "impots", "avis-2026-10-03.pdf"))
	// Subfolder symlinks: out of the inbox and to a sibling subfolder.
	mustSymlink(t, outside, filepath.Join(dir, "edf"))
	mustSymlink(t, "impots", filepath.Join(dir, "alias"))
	// FIFO with an identifiable name: must be neither opened nor read.
	if err := syscall.Mkfifo(filepath.Join(dir, "2026-03-14_edf_invoice_fifo.pdf"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	before := snapshot(t, dir)

	fp := &fakePrompter{t: t, answers: map[string]answer{}}
	ib := newInbox(t, dir, inbox.Options{Providers: providers, Prompter: fp})

	type out struct {
		res inbox.Result
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := ib.Scan(t.Context())
		done <- out{res, err}
	}()
	var res inbox.Result
	select {
	case o := <-done:
		if o.err != nil {
			t.Fatalf("Scan: %v", o.err)
		}
		res = o.res
	case <-time.After(10 * time.Second):
		t.Fatal("Scan blocked (opened the FIFO?)")
	}

	var paths []string
	for _, it := range res.Items {
		paths = append(paths, it.Path)
	}
	wantPaths := []string{"2026-03-14_edf_invoice.pdf", "impots/avis-2026-10-02.pdf"}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("items = %v, want only the real regular files %v", paths, wantPaths)
	}
	checkItemContent(t, res.Items, files)
	wantW := []inbox.Warning{
		{Path: "2026-03-14_edf_invoice_dangling.pdf", Reason: inbox.ReasonNotRegular},
		{Path: "2026-03-14_edf_invoice_fifo.pdf", Reason: inbox.ReasonNotRegular},
		{Path: "2026-03-14_edf_invoice_in.pdf", Reason: inbox.ReasonNotRegular},
		{Path: "2026-03-14_edf_invoice_out.pdf", Reason: inbox.ReasonNotRegular},
		{Path: "alias", Reason: inbox.ReasonNotRegular},
		{Path: "edf", Reason: inbox.ReasonNotRegular},
		{Path: "impots/avis-2026-10-03.pdf", Reason: inbox.ReasonNotRegular},
	}
	if !reflect.DeepEqual(res.Warnings, wantW) {
		t.Fatalf("warnings\n got: %+v\nwant: %+v", res.Warnings, wantW)
	}
	if n := len(fp.calls()); n != 0 {
		t.Fatalf("prompter asked %d times about links or special files", n)
	}
	wantSnapshot(t, dir, before)
	wantSnapshot(t, outside, beforeOutside)
}

// TestScan_InboxRootMayBeASymlink: the inbox directory itself may be a link
// (e.g. into a Google Drive for desktop folder); only links inside it are refused.
func TestScan_InboxRootMayBeASymlink(t *testing.T) {
	t.Parallel()
	realDir := makeInbox(t, map[string][]byte{"2026-03-14_edf_invoice.pdf": plainPDF(t, "1")})
	link := filepath.Join(t.TempDir(), "inbox-link")
	mustSymlink(t, realDir, link)
	res := scan(t, newInbox(t, link, inbox.Options{Providers: providers}))
	if len(res.Items) != 1 {
		t.Fatalf("items = %+v, want the file behind the linked inbox", itemViews(res.Items))
	}
}

// TestOpenDone_RefuseSymlinkSwap: after Scan the file is replaced by a
// symlink to an outside file with the very same content (same size, same
// hash). Open must not follow it and Done must not act on it.
func TestOpenDone_RefuseSymlinkSwap(t *testing.T) {
	t.Parallel()
	const p = "impots/avis-2026-10-02.pdf"
	content := plainPDF(t, "1")
	dir := makeInbox(t, map[string][]byte{p: content})
	ib := newInbox(t, dir, inbox.Options{Providers: providers})
	it := findItem(t, scan(t, ib), p)
	if it.SHA256 != sha256.Sum256(content) {
		t.Fatal("setup: unexpected hash")
	}

	base := filepath.Dir(filepath.Dir(dir))
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), "twin.pdf", content); err != nil {
		t.Fatalf("write twin: %v", err)
	}
	full := filepath.Join(dir, "impots", "avis-2026-10-02.pdf")
	if err := os.Remove(full); err != nil {
		t.Fatalf("remove: %v", err)
	}
	mustSymlink(t, filepath.Join(base, "twin.pdf"), full)
	before := snapshot(t, base)

	if got, err := readAll(t, ib, it); err == nil {
		t.Fatalf("Open followed a symlink swapped in after Scan (read %d bytes)", len(got))
	} else if !errors.Is(err, inbox.ErrChanged) {
		t.Fatalf("Open error = %v, want ErrChanged", err)
	}
	if err := ib.Done(t.Context(), it); !errors.Is(err, inbox.ErrChanged) {
		t.Fatalf("Done error = %v, want ErrChanged", err)
	}
	wantSnapshot(t, base, before)
}

// TestOpenDone_RefuseSymlinkedSubfolderSwap: the subfolder itself is swapped
// for a symlink to an outside directory holding an identical file.
func TestOpenDone_RefuseSymlinkedSubfolderSwap(t *testing.T) {
	t.Parallel()
	const p = "impots/avis-2026-10-02.pdf"
	content := plainPDF(t, "1")
	dir := makeInbox(t, map[string][]byte{p: content})
	ib := newInbox(t, dir, inbox.Options{Providers: providers})
	it := findItem(t, scan(t, ib), p)

	base := filepath.Dir(filepath.Dir(dir))
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate("elsewhere"); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := r.WriteAtomic(t.Context(), "elsewhere/avis-2026-10-02.pdf", content); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Rename(filepath.Join(dir, "impots"), filepath.Join(base, "moved")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	mustSymlink(t, filepath.Join(base, "elsewhere"), filepath.Join(dir, "impots"))
	before := snapshot(t, base)

	if _, err := readAll(t, ib, it); err == nil {
		t.Fatal("Open followed a subfolder symlink out of the inbox")
	}
	if err := ib.Done(t.Context(), it); err == nil {
		t.Fatal("Done followed a subfolder symlink out of the inbox")
	}
	wantSnapshot(t, base, before)
}
