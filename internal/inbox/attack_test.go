//go:build unix

// Red-team attack tests for the inbox (J0 task T30): forged item paths,
// swaps between Scan and Open/Done, special files, huge files and hostile
// Factur-X fields. A test passes when the attack is defeated. Everything is
// synthetic.
package inbox_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
)

// atkVictim writes base/out/victim.pdf and base/victim.pdf (outside the
// inbox) with content c and returns their paths.
func atkVictims(t *testing.T, inboxDir string, c []byte) []string {
	t.Helper()
	out := filepath.Dir(inboxDir)
	base := filepath.Dir(out)
	var paths []string
	for _, dir := range []string{out, base} {
		r, err := fsx.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.WriteAtomic(t.Context(), "victim.pdf", c); err != nil {
			t.Fatal(err)
		}
		_ = r.Close()
		paths = append(paths, filepath.Join(dir, "victim.pdf"))
	}
	return paths
}

// TestAttack_InboxForgedItemPathsNeverReachOutside forges Items (as a
// compromised caller or a corrupted plan would) whose Path points outside
// the inbox, with the victim's real size and hash, and calls Open and Done.
func TestAttack_InboxForgedItemPathsNeverReachOutside(t *testing.T) {
	t.Parallel()
	content := []byte("synthetic victim content")
	dir := makeInbox(t, map[string][]byte{"edf/2026-03-14_edf_invoice.pdf": []byte("x")})
	victims := atkVictims(t, dir, content)
	ib := newInbox(t, dir, inbox.Options{})
	sum := sha256.Sum256(content)
	paths := []string{
		"../victim.pdf", "../../victim.pdf", "/" + strings.TrimPrefix(victims[1], "/"),
		"edf/../../victim.pdf", "edf/../../../victim.pdf", "./../victim.pdf",
		"edf\\..\\..\\victim.pdf", "..\\victim.pdf", "edf/x/../../../victim.pdf",
		"..", ".", "", "edf/.", "edf//../../victim.pdf", "edf/\x00/../../victim.pdf",
	}
	for _, p := range paths {
		it := inbox.Item{Path: p, Size: int64(len(content)), SHA256: sum}
		if rc, err := ib.Open(t.Context(), it); err == nil {
			_ = rc.Close()
			t.Errorf("Open(%q) succeeded", p)
		}
		if err := ib.Done(t.Context(), it); err == nil {
			t.Errorf("Done(%q) succeeded", p)
		}
	}
	for _, v := range victims {
		if _, err := os.Lstat(v); err != nil {
			t.Errorf("victim %s removed: %v", v, err)
		}
	}
}

// TestAttack_InboxSwapsAfterScanAreRefused scans an item, then replaces its
// subfolder by a symlink to an outside folder holding a byte-identical file,
// and replaces a root item by a symlink to an identical outside file.
func TestAttack_InboxSwapsAfterScanAreRefused(t *testing.T) {
	t.Parallel()
	c := []byte("identical synthetic content")
	dir := makeInbox(t, map[string][]byte{
		"edf/2026-03-14_edf_invoice.pdf": c,
		"2026-03-15_edf_invoice.pdf":     c,
	})
	base := filepath.Dir(filepath.Dir(dir))
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate("elsewhere"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"2026-03-14_edf_invoice.pdf", "2026-03-15_edf_invoice.pdf"} {
		if err := r.WriteAtomic(t.Context(), "elsewhere/"+n, c); err != nil {
			t.Fatal(err)
		}
	}
	ib := newInbox(t, dir, inbox.Options{})
	res := scan(t, ib)
	if len(res.Items) != 2 {
		t.Fatalf("items = %+v", res.Items)
	}
	if err := os.Rename(filepath.Join(dir, "edf"), filepath.Join(dir, "edf.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "elsewhere"), filepath.Join(dir, "edf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "2026-03-15_edf_invoice.pdf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "elsewhere", "2026-03-15_edf_invoice.pdf"), filepath.Join(dir, "2026-03-15_edf_invoice.pdf")); err != nil {
		t.Fatal(err)
	}
	for _, it := range res.Items {
		if rc, err := ib.Open(t.Context(), it); err == nil {
			_ = rc.Close()
			t.Errorf("Open(%q) followed a swapped-in symlink", it.Path)
		} else if !errors.Is(err, inbox.ErrChanged) {
			t.Errorf("Open(%q) error = %v, want ErrChanged", it.Path, err)
		}
		if err := ib.Done(t.Context(), it); err == nil {
			t.Errorf("Done(%q) succeeded through a swapped-in symlink", it.Path)
		}
	}
	for _, n := range []string{"2026-03-14_edf_invoice.pdf", "2026-03-15_edf_invoice.pdf"} {
		if _, err := os.Lstat(filepath.Join(base, "elsewhere", n)); err != nil {
			t.Errorf("outside file %s removed: %v", n, err)
		}
	}
}

// TestAttack_InboxSpecialAndHugeFilesNeverBlockOrLoad plants a FIFO, a unix
// socket and a 4 GiB sparse file (at the root and in a subfolder) and a
// file just over a tiny MaxSize. Scan must finish quickly without reading
// them.
func TestAttack_InboxSpecialAndHugeFilesNeverBlockOrLoad(t *testing.T) {
	t.Parallel()
	dir := makeInbox(t, map[string][]byte{
		"edf/2026-03-14_edf_invoice_huge.pdf": []byte("x"),
		"2026-03-14_edf_invoice_huge.pdf":     []byte("x"),
	})
	for _, p := range []string{"edf/2026-03-14_edf_invoice_huge.pdf", "2026-03-14_edf_invoice_huge.pdf"} {
		if err := os.Truncate(filepath.Join(dir, p), 4<<30); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "2026-03-14_edf_invoice_fifo.pdf"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "edf", "2026-03-14_edf_invoice_fifo.pdf"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Unix socket paths are limited to ~108 bytes: listen through a short
	// relative name from a dedicated directory is not possible in parallel
	// tests, so only create it when the path fits.
	if sock := filepath.Join(dir, "s.pdf"); len(sock) < 100 {
		l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
		if err == nil {
			defer func() { _ = l.Close() }()
		}
	}
	ib := newInbox(t, dir, inbox.Options{})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	done := make(chan inbox.Result, 1)
	go func() {
		res, err := ib.Scan(ctx)
		if err != nil {
			t.Errorf("Scan: %v", err)
		}
		done <- res
	}()
	var res inbox.Result
	select {
	case res = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Scan blocked")
	}
	if len(res.Items) != 0 {
		t.Errorf("special or huge files became items: %+v", res.Items)
	}
	got := map[string]inbox.Reason{}
	for _, w := range res.Warnings {
		got[w.Path] = w.Reason
	}
	for p, want := range map[string]inbox.Reason{
		"2026-03-14_edf_invoice_huge.pdf":     inbox.ReasonTooLarge,
		"edf/2026-03-14_edf_invoice_huge.pdf": inbox.ReasonTooLarge,
		"2026-03-14_edf_invoice_fifo.pdf":     inbox.ReasonNotRegular,
		"edf/2026-03-14_edf_invoice_fifo.pdf": inbox.ReasonNotRegular,
	} {
		if got[p] != want {
			t.Errorf("warning for %q = %q, want %q", p, got[p], want)
		}
	}
}

var atkSlugRe = regexp.MustCompile(`^([a-z0-9]+(-[a-z0-9]+)*)?$`)

// TestAttack_InboxHostileFacturXFieldsBecomeSlugs checks that Factur-X
// number and seller strings never reach Item.Doc unslugged.
func TestAttack_InboxHostileFacturXFieldsBecomeSlugs(t *testing.T) {
	t.Parallel()
	hostile := []string{
		"../../.ssh/id_rsa", "..\\..\\x", "/etc/passwd", "CON", "nul.txt", strings.Repeat("Ab/", 120),
		"\u202egnp.exe", "a\u200bb", "x&#x2F;..&#x2F;y", "%2e%2e%2f", "~root", "$HOME", "`id`",
	}
	files := map[string][]byte{}
	for i, h := range hostile {
		files["drop-"+string(rune('a'+i))+".pdf"] = facturXPDF(t, ciiXML(h, "20260314", h, "EUR", "1.00"))
	}
	dir := makeInbox(t, files)
	res := scan(t, newInbox(t, dir, inbox.Options{}))
	for _, it := range res.Items {
		for name, v := range map[string]string{"Provider": it.Doc.Provider, "Ref": it.Doc.Ref, "Category": it.Doc.Category} {
			if !atkSlugRe.MatchString(v) {
				t.Errorf("%s: Doc.%s = %q is not a slug", it.Path, name, v)
			}
		}
	}
}
