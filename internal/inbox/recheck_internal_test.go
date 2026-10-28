// Identity-check test for Done: a file renamed over the item after its
// content was verified must not be removed (re-Lstat + os.SameFile). The
// rename happens in the doneRecheckHook test hook, called exactly in that
// window. These tests swap a package-level hook, so they are NOT parallel.
package inbox

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func writeFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, data); err != nil {
		t.Fatal(err)
	}
}

func setDoneHook(t *testing.T, f func()) {
	t.Helper()
	prev := doneRecheckHook
	doneRecheckHook = f
	t.Cleanup(func() { doneRecheckHook = prev })
}

func newTestInbox(t *testing.T, content []byte) (*Inbox, string, Item) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "x.pdf", content)
	ib, err := New(dir, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = ib.Close() })
	return ib, dir, Item{Path: "x.pdf", Size: int64(len(content)), SHA256: sha256.Sum256(content)}
}

func TestDone_KeepsFileRenamedOverAfterVerification(t *testing.T) {
	scanned := []byte("scanned-content")
	ib, dir, it := newTestInbox(t, scanned)
	newer := []byte("newer-drop")
	writeFile(t, dir, "newer.pdf", newer)
	calls := 0
	setDoneHook(t, func() {
		calls++
		if err := os.Rename(filepath.Join(dir, "newer.pdf"), filepath.Join(dir, "x.pdf")); err != nil {
			t.Errorf("rename: %v", err)
		}
	})

	err := ib.Done(t.Context(), it)
	if calls != 1 {
		t.Fatalf("doneRecheckHook called %d times, want 1", calls)
	}
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("Done error = %v, want ErrChanged", err)
	}
	got, rerr := os.ReadFile(filepath.Clean(filepath.Join(dir, "x.pdf")))
	if rerr != nil || string(got) != string(newer) {
		t.Errorf("x.pdf after Done = %q, %v; want the newer drop kept", got, rerr)
	}
}

func TestDone_RemovesUnchangedFile(t *testing.T) {
	ib, dir, it := newTestInbox(t, []byte("scanned-content"))
	calls := 0
	setDoneHook(t, func() { calls++ })
	if err := ib.Done(t.Context(), it); err != nil {
		t.Fatalf("Done: %v", err)
	}
	if calls != 1 {
		t.Errorf("doneRecheckHook called %d times, want 1", calls)
	}
	if _, err := os.Lstat(filepath.Join(dir, "x.pdf")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("x.pdf still present after Done: %v", err)
	}
}
