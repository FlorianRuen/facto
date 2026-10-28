//go:build unix

// Red-team attack tests for the local destination (J0 task T30): forged
// normalize.Paths that bypass the Namer, planted symlinks, files and FIFOs
// in the output folder, permission downgrades under a zero umask, racing
// Puts and failing readers. A test passes when the attack is defeated.
package local_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/dest/local"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

// atkOut creates base/out (the output folder) and base/outside, and opens
// the destination on base/out.
func atkOut(t *testing.T) (l *local.Local, out, outside string) {
	t.Helper()
	base := t.TempDir()
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	for _, d := range []string{"out", "outside"} {
		if err := r.MkdirPrivate(d); err != nil {
			t.Fatal(err)
		}
	}
	out, outside = filepath.Join(base, "out"), filepath.Join(base, "outside")
	l, err = local.New(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, out, outside
}

func atkEmpty(t *testing.T, dir string) {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range des {
		t.Errorf("unexpected entry in %s: %q", filepath.Base(dir), d.Name())
	}
}

func atkDoc(dir, file string) dest.NormalizedDoc {
	return dest.NormalizedDoc{Path: normalize.Path{Dir: dir, File: file}}
}

// TestAttack_LocalForgedPathsRefused calls Put and Exists with paths a
// buggy namer or a hostile caller could produce.
func TestAttack_LocalForgedPathsRefused(t *testing.T) {
	t.Parallel()
	l, out, outside := atkOut(t)
	paths := []normalize.Path{
		{Dir: "..", File: "x.pdf"},
		{Dir: "../outside", File: "x.pdf"},
		{Dir: "a/../..", File: "x.pdf"},
		{Dir: "", File: "../x.pdf"},
		{Dir: "", File: "../outside/x.pdf"},
		{Dir: "/etc", File: "x.pdf"},
		{Dir: "/", File: "x.pdf"},
		{Dir: "a//b", File: "x.pdf"},
		{Dir: "a/./b", File: "x.pdf"},
		{Dir: "a/", File: "x.pdf"},
		{Dir: "", File: "CON"},
		{Dir: "", File: "con.pdf"},
		{Dir: "LPT1", File: "x.pdf"},
		{Dir: "", File: "x\x00.pdf"},
		{Dir: "", File: strings.Repeat("a", 201)},
		{Dir: "", File: ".hidden.pdf"},
		{Dir: ".facto", File: "x.pdf"},
		{Dir: "", File: "x.pdf "},
		{Dir: "", File: "x.pdf."},
		{Dir: "a\\..\\..", File: "x.pdf"},
		{Dir: "", File: "a\\..\\x.pdf"},
		{Dir: "", File: ""},
		{Dir: "", File: "."},
		{Dir: "", File: ".."},
		{Dir: "\u202e", File: "x.pdf"},
		{Dir: "", File: "x\u200b.pdf"},
		{Dir: "", File: "x\n.pdf"},
		{Dir: "", File: "a:b.pdf"},
	}
	for _, p := range paths {
		_, err := l.Put(t.Context(), dest.NormalizedDoc{Path: p}, strings.NewReader("attack"))
		if !errors.Is(err, dest.ErrInvalidPath) {
			t.Errorf("Put(%+v) = %v, want ErrInvalidPath", p, err)
		}
		if _, err := l.Exists(t.Context(), dest.NormalizedDoc{Path: p}); !errors.Is(err, dest.ErrInvalidPath) {
			t.Errorf("Exists(%+v) = %v, want ErrInvalidPath", p, err)
		}
	}
	atkEmpty(t, out)
	atkEmpty(t, outside)
}

// TestAttack_LocalPlantedEntriesNeverFollowedOrReplaced plants, in the
// output folder: a directory symlink leading outside, a dangling file
// symlink leading outside, a file symlink to an outside file, a regular
// file and a FIFO, each at a path Put will target.
func TestAttack_LocalPlantedEntriesNeverFollowedOrReplaced(t *testing.T) {
	t.Parallel()
	l, out, outside := atkOut(t)
	r, err := fsx.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate("2026/energy/edf"); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteAtomic(t.Context(), "2026/energy/edf/planted.pdf", []byte("planted")); err != nil {
		t.Fatal(err)
	}
	ro, err := fsx.Open(outside)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if err := ro.WriteAtomic(t.Context(), "victim.pdf", []byte("victim")); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"2027":                         outside,
		"2026/energy/edf/dangling.pdf": filepath.Join(outside, "created.pdf"),
		"2026/energy/edf/victim.pdf":   filepath.Join(outside, "victim.pdf"),
		"2026/energy/edf/relative.pdf": "../../../../outside/created2.pdf",
		"2026/energy/escape":           "../../../outside",
	} {
		if err := os.Symlink(target, filepath.Join(out, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(out, "2026/energy/edf/fifo.pdf"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		doc     dest.NormalizedDoc
		wantErr error
	}{
		{atkDoc("2027/energy/edf", "x.pdf"), nil},
		{atkDoc("2027", "x.pdf"), nil},
		{atkDoc("2026/energy/escape", "x.pdf"), nil},
		{atkDoc("2026/energy/edf", "dangling.pdf"), dest.ErrExists},
		{atkDoc("2026/energy/edf", "victim.pdf"), dest.ErrExists},
		{atkDoc("2026/energy/edf", "relative.pdf"), dest.ErrExists},
		{atkDoc("2026/energy/edf", "planted.pdf"), dest.ErrExists},
		{atkDoc("2026/energy/edf", "fifo.pdf"), dest.ErrExists},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, c := range cases {
			_, err := l.Put(context.Background(), c.doc, strings.NewReader("attack"))
			switch {
			case err == nil:
				t.Errorf("Put(%+v) succeeded", c.doc.Path)
			case c.wantErr != nil && !errors.Is(err, c.wantErr):
				t.Errorf("Put(%+v) = %v, want %v", c.doc.Path, err, c.wantErr)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Put blocked on a planted FIFO")
	}
	for _, n := range []string{"dangling.pdf", "victim.pdf", "relative.pdf"} {
		if fi, err := os.Lstat(filepath.Join(out, "2026/energy/edf", n)); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			t.Errorf("planted symlink %s replaced or removed", n)
		}
	}
	if b, _ := os.ReadFile(filepath.Clean(filepath.Join(out, "2026/energy/edf/planted.pdf"))); string(b) != "planted" {
		t.Errorf("planted file replaced: %q", b)
	}
	des, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 1 || des[0].Name() != "victim.pdf" {
		t.Errorf("outside dir changed: %d entries", len(des))
	}
	if b, _ := os.ReadFile(filepath.Clean(filepath.Join(outside, "victim.pdf"))); string(b) != "victim" {
		t.Errorf("outside victim changed: %q", b)
	}
	if ok, err := l.Exists(t.Context(), atkDoc("2026/energy/edf", "victim.pdf")); ok || err != nil {
		t.Errorf("Exists through a symlink = %v, %v; want false, nil", ok, err)
	}
}

// TestAttack_LocalPermissionsUnderZeroUmask files a document with umask 0
// and checks the modes, then makes the target dir world-writable.
// Not parallel: the umask is process-wide.
func TestAttack_LocalPermissionsUnderZeroUmask(t *testing.T) {
	broadDir := fs.FileMode(0o777) // left by an attacker or a careless tool
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	l, out, _ := atkOut(t)
	if _, err := l.Put(t.Context(), atkDoc("2026/energy/edf", "a.pdf"), strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]fs.FileMode{"2026": 0o700, "2026/energy": 0o700, "2026/energy/edf": 0o700, "2026/energy/edf/a.pdf": 0o600} {
		fi, err := os.Lstat(filepath.Join(out, p))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	if err := os.Chmod(filepath.Join(out, "2026/energy/edf"), broadDir); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(t.Context(), atkDoc("2026/energy/edf", "b.pdf"), strings.NewReader("x")); !errors.Is(err, fsx.ErrInsecurePerms) {
		t.Errorf("Put into a 0777 dir = %v, want ErrInsecurePerms", err)
	}
}

// atkFailing yields some bytes then an error.
type atkFailing struct{ sent bool }

func (f *atkFailing) Read(p []byte) (int, error) {
	if !f.sent {
		f.sent = true
		return copy(p, "partial"), nil
	}
	return 0, io.ErrUnexpectedEOF
}

// TestAttack_LocalRacesAndPartialWrites races 16 Puts on one path and
// feeds a failing reader: one winner, intact content, no partial file and
// no temp file left behind.
func TestAttack_LocalRacesAndPartialWrites(t *testing.T) {
	t.Parallel()
	l, out, _ := atkOut(t)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins [][]byte
	)
	for i := range 16 {
		wg.Go(func() {
			body := bytes.Repeat([]byte{"abcdefghijklmnop"[i]}, 32<<10)
			_, err := l.Put(t.Context(), atkDoc("2026", "same.pdf"), bytes.NewReader(body))
			switch {
			case err == nil:
				mu.Lock()
				wins = append(wins, body)
				mu.Unlock()
			case !errors.Is(err, dest.ErrExists):
				t.Errorf("Put: %v", err)
			}
		})
	}
	wg.Wait()
	if len(wins) != 1 {
		t.Fatalf("%d winners, want 1", len(wins))
	}
	if b, _ := os.ReadFile(filepath.Clean(filepath.Join(out, "2026/same.pdf"))); !bytes.Equal(b, wins[0]) {
		t.Error("published content is not the winner's")
	}
	if _, err := l.Put(t.Context(), atkDoc("2026", "partial.pdf"), &atkFailing{}); err == nil {
		t.Error("Put with a failing reader succeeded")
	}
	des, err := os.ReadDir(filepath.Join(out, "2026"))
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 1 {
		var names []string
		for _, d := range des {
			names = append(names, d.Name())
		}
		t.Errorf("leftover entries: %q", names)
	}
}
