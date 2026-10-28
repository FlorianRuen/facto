//go:build unix

// Red-team attack tests for the SQLite index (J0 task T30): SQL injection
// through every text field and lookup argument, DSN injection through the
// state directory name, side-file permissions under a zero umask, and
// planted side files. A test passes when the attack is defeated. Everything
// is synthetic.
package store_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/store"
)

var atkInjections = []string{
	"x'); DROP TABLE documents;--",
	"' OR '1'='1",
	"\" OR \"\"=\"",
	"%", "_", "*", "edf%", "\\",
	"x\x00y",
	"'; ATTACH DATABASE '/tmp/facto-attack.db' AS a; --",
	"'||(SELECT sql FROM sqlite_master)||'",
	"1; PRAGMA writable_schema=1;",
	strings.Repeat("A", 1<<16),
	string(rune(0x202e)) + string(rune(0xfeff)),
}

// TestAttack_StoreSQLInjectionThroughFields stores every injection string
// in every text field, reads it back verbatim, and looks it up: lookups
// must match exactly, never as a pattern or as SQL.
func TestAttack_StoreSQLInjectionThroughFields(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := t.Context()
	mustInsert(t, s, doc("edf", "legit-1", 1, "legit"))
	for i, inj := range atkInjections {
		d := store.Document{
			Provider: inj, ProviderID: inj, Kind: connector.Invoice,
			IssuedAt: time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC), AmountCents: cents(1), Currency: inj,
			SHA256: sum("inj" + string(rune('a'+i))), LocalPath: inj, DriveID: inj, Version: 1,
		}
		mustInsert(t, s, d)
		got, err := s.FindByProviderID(ctx, inj, inj)
		if err != nil {
			t.Fatalf("FindByProviderID(%.40q): %v", inj, err)
		}
		if len(got) != 1 {
			t.Fatalf("FindByProviderID(%.40q) = %d rows, want exactly 1", inj, len(got))
		}
		g := got[0]
		if g.Provider != inj || g.ProviderID != inj || g.Currency != inj || g.LocalPath != inj || g.DriveID != inj {
			t.Errorf("injection %.40q not stored verbatim: %+v", inj, g)
		}
	}
	for _, inj := range atkInjections {
		if got, err := s.FindByProviderID(ctx, "edf", inj); err != nil || len(got) != 0 {
			t.Errorf("FindByProviderID(edf, %.40q) = %d rows, %v; want 0", inj, len(got), err)
		}
		if v, found, err := s.LatestVersion(ctx, "edf", inj); err != nil || found || v != 0 {
			t.Errorf("LatestVersion(edf, %.40q) = %d %v %v", inj, v, found, err)
		}
	}
	if got, err := s.FindByProviderID(ctx, "edf", "legit-1"); err != nil || len(got) != 1 {
		t.Errorf("legit row lost after injections: %d, %v", len(got), err)
	}
	if _, err := os.Stat("/tmp/facto-attack.db"); err == nil {
		t.Error("ATTACH injection created /tmp/facto-attack.db")
	}
}

// TestAttack_StoreDSNInjectionThroughStateDir names the state directory
// after URI query syntax. The database must live exactly in that
// directory, on disk, in WAL mode, with nothing created next to it.
func TestAttack_StoreDSNInjectionThroughStateDir(t *testing.T) {
	t.Parallel()
	names := []string{
		"st?mode=memory", "st#frag", "st&_pragma=journal_mode(DELETE)", "st%3Fmode=memory",
		"st?_pragma=journal_mode(OFF)&x=", "st'q\"", "st space", "st;x", "st?vfs=memdb", "st%00x",
	}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			dir := filepath.Join(parent, n)
			s := openStore(t, dir, newClock())
			mustInsert(t, s, doc("edf", "id-1", 1, "content"))
			if _, err := os.Stat(filepath.Join(dir, store.FileName+"-wal")); err != nil {
				t.Errorf("no -wal file while open (journal mode overridden?): %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(filepath.Join(dir, store.FileName))
			if err != nil || fi.Size() == 0 {
				t.Fatalf("database not on disk in %q: %v", n, err)
			}
			des, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			if len(des) != 1 || des[0].Name() != n {
				var got []string
				for _, d := range des {
					got = append(got, d.Name())
				}
				t.Errorf("parent holds %q, want only %q", got, n)
			}
			s2 := openStore(t, dir, newClock())
			if got, err := s2.FindByProviderID(t.Context(), "edf", "id-1"); err != nil || len(got) != 1 {
				t.Errorf("row not persisted: %d %v", len(got), err)
			}
		})
	}
}

// TestAttack_StoreSideFilesPrivateUnderZeroUmask writes with umask 0 and
// checks the database, -wal and -shm modes while the store is open.
// Not parallel: the umask is process-wide.
func TestAttack_StoreSideFilesPrivateUnderZeroUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := filepath.Join(t.TempDir(), "state")
	s := openStore(t, dir, newClock())
	for i := range 50 {
		mustInsert(t, s, doc("edf", "id-"+string(rune('a'+i%26))+string(rune('a'+i/26)), 1, "c"+string(rune(i))))
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, d := range des {
		fi, err := d.Info()
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, d.Name())
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v under umask 0", d.Name(), fi.Mode().Perm())
		}
	}
	for _, want := range []string{store.FileName, store.FileName + "-wal", store.FileName + "-shm"} {
		if !slices.Contains(seen, want) {
			t.Errorf("%s missing (seen %q): the mode check did not cover it", want, seen)
		}
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode %v, %v", fi.Mode().Perm(), err)
	}
}

// TestAttack_StorePlantedSideFilesRefused plants a -wal symlink to an
// outside file, a world-readable -shm, a FIFO -journal, and a symlinked
// state dir. Open must refuse and leave the planted targets untouched.
func TestAttack_StorePlantedSideFilesRefused(t *testing.T) {
	readable := fs.FileMode(0o644) // a world-readable planted side file
	t.Parallel()
	base := t.TempDir()
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	for _, d := range []string{"wal", "shm", "journal", "real"} {
		if err := r.MkdirPrivate(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.WriteAtomic(t.Context(), "victim", []byte("victim")); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(base, "victim")
	if err := os.Symlink(victim, filepath.Join(base, "wal", store.FileName+"-wal")); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteAtomic(t.Context(), "shm/"+store.FileName+"-shm", nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(base, "shm", store.FileName+"-shm"), readable); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(base, "journal", store.FileName+"-journal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "linked")); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"wal", "shm", "journal", "linked"} {
		s, err := store.Open(t.Context(), filepath.Join(base, d), newClock())
		if err == nil {
			_ = s.Close()
			t.Errorf("Open(%s) accepted a planted side file or symlinked dir", d)
		}
	}
	if b, err := os.ReadFile(filepath.Clean(victim)); err != nil || string(b) != "victim" {
		t.Errorf("victim changed: %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(base, "real", store.FileName)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("database created through a symlinked state dir: %v", err)
	}
}
