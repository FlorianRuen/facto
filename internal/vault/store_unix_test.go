//go:build unix

// Permission and file-type tests for the session store (J1 T16). See
// store_test.go for the expected API.
package vault_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/vault"
)

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("lstat %s: %v", p, err)
	}
	return fi.Mode().Perm()
}

func checkPrivateTree(t *testing.T, f *storeFixture) {
	t.Helper()
	mustSave(t, f.store, "edf", "synthetic jar")
	want := map[string]os.FileMode{
		"install-id":        0o600,
		"sessions":          0o700,
		"sessions/edf.sess": 0o600,
	}
	for rel, m := range want {
		if got := modeOf(t, filepath.Join(f.dir, filepath.FromSlash(rel))); got != m {
			t.Errorf("%s mode = %#o, want %#o", rel, got, m)
		}
	}
	lock := filepath.Join(f.dir, "sessions", "edf.lock")
	if exists(t, lock) {
		fi, err := os.Lstat(lock)
		if err != nil {
			t.Fatalf("lstat lock: %v", err)
		}
		if fi.Mode().Perm() != 0o600 || fi.Size() != 0 {
			t.Errorf("sessions/edf.lock mode %#o size %d, want 0600 and empty", fi.Mode().Perm(), fi.Size())
		}
	}
}

func TestStore_FilesPrivate(t *testing.T) {
	t.Parallel()

	t.Run("default umask", func(t *testing.T) {
		t.Parallel()
		checkPrivateTree(t, newPersistent(t))
	})

	t.Run("group-readable sessions dir refused", func(t *testing.T) {
		t.Parallel()
		f := newPersistent(t)
		sessions := filepath.Join(f.dir, "sessions")
		insecure := os.FileMode(0o755)
		if err := os.Mkdir(sessions, insecure); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(sessions, insecure); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		f.keys.resetCalls()
		err := f.store.Save(t.Context(), "edf", secret.FromString("synthetic jar"))
		if !errors.Is(err, fsx.ErrInsecurePerms) {
			t.Fatalf("Save into a 0755 sessions dir: err = %v, want ErrInsecurePerms", err)
		}
		if exists(t, filepath.Join(sessions, "edf.sess")) {
			t.Fatalf("session written into an insecure directory")
		}
		f.keys.wantNoCalls(t)
	})
}

// TestStore_FilesPrivateUnderUmask0 is a separate, non-parallel test: umask
// is process-wide.
func TestStore_FilesPrivateUnderUmask0(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	checkPrivateTree(t, newPersistent(t))
}

func TestStore_SessionSymlinkNotFollowed(t *testing.T) {
	t.Parallel()
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "victim")
	put(t, victimDir, "victim", []byte("synthetic victim"))

	t.Run("persistent Load refuses a symlinked session file", func(t *testing.T) {
		t.Parallel()
		f := newPersistent(t)
		mustSave(t, f.store, "edf", "synthetic jar")
		p := f.sessPath("edf")
		if err := os.Remove(p); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if err := os.Symlink(victim, p); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		got, err := f.store.Load(t.Context(), "edf")
		if err == nil || !got.IsZero() {
			t.Fatalf("Load followed a symlinked session file")
		}
		if string(readBytes(t, victim)) != "synthetic victim" {
			t.Fatalf("symlink target modified")
		}
	})

	t.Run("ephemeral sweep removes the link, not the target", func(t *testing.T) {
		t.Parallel()
		dir := newStateDir(t)
		put(t, dir, "sessions/keep.txt", []byte("synthetic"))
		link := filepath.Join(dir, "sessions", "edf.sess")
		if err := os.Symlink(victim, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		keys := newFakeKeys()
		_, spy, _ := openStore(t, dir, vault.Ephemeral, keys, nil)
		if exists(t, link) {
			t.Fatalf("symlinked *.sess survived the sweep")
		}
		if string(readBytes(t, victim)) != "synthetic victim" {
			t.Fatalf("sweep followed the symlink")
		}
		if spy.count() != 0 {
			t.Fatalf("sweep opened a session file")
		}
	})
}
