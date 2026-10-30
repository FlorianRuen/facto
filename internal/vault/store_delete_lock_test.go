// Tests for the locking of Store.Delete (J1 T18 review): Delete always takes
// the per-connector lock, like Save, so it never interleaves with a
// concurrent Save of the same connector (a keyring-only Delete could remove
// the key a first Save had just Set). All values are synthetic.
package vault_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestStore_DeleteWithoutSessionsDirTakesLock(t *testing.T) {
	t.Parallel()
	f := newPersistent(t)
	install := f.installID(t)
	sessDir := filepath.Join(f.dir, "sessions")
	if exists(t, sessDir) {
		t.Fatal("fixture already has a sessions dir")
	}
	// An orphan key, as a crashed first Save would leave it.
	f.keys.put(sessionRef(install, "edf"), "synthetic orphan key")

	if err := f.store.Delete(t.Context(), "edf"); err != nil {
		t.Fatalf("Delete(edf): %v", err)
	}
	fi, err := os.Lstat(sessDir)
	if err != nil {
		t.Fatalf("sessions dir not created by Delete: %v", err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("sessions dir mode = %v, want a 0700 directory", fi.Mode())
	}
	if !exists(t, filepath.Join(sessDir, "edf.lock")) {
		t.Fatal("sessions/edf.lock missing: Delete did not take the per-connector lock")
	}
	if _, ok := f.keys.get(sessionRef(install, "edf")); ok {
		t.Fatal("orphan key still present after Delete")
	}
}

func TestStore_DeleteWaitsForTheConnectorLock(t *testing.T) {
	t.Parallel()
	f := newPersistent(t)
	install := f.installID(t)
	mustSave(t, f.store, "edf", "synthetic edf jar")

	sessions, err := fsx.Open(filepath.Join(f.dir, "sessions"))
	if err != nil {
		t.Fatalf("open sessions dir: %v", err)
	}
	defer func() { _ = sessions.Close() }()
	held, err := sessions.TryLock("edf.lock")
	if err != nil {
		t.Fatalf("hold edf.lock: %v", err)
	}

	// A concurrent Save holds the lock: Delete must wait for it, so with a
	// short deadline it gives up and leaves both the file and the key.
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := f.store.Delete(ctx, "edf"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Delete while the lock is held: err = %v, want the context deadline", err)
	}
	if !exists(t, f.sessPath("edf")) {
		t.Fatal("session file removed without the lock")
	}
	if _, ok := f.keys.get(sessionRef(install, "edf")); !ok {
		t.Fatal("keyring entry deleted without the lock")
	}

	if err := held.Close(); err != nil {
		t.Fatalf("release edf.lock: %v", err)
	}
	if err := f.store.Delete(t.Context(), "edf"); err != nil {
		t.Fatalf("Delete after the lock is released: %v", err)
	}
	if exists(t, f.sessPath("edf")) {
		t.Fatal("session file still present")
	}
	if _, ok := f.keys.get(sessionRef(install, "edf")); ok {
		t.Fatal("keyring entry still present")
	}
}
