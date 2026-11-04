// Tests for Store.Delete (J1 T18): the orchestrator drops a saved session
// the supplier rejected (needs_login / auth_failed after a restore). All
// blobs are synthetic.
//
// Expected API (package vault):
//
//	// Delete removes the saved session of id: sessions/<id>.sess is removed
//	// without being opened, then the keyring entry is Deleted, both under
//	// the sessions/<id>.lock lock. A missing file or key is not an error
//	// (idempotent). An invalid id is ErrInvalidArgument before any file or
//	// keyring access. A keyring Delete error wraps ErrKeyring (the file is
//	// already gone: the orphan key opens nothing). When the store is not
//	// persistent Delete touches nothing and returns nil.
//	func (s *Store) Delete(ctx context.Context, id string) error
package vault_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/vault"
)

// errDeleteBackend is a synthetic keyring backend failure.
var errDeleteBackend = errors.New("synthetic keyring delete failure")

// deleteFailKeys is a fakeKeys whose Delete fails.
type deleteFailKeys struct{ *fakeKeys }

func (d deleteFailKeys) Delete(ctx context.Context, ref secret.Ref) error {
	_ = d.fakeKeys.Delete(ctx, ref)
	return errDeleteBackend
}

func TestStore_DeleteRemovesFileAndKeyUnread(t *testing.T) {
	t.Parallel()
	f := newPersistent(t)
	mustSave(t, f.store, "edf", "synthetic edf jar")
	mustSave(t, f.store, "ileo", "synthetic ileo jar")
	install := f.installID(t)
	f.keys.resetCalls()
	opens := f.spy.count()

	if err := f.store.Delete(t.Context(), "edf"); err != nil {
		t.Fatalf("Delete(edf): %v", err)
	}
	if exists(t, f.sessPath("edf")) {
		t.Fatal("sessions/edf.sess still present after Delete")
	}
	if _, ok := f.keys.get(sessionRef(install, "edf")); ok {
		t.Fatal("edf keyring entry still present after Delete")
	}
	resolves, sets, deletes := f.keys.calls()
	if len(resolves) != 0 || len(sets) != 0 {
		t.Fatalf("Delete read or wrote the keyring: %d Resolve, %d Set", len(resolves), len(sets))
	}
	if len(deletes) != 1 || deletes[0] != sessionRef(install, "edf") {
		t.Fatalf("keyring Delete calls = %v, want exactly the edf entry", deletes)
	}
	if n := f.spy.count(); n != opens {
		t.Fatalf("Delete opened %d session files, want 0", n-opens)
	}
	wantNoSession(t, f.store, "edf")
	mustLoad(t, f.store, "ileo", "synthetic ileo jar")

	// Idempotent: nothing left to delete is not an error.
	if err := f.store.Delete(t.Context(), "edf"); err != nil {
		t.Fatalf("second Delete(edf): %v", err)
	}
	if err := f.store.Delete(t.Context(), "never-saved"); err != nil {
		t.Fatalf("Delete(never-saved): %v", err)
	}
}

func TestStore_DeleteKeyringErrorWrapsErrKeyring(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	keys := newFakeKeys()
	s, _, _ := openStore(t, dir, vault.Persistent, deleteFailKeys{keys}, nil)
	mustSave(t, s, "edf", "synthetic edf jar")

	err := s.Delete(t.Context(), "edf")
	if !errors.Is(err, vault.ErrKeyring) {
		t.Fatalf("Delete: err = %v, want ErrKeyring", err)
	}
	if exists(t, filepath.Join(dir, "sessions", "edf.sess")) {
		t.Fatal("session file kept after a keyring Delete error, want it removed first")
	}
}

func TestStore_DeleteIDTraversalRefused(t *testing.T) {
	t.Parallel()
	ids := []string{"", ".", "..", "../edf", "a/b", `..\edf`, "/edf", "edf.sess", "EDF", "edf\x00", " edf"}
	for _, mode := range []vault.Mode{vault.Persistent, vault.Ephemeral} {
		t.Run(fmt.Sprintf("mode %d", mode), func(t *testing.T) {
			t.Parallel()
			dir := newStateDir(t)
			keys := newFakeKeys()
			s, spy, _ := openStore(t, dir, mode, keys, nil)
			parent := filepath.Dir(dir)
			before := snapshot(t, parent)
			keys.resetCalls()
			for _, id := range ids {
				if err := s.Delete(t.Context(), id); !errors.Is(err, vault.ErrInvalidArgument) {
					t.Errorf("Delete(%q): err = %v, want ErrInvalidArgument", id, err)
				}
			}
			wantSameTree(t, before, snapshot(t, parent))
			keys.wantNoCalls(t)
			if n := spy.count(); n != 0 {
				t.Fatalf("%d opens for invalid ids", n)
			}
		})
	}
}

func TestStore_DeleteEphemeralTouchesNothing(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	keys := newFakeKeys()
	s, spy, _ := openStore(t, dir, vault.Ephemeral, keys, nil)
	before := snapshot(t, dir)
	keys.resetCalls()
	if err := s.Delete(t.Context(), "edf"); err != nil {
		t.Fatalf("Delete in ephemeral mode: %v", err)
	}
	wantSameTree(t, before, snapshot(t, dir))
	keys.wantNoCalls(t)
	if n := spy.count(); n != 0 {
		t.Fatalf("%d opens in ephemeral mode", n)
	}
}
