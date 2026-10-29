// Ephemeral mode without a usable keyring (J1 T16, decision recorded with the
// task): the user chose ephemeral sessions, so every sessions/*.sess is still
// removed unopened; no keyring call is made; one log line. Persistent mode
// without a keyring touches nothing (TestStore_NoKeyringFallbackDeletesNothing).
package vault_test

import (
	"crypto/rand"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/vault"
)

func TestStore_EphemeralWithoutKeyringStillSweepsFiles(t *testing.T) {
	t.Parallel()
	cause := errors.New("synthetic: secret service unavailable")
	tests := []struct {
		name    string
		keys    bool
		keysErr error
	}{
		{"no backend", false, nil},
		{"backend unavailable", true, cause},
		{"no backend with cause", false, cause},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := newStateDir(t)
			install := "0123456789abcdef0123456789abcdef"
			put(t, dir, "install-id", []byte(install))
			for _, name := range []string{"edf.sess", "ileo.sess", "Legacy_Name.sess"} {
				put(t, dir, "sessions/"+name, []byte("synthetic opaque bytes"))
			}
			put(t, dir, "sessions/notes.txt", []byte("synthetic note"))
			keys := newFakeKeys()
			var kb vault.KeyBackend
			if tc.keys {
				kb = keys
			}

			s, spy, logs := openStore(t, dir, vault.Ephemeral, kb, tc.keysErr)
			if s.Persistent() {
				t.Fatalf("Persistent() = true in ephemeral mode")
			}
			for _, name := range []string{"edf.sess", "ileo.sess", "Legacy_Name.sess"} {
				if exists(t, filepath.Join(dir, "sessions", name)) {
					t.Errorf("sessions/%s survived the sweep without a keyring", name)
				}
			}
			if !exists(t, filepath.Join(dir, "sessions", "notes.txt")) {
				t.Errorf("sessions/notes.txt removed, want only *.sess removed")
			}
			if got := string(readBytes(t, filepath.Join(dir, "install-id"))); got != install {
				t.Errorf("install-id changed")
			}
			if n := spy.count(); n != 0 {
				t.Fatalf("sweep opened %d files", n)
			}
			keys.wantNoCalls(t)
			recs := logs.records(t, slog.LevelInfo)
			if len(recs) != 1 || recs[0]["removed"] != float64(3) {
				t.Fatalf("want one log line with removed=3:\n%s", logs.text())
			}
		})
	}
}

func TestStore_NewRefusesUnknownMode(t *testing.T) {
	t.Parallel()
	_, err := vault.NewStore(t.Context(), vault.Options{
		StateDir: newStateDir(t), Mode: vault.Mode(7), Keyring: newFakeKeys(), Rand: rand.Reader,
	})
	if !errors.Is(err, vault.ErrInvalidArgument) {
		t.Fatalf("NewStore(unknown mode): err = %v, want ErrInvalidArgument", err)
	}
}

func TestStore_EphemeralSweepRefusesNonDirSessions(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	put(t, dir, "sessions", []byte("synthetic: not a directory"))
	keys := newFakeKeys()
	_, err := vault.NewStore(t.Context(), vault.Options{
		StateDir: dir, Mode: vault.Ephemeral, Keyring: keys, Rand: rand.Reader,
	})
	if !errors.Is(err, fsx.ErrNotDir) {
		t.Fatalf("NewStore(ephemeral, sessions is a file): err = %v, want fsx.ErrNotDir", err)
	}
	if !exists(t, filepath.Join(dir, "sessions")) {
		t.Fatalf("sweep removed the non-directory sessions entry")
	}
	keys.wantNoCalls(t)
}
