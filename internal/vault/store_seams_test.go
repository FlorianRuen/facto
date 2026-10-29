// Store failure paths driven through seams (J1 T16 review): session file
// write failure and ErrNotDurable (Options.Write), install-id creation race,
// durability and hard-link failures, and install-id read errors in ephemeral
// mode (export_test.go hooks).
package vault_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/vault"
)

func seamStore(t *testing.T, dir string, mode vault.Mode, keys vault.KeyBackend, edit func(vault.Options) vault.Options) (*vault.Store, *logCapture) {
	t.Helper()
	s, logs, err := seamStoreErr(t, dir, mode, keys, edit)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, logs
}

func seamStoreErr(t *testing.T, dir string, mode vault.Mode, keys vault.KeyBackend, edit func(vault.Options) vault.Options) (*vault.Store, *logCapture, error) {
	t.Helper()
	logs := &logCapture{}
	opts := vault.Options{StateDir: dir, Mode: mode, Keyring: keys, Rand: rand.Reader, Log: logs.logger()}
	if edit != nil {
		opts = edit(opts)
	}
	s, err := vault.NewStore(t.Context(), opts)
	return s, logs, err
}

func TestStore_SessionWriteFailureRemovesOldFile(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	keys := newFakeKeys()
	writeErr := errors.New("synthetic: disk full")
	fail := false
	s, logs := seamStore(t, dir, vault.Persistent, keys, func(o vault.Options) vault.Options {
		o.Write = func(ctx context.Context, sessions *fsx.Root, name string, data []byte) error {
			if fail {
				return fmt.Errorf("synthetic write %s: %w", name, writeErr)
			}
			return sessions.WriteAtomic(ctx, name, data)
		}
		return o
	})
	mustSave(t, s, "edf", "synthetic jar old")
	fail = true

	err := s.Save(t.Context(), "edf", secret.FromString("synthetic jar new"))
	if !errors.Is(err, writeErr) {
		t.Fatalf("Save: err = %v, want the write error", err)
	}
	if exists(t, filepath.Join(dir, "sessions", "edf.sess")) {
		t.Fatalf("old session file kept although its key was replaced")
	}
	if warns := logs.records(t, slog.LevelWarn); len(warns) != 1 {
		t.Fatalf("%d warnings, want one:\n%s", len(warns), logs.text())
	}
	wantNoSession(t, s, "edf")
}

func TestStore_SessionWriteNotDurableKeepsNewFile(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	keys := newFakeKeys()
	s, _ := seamStore(t, dir, vault.Persistent, keys, func(o vault.Options) vault.Options {
		o.Write = func(ctx context.Context, sessions *fsx.Root, name string, data []byte) error {
			if err := sessions.WriteAtomic(ctx, name, data); err != nil {
				return err
			}
			return fmt.Errorf("synthetic: %w", fsx.ErrNotDurable)
		}
		return o
	})
	err := s.Save(t.Context(), "edf", secret.FromString("synthetic jar"))
	if !errors.Is(err, fsx.ErrNotDurable) {
		t.Fatalf("Save: err = %v, want ErrNotDurable", err)
	}
	mustLoad(t, s, "edf", "synthetic jar")
}

func TestInstallID_CreationRaceUsesWinner(t *testing.T) {
	t.Parallel()
	const winner = "fedcba9876543210fedcba9876543210"
	tests := []struct {
		name       string
		planted    string
		persistent bool
	}{
		{"valid winner", winner, true},
		{"malformed winner", "synthetic-not-an-install-id", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := newStateDir(t)
			keys := newFakeKeys()
			s, logs := seamStore(t, dir, vault.Persistent, keys, func(o vault.Options) vault.Options {
				return vault.WithInstallIDWrite(o, func(ctx context.Context, state *fsx.Root, name string, src io.Reader) error {
					// Another first run publishes its id just before ours.
					if err := state.WriteAtomic(ctx, name, []byte(tc.planted)); err != nil {
						t.Errorf("plant install-id: %v", err)
					}
					return state.WriteNew(ctx, name, src)
				})
			})
			if got := readInstallID(t, dir); got != tc.planted {
				t.Fatalf("install-id rewritten after losing the race")
			}
			if s.Persistent() != tc.persistent {
				t.Fatalf("Persistent() = %v, want %v", s.Persistent(), tc.persistent)
			}
			if !tc.persistent {
				if warns := logs.records(t, slog.LevelWarn); len(warns) != 1 {
					t.Fatalf("%d warnings, want one:\n%s", len(warns), logs.text())
				}
				return
			}
			mustSave(t, s, "edf", "synthetic jar")
			if _, sets, _ := keys.calls(); len(sets) != 1 || sets[0] != sessionRef(winner, "edf") {
				t.Fatalf("Set refs = %v, want the winner's install id", sets)
			}
		})
	}
}

func TestInstallID_NotDurableIsCreated(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	keys := newFakeKeys()
	s, logs := seamStore(t, dir, vault.Persistent, keys, func(o vault.Options) vault.Options {
		return vault.WithInstallIDWrite(o, func(ctx context.Context, state *fsx.Root, name string, src io.Reader) error {
			if err := state.WriteNew(ctx, name, src); err != nil {
				return err
			}
			return fmt.Errorf("synthetic: %w", fsx.ErrNotDurable)
		})
	})
	if !s.Persistent() {
		t.Fatalf("Persistent() = false after an install-id written but not synced")
	}
	if warns := logs.records(t, slog.LevelWarn); len(warns) != 0 {
		t.Fatalf("unexpected warnings:\n%s", logs.text())
	}
	mustSave(t, s, "edf", "synthetic jar")
	if _, sets, _ := keys.calls(); len(sets) != 1 || sets[0] != sessionRef(readInstallID(t, dir), "edf") {
		t.Fatalf("Set refs = %v, want the created install id", sets)
	}
}

func TestInstallID_LinkUnsupportedFallsBackWithWarning(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	keys := newFakeKeys()
	s, logs := seamStore(t, dir, vault.Persistent, keys, func(o vault.Options) vault.Options {
		return vault.WithInstallIDWrite(o, func(context.Context, *fsx.Root, string, io.Reader) error {
			return fmt.Errorf("synthetic link in %q: %w", ".", fsx.ErrLinkUnsupported)
		})
	})
	if s.Persistent() {
		t.Fatalf("Persistent() = true without an install-id")
	}
	before := snapshot(t, dir)
	mustSave(t, s, "edf", "synthetic jar")
	wantNoSession(t, s, "edf")
	wantSameTree(t, before, snapshot(t, dir))
	keys.wantNoCalls(t)
	warns := logs.records(t, slog.LevelWarn)
	if len(warns) != 1 || !strings.Contains(logs.text(), "hard link") {
		t.Fatalf("want one warning naming the hard-link failure:\n%s", logs.text())
	}
}

func TestStore_EphemeralInstallIDReadErrorStillSweeps(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	put(t, dir, "install-id", []byte("0123456789abcdef0123456789abcdef"))
	for _, name := range []string{"edf.sess", "ileo.sess"} {
		put(t, dir, "sessions/"+name, []byte("synthetic opaque bytes"))
	}
	keys := newFakeKeys()
	readErr := errors.New("synthetic: input/output error")
	_, logs := seamStore(t, dir, vault.Ephemeral, keys, func(o vault.Options) vault.Options {
		return vault.WithInstallIDOpen(o, func(*fsx.Root, string) (io.ReadCloser, error) {
			return nil, readErr
		})
	})
	for _, name := range []string{"edf.sess", "ileo.sess"} {
		if exists(t, filepath.Join(dir, "sessions", name)) {
			t.Errorf("sessions/%s survived the sweep", name)
		}
	}
	keys.wantNoCalls(t)
	recs := logs.records(t, slog.LevelInfo)
	if len(recs) != 1 || recs[0]["removed"] != float64(2) {
		t.Fatalf("want one log line with removed=2:\n%s", logs.text())
	}
	if recs[0]["keys_skipped"] != true {
		t.Fatalf("log line does not report the skipped key deletes:\n%s", logs.text())
	}
}

func TestStore_PersistentInstallIDReadErrorFails(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	readErr := errors.New("synthetic: input/output error")
	_, _, err := seamStoreErr(t, dir, vault.Persistent, newFakeKeys(), func(o vault.Options) vault.Options {
		return vault.WithInstallIDOpen(o, func(*fsx.Root, string) (io.ReadCloser, error) {
			return nil, readErr
		})
	})
	if !errors.Is(err, readErr) {
		t.Fatalf("NewStore: err = %v, want the read error", err)
	}
}
