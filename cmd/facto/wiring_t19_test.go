// Extra tests for the T19 session wiring: the key backend seam is asked
// once per run, and a successful persistent run deletes no key. Synthetic
// values only.
package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/vault"
)

// persistSession is the Persistable session of the synthetic connector.
var _ connector.Persistable = persistSession{}

// TestCollect_KeyBackendAskedOnce: collect asks the key backend seam once;
// without a keyring the run is ephemeral with one warning; with one, a
// successful run deletes no key.
func TestCollect_KeyBackendAskedOnce(t *testing.T) {
	t.Parallel()

	t.Run("no keyring", func(t *testing.T) {
		t.Parallel()
		r := newLoginRig(t, &synthConn{persist: "synthetic-blob"}, false, "synthetic")
		cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, ""))
		kb := &countingNoKeyring{}
		e := r.env()
		e.KeyBackend = kb.factory()
		res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
		if res.code != orchestrator.ExitOK {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
		}
		if kb.count() != 1 {
			t.Errorf("key backend asked %d times, want 1", kb.count())
		}
		if n := strings.Count(res.stderr, "sessions are ephemeral"); n != 1 {
			t.Errorf("%d ephemeral warnings, want 1:\n%s", n, res.stderr)
		}
	})

	t.Run("keyring", func(t *testing.T) {
		t.Parallel()
		r := newLoginRig(t, &synthConn{persist: "synthetic-blob"}, false, "synthetic")
		cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, ""))
		res := invoke(t.Context(), r.env(), "", "collect", "--config", cfg, "--year", "2026")
		if res.code != orchestrator.ExitOK {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
		}
		_, sets, deletes, built := r.keys.counts()
		if built != 1 || sets != 1 || deletes != 0 {
			t.Errorf("key backend built %d, sets %d, deletes %d; want 1, 1, 0", built, sets, deletes)
		}
	})
}

// TestSessions_EphemeralNeverProbesKeyring: with sessions: ephemeral the
// key backend is never asked (no unlock dialog for a run that needs no
// key), in collect and in login.
func TestSessions_EphemeralNeverProbesKeyring(t *testing.T) {
	t.Parallel()
	for _, cmd := range []string{"collect", "login"} {
		t.Run(cmd, func(t *testing.T) {
			t.Parallel()
			r := newLoginRig(t, &synthConn{persist: "synthetic-blob"}, cmd == "login", "synthetic")
			cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, "sessions: ephemeral\n"))
			kb := &countingNoKeyring{}
			e := r.env()
			e.KeyBackend = kb.factory()
			args := []string{"collect", "--config", cfg, "--year", "2026"}
			if cmd == "login" {
				args = []string{"login", synthID, "--config", cfg}
			}
			res := invoke(t.Context(), e, "", args...)
			if res.code != orchestrator.ExitOK {
				t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
			}
			if kb.count() != 0 {
				t.Errorf("key backend asked %d times in ephemeral mode, want 0", kb.count())
			}
		})
	}
}

// TestSessions_ProbeDeadlineOnlyWhenNonInteractive: a non-interactive run
// bounds the keyring probe (a locked keyring may wait for an unlock dialog
// nobody answers) with keyringProbeTimeout; an interactive one lets the
// user answer that dialog within the provider's own bound.
func TestSessions_ProbeDeadlineOnlyWhenNonInteractive(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name         string
		tty          bool
		wantDeadline bool
	}{
		{name: "non-interactive collect", wantDeadline: true},
		{name: "interactive collect", tty: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newLoginRig(t, &synthConn{persist: "synthetic-blob"}, tt.tty, "synthetic")
			cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, ""))
			var gotDeadline bool
			e := r.env()
			e.KeyBackend = func(ctx context.Context, _ env) (vault.KeyBackend, error) {
				_, gotDeadline = ctx.Deadline()
				return r.keys, nil
			}
			res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
			if res.code != orchestrator.ExitOK {
				t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
			}
			if gotDeadline != tt.wantDeadline {
				t.Errorf("probe ctx has a deadline = %v, want %v", gotDeadline, tt.wantDeadline)
			}
		})
	}
	if keyringProbeTimeout <= 0 || keyringProbeTimeout > 5_000_000_000 {
		t.Errorf("keyringProbeTimeout = %v, want a short positive bound", keyringProbeTimeout)
	}
}

// TestShutdownSignals_IncludeHangup: closing the terminal (SIGHUP) cancels
// the run like Ctrl-C, so a prompt waiting with echo off restores it.
func TestShutdownSignals_IncludeHangup(t *testing.T) {
	t.Parallel()
	if !slices.Contains(shutdownSignals(), os.Signal(syscall.SIGHUP)) {
		t.Errorf("shutdownSignals() = %v, want SIGHUP", shutdownSignals())
	}
}

// TestSessions_EphemeralWithSessionFilesDeletesKeys (ADR 0009, audit
// MEDIUM 2): when an ephemeral run finds saved sessions, it opens the key
// backend (probe bounded when non-interactive) and deletes their keys, so a
// backed-up .sess file is no longer decryptable; the files are removed
// unread either way, and a missing keyring is one warning.
func TestSessions_EphemeralWithSessionFilesDeletesKeys(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		noKeyring bool
	}{
		{name: "keyring available"},
		{name: "no keyring", noKeyring: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newLoginRig(t, &synthConn{persist: "synthetic-blob"}, false, "synthetic")
			cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, "sessions: ephemeral\n"))
			stateName := filepath.Base(r.s.state)
			writeFile(t, r.s.home, stateName+"/"+vault.InstallIDFile, []byte("0123456789abcdef0123456789abcdef"))
			writeFile(t, r.s.state, vault.SessionsDir+"/"+synthID+".sess", []byte("synthetic sealed blob"))

			var calls int
			var deadline bool
			kb := &countingNoKeyring{}
			e := r.env()
			e.KeyBackend = func(ctx context.Context, e env) (vault.KeyBackend, error) {
				calls++
				_, deadline = ctx.Deadline()
				if tt.noKeyring {
					return kb.factory()(ctx, e)
				}
				return r.keys, nil
			}
			res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
			if res.code != orchestrator.ExitOK {
				t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
			}
			if calls != 1 || !deadline {
				t.Errorf("key backend asked %d times (deadline %v), want once with a deadline", calls, deadline)
			}
			if _, err := os.Stat(sessFile(r.s.state, synthID)); !os.IsNotExist(err) {
				t.Errorf("session file kept (stat err = %v)", err)
			}
			resolves, sets, deletes, _ := r.keys.counts()
			if resolves != 0 || sets != 0 {
				t.Errorf("keyring resolves %d, sets %d; want 0", resolves, sets)
			}
			if tt.noKeyring {
				if deletes != 0 {
					t.Errorf("keys deleted %d without a keyring", deletes)
				}
				if n := strings.Count(res.stderr, "keys of removed sessions not deleted"); n != 1 {
					t.Errorf("%d keyring warnings, want 1:\n%s", n, res.stderr)
				}
				return
			}
			if deletes != 1 {
				t.Errorf("keys deleted %d, want 1 (the swept session's)", deletes)
			}
		})
	}
}
