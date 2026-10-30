//go:build unix

// Review follow-up of J1 T19 (A12): collect builds the browser pool, and so
// sweeps stale profiles, before opening the session store: a store that
// fails to open still leaves no stale profile behind. Synthetic only.
package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/vault"
)

func TestCollect_SessionsFailureStillSweeps(t *testing.T) {
	t.Parallel()
	r := newLoginRig(t, &synthConn{persist: "synthetic-blob"}, false, "synthetic")
	cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, ""))
	stateName := filepath.Base(r.s.state)
	stale := "profile-" + strconv.Itoa(deadPid) + "-synthstale"
	writeFile(t, r.s.home, stateName+"/tmp/"+stale+"/Default/Cookies", []byte("synthetic"))
	// An unreadable install-id makes the session store fail to open.
	writeFile(t, r.s.home, stateName+"/"+vault.InstallIDFile, []byte("0123456789abcdef0123456789abcdef"))
	if err := os.Chmod(filepath.Join(r.s.state, vault.InstallIDFile), 0o000); err != nil {
		t.Fatalf("setup chmod: %v", err)
	}
	e := r.env()
	e.NewPool = nil // the production pool and its sweep

	res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
	if res.code != orchestrator.ExitAttention {
		t.Fatalf("exit code = %d, want %d (session store refused)\nstderr:\n%s", res.code, orchestrator.ExitAttention, res.stderr)
	}
	if _, err := os.Lstat(filepath.Join(r.s.state, "tmp", stale)); !os.IsNotExist(err) {
		t.Errorf("stale profile not swept when the session store failed (lstat err = %v)", err)
	}
	if built, closed := r.secr.counts(); built != 1 || closed != 1 {
		t.Errorf("resolver built %d, closed %d; want 1 and 1", built, closed)
	}
}
