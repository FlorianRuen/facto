//go:build unix

// TestCollect_StaleProfilesSweptAtStartup (J1 task T19, decision A12):
// collect builds the production browser pool (env.NewPool nil, so
// newBrowserPool → browser.NewPool) at startup, even with no connector and
// no browser, and NewPool sweeps the stale profiles a crashed run left in
// both $XDG_RUNTIME_DIR/facto and <state_dir>/tmp. Profiles of live
// processes and unrelated entries are kept. No browser is started. All
// profile content is synthetic.
package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// deadPid is a pid no process has (above every pid_max): its profiles are
// stale.
const deadPid = 2147483646

func TestCollect_StaleProfilesSweptAtStartup(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)

	// $XDG_RUNTIME_DIR: a private directory outside the sandbox home.
	runtimeDir := filepath.Join(t.TempDir(), "run")
	root, err := fsx.Open(filepath.Dir(runtimeDir))
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	if err := root.MkdirPrivate("run/facto"); err != nil {
		t.Fatalf("setup mkdir: %v", err)
	}
	_ = root.Close()
	runtimeBase := filepath.Join(runtimeDir, "facto")
	stateBase := filepath.Join(s.state, "tmp")

	stale := "profile-" + strconv.Itoa(deadPid) + "-synthstale"
	live := "profile-" + strconv.Itoa(os.Getpid()) + "-synthlive"
	other := "notes-synthetic"
	stateRel, err := filepath.Rel(s.home, stateBase)
	if err != nil {
		t.Fatalf("setup rel: %v", err)
	}
	for _, name := range []string{stale, live, other} {
		writeFile(t, runtimeDir, "facto/"+name+"/Default/Cookies", []byte(cookie))
		writeFile(t, s.home, filepath.ToSlash(stateRel)+"/"+name+"/Default/Cookies", []byte(cookie))
	}

	e := s.env()
	e.LookupEnv = func(k string) (string, bool) {
		if k == "XDG_RUNTIME_DIR" {
			return runtimeDir, true
		}
		return "", false
	}
	res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
	if res.code != orchestrator.ExitOK {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
	}
	for _, base := range []string{runtimeBase, stateBase} {
		if _, err := os.Lstat(filepath.Join(base, stale)); !os.IsNotExist(err) {
			t.Errorf("stale profile %s not swept (lstat err = %v)", filepath.Join(base, stale), err)
		}
		for _, keep := range []string{live, other} {
			if _, err := os.Lstat(filepath.Join(base, keep, "Default", "Cookies")); err != nil {
				t.Errorf("%s removed by the startup sweep: %v", filepath.Join(base, keep), err)
			}
		}
	}
	fi, err := os.Lstat(runtimeBase)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("pool base %s: mode %v, err %v; want a 0700 directory", runtimeBase, fi, err)
	}
}
