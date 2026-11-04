//go:build linux && amd64

// Installed-browser tests that need the pinned Chrome for Testing build,
// which only exists for linux/amd64 (cft.Pinned().Platform "linux64").
// browser_installed_other_test.go asserts the behaviour on every other
// platform: no installed browser is ever reported there.
package main

import (
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

// TestInstalledBrowser_CollectUsesInstalledBuild: collect uses the
// installed build when browser.path is unset.
func TestInstalledBrowser_CollectUsesInstalledBuild(t *testing.T) {
	t.Parallel()
	conn := &synthConn{persist: "synthetic-session-blob"}
	r := newLoginRig(t, conn, false, "synthetic")
	writeFile(t, r.s.home, ".facto/.keep", nil)
	fakeInstall{marker: cft.Pinned().SHA256}.write(t, r.s.state)
	cfg := r.s.writeConfig(t, synthConfig(true, "", ""))
	e := r.env()
	e.InstalledBrowser = nil // the production lookup under state_dir
	res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
	if res.code != orchestrator.ExitOK {
		t.Fatalf("exit code = %d\nstderr:\n%s", res.code, res.stderr)
	}
	params, _, _ := r.pool.snapshot()
	if len(params) != 1 || params[0].Executable != pinnedExe(r.s.state) {
		t.Errorf("pool built with %+v, want Executable %q", params, pinnedExe(r.s.state))
	}
}

// TestCollect_WarnsWhenPinnedChromeStale (ADR 0008 patching policy, fake
// clock): a run on the installed pinned build warns once when the pin is
// more than cft.MaxPinAge old; a fresh pin, a user-supplied browser.path
// and a run without any browser never warn.
func TestCollect_WarnsWhenPinnedChromeStale(t *testing.T) {
	t.Parallel()
	pinnedAt := cft.Pinned().PinnedAt
	stale := pinnedAt.Add(cft.MaxPinAge + 24*time.Hour)
	fresh := pinnedAt.Add(24 * time.Hour)
	tests := []struct {
		name       string
		now        time.Time
		installed  bool
		configured bool // browser.path set in config.yaml
		wantWarn   int
	}{
		{name: "installed and stale", now: stale, installed: true, wantWarn: 1},
		{name: "installed and fresh", now: fresh, installed: true},
		{name: "installed, exactly MaxPinAge old", now: pinnedAt.Add(cft.MaxPinAge), installed: true},
		{name: "browser.path configured, stale clock", now: stale, installed: true, configured: true},
		{name: "no browser at all, stale clock", now: stale},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := &synthConn{persist: "synthetic-session-blob", launch: true}
			r := newLoginRig(t, conn, false, "synthetic")
			writeFile(t, r.s.home, ".facto/.keep", nil)
			if tt.installed {
				fakeInstall{marker: cft.Pinned().SHA256}.write(t, r.s.state)
			}
			browserPath := ""
			if tt.configured {
				browserPath = r.chrom
			}
			cfg := r.s.writeConfig(t, synthConfig(true, browserPath, ""))
			e := r.env()
			e.InstalledBrowser = nil // the production lookup under state_dir
			e.Clock = clock.NewFake(tt.now)

			res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
			if res.code != orchestrator.ExitOK {
				t.Fatalf("exit code = %d, want %d\nstderr:\n%s", res.code, orchestrator.ExitOK, res.stderr)
			}
			if n := strings.Count(res.stderr, staleWarning); n != tt.wantWarn {
				t.Errorf("%d stale-pin warnings on stderr, want %d:\n%s", n, tt.wantWarn, res.stderr)
			}
			if tt.wantWarn > 0 && !strings.Contains(res.stderr, cft.Pinned().Version) {
				t.Errorf("stale-pin warning does not name the pinned version %s:\n%s", cft.Pinned().Version, res.stderr)
			}
			if strings.Contains(res.stdout, staleWarning) {
				t.Error("stale-pin warning printed on stdout, want stderr (log) only")
			}
		})
	}
}
