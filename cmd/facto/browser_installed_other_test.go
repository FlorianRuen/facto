//go:build !(linux && amd64)

// Installed-browser behaviour on platforms without a pinned Chrome for
// Testing build (everything but linux/amd64, see
// browser_installed_linux_amd64_test.go): a verified-looking install under
// <state>/chrome is never reported, collect never uses it and never warns
// about its age.
package main

import (
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

// TestInstalledBrowser_NoPinnedBuildOnThisPlatform: installedBrowser
// returns ("", false) even for a layout that is a verified install on
// linux/amd64.
func TestInstalledBrowser_NoPinnedBuildOnThisPlatform(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	writeFile(t, s.home, ".facto/.keep", nil)
	fakeInstall{marker: cft.Pinned().SHA256}.write(t, s.state)
	if got, ok := installedBrowser(s.env(), s.state); ok || got != "" {
		t.Fatalf("installedBrowser() = %q, %v; want \"\", false (no pinned build here)", got, ok)
	}
}

// TestCollect_NoStaleWarningWithoutPinnedBuild: with a verified-looking
// install and a stale clock, collect neither uses the install nor warns
// about the pin (the browser in use is never the pinned build here).
func TestCollect_NoStaleWarningWithoutPinnedBuild(t *testing.T) {
	t.Parallel()
	conn := &synthConn{persist: "synthetic-session-blob", launch: true}
	r := newLoginRig(t, conn, false, "synthetic")
	writeFile(t, r.s.home, ".facto/.keep", nil)
	fakeInstall{marker: cft.Pinned().SHA256}.write(t, r.s.state)
	cfg := r.s.writeConfig(t, synthConfig(true, "", ""))
	e := r.env()
	e.InstalledBrowser = nil // the production lookup under state_dir
	e.Clock = clock.NewFake(cft.Pinned().PinnedAt.Add(cft.MaxPinAge + 24*time.Hour))

	res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
	if res.code != orchestrator.ExitOK {
		t.Fatalf("exit code = %d, want %d\nstderr:\n%s", res.code, orchestrator.ExitOK, res.stderr)
	}
	if strings.Contains(res.stderr, staleWarning) || strings.Contains(res.stdout, staleWarning) {
		t.Errorf("stale-pin warning printed without a pinned build:\nstdout:\n%s\nstderr:\n%s", res.stdout, res.stderr)
	}
	params, _, _ := r.pool.snapshot()
	for _, p := range params {
		if p.Executable == pinnedExe(r.s.state) {
			t.Errorf("pool built with the unpinned install %q", p.Executable)
		}
	}
}
