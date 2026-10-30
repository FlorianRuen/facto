// Tests for the installed-browser wiring of J1 task T13 (follow-ups of
// T12/T19 in docs/agentic/PROGRESS.md): collect and login use the Chrome
// for Testing build `facto browser install` verified under the state dir,
// and warn when that pinned build is stale. All files are synthetic; no
// test runs a browser or touches the network.
//
// Expected API (changes to wiring.go and main.go):
//
//	// env.InstalledBrowser gets the configured state dir (cfg.StateDir):
//	InstalledBrowser func(e env, stateDir string) (string, bool)
//
//	// installedBrowser returns <stateDir>/chrome/<cft.Pinned().Version>/
//	// chrome-linux64/chrome, true when that install is verified the way
//	// cft.Installer.Install checks it: <version>/ a real directory,
//	// <version>/.facto-verified (cft.MarkerName) a regular file holding
//	// cft.Pinned().SHA256 (surrounding white space ignored), and the
//	// executable a regular file (no symlink anywhere below stateDir/chrome
//	// is followed). Anything else, or a platform without a pinned build
//	// (not linux/amd64), gives ("", false). It never creates or modifies
//	// anything.
//	func installedBrowser(e env, stateDir string) (string, bool)
//
//	// installedFor(e, stateDir) binds the seam (nil = installedBrowser).
//	func installedFor(e env, stateDir string) func() (string, bool)
//
//	// collect (and login) call cft.WarnIfStale(ctx, log, e.Clock,
//	// cft.Pinned()) once per run when the browser path in use is the
//	// installed pinned build; never for a browser.path set in config.yaml
//	// (user-supplied, unpinned), never when no browser is found.
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

// staleWarning is the start of cft.WarnIfStale's message.
const staleWarning = "the pinned Chrome for Testing build is more than 4 weeks old"

// pinnedExe is the executable path of a verified install under state.
func pinnedExe(state string) string {
	return filepath.Join(state, "chrome", cft.Pinned().Version, "chrome-linux64", "chrome")
}

// fakeInstall lays out what `facto browser install` leaves under
// <state>/chrome (synthetic executable, never run).
type fakeInstall struct {
	marker    string // marker content; "" = no marker
	noExe     bool   // no executable
	exeIsDir  bool   // the executable path is a directory
	exeLink   bool   // the executable is a symlink to a regular file
	version   string // version directory; "" = cft.Pinned().Version
	markerDir bool   // the marker is a directory
}

func (f fakeInstall) write(t *testing.T, state string) {
	t.Helper()
	version := f.version
	if version == "" {
		version = cft.Pinned().Version
	}
	base := "chrome/" + version
	switch {
	case f.noExe:
		writeFile(t, state, base+"/chrome-linux64/.keep", nil)
	case f.exeIsDir:
		writeFile(t, state, base+"/chrome-linux64/chrome/.keep", nil)
	case f.exeLink:
		writeFile(t, state, "elsewhere/chrome", []byte("synthetic browser binary\n"))
		writeFile(t, state, base+"/chrome-linux64/.keep", nil)
		if err := os.Symlink(filepath.Join(state, "elsewhere", "chrome"), filepath.Join(state, filepath.FromSlash(base), "chrome-linux64", "chrome")); err != nil {
			t.Fatal(err)
		}
	default:
		writeFile(t, state, base+"/chrome-linux64/chrome", []byte("synthetic browser binary\n"))
	}
	switch {
	case f.markerDir:
		writeFile(t, state, base+"/"+cft.MarkerName+"/.keep", nil)
	case f.marker != "":
		writeFile(t, state, base+"/"+cft.MarkerName, []byte(f.marker))
	}
}

// TestInstalledBrowser_FindsCftInstall: the installed browser is the
// verified Chrome for Testing build under <state>/chrome, and only that.
func TestInstalledBrowser_FindsCftInstall(t *testing.T) {
	t.Parallel()
	pinned := runtime.GOOS == "linux" && runtime.GOARCH == "amd64"
	sum := cft.Pinned().SHA256
	tests := []struct {
		name    string
		install *fakeInstall // nil = nothing installed
		want    bool
	}{
		{name: "verified install", install: &fakeInstall{marker: sum}, want: pinned},
		{name: "marker with trailing newline", install: &fakeInstall{marker: sum + "\n"}, want: pinned},
		{name: "nothing installed"},
		{name: "no marker (interrupted install)", install: &fakeInstall{}},
		{name: "marker of another archive", install: &fakeInstall{marker: strings.Repeat("0", 64)}},
		{name: "marker is a directory", install: &fakeInstall{markerDir: true}},
		{name: "executable missing", install: &fakeInstall{marker: sum, noExe: true}},
		{name: "executable is a directory", install: &fakeInstall{marker: sum, exeIsDir: true}},
		{name: "executable is a symlink", install: &fakeInstall{marker: sum, exeLink: true}},
		{name: "only another version installed", install: &fakeInstall{marker: sum, version: "1.0.0.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			writeFile(t, s.home, ".facto/.keep", nil)
			if tt.install != nil {
				tt.install.write(t, s.state)
			}
			got, ok := installedBrowser(s.env(), s.state)
			if ok != tt.want {
				t.Fatalf("installedBrowser() = %q, %v; want ok %v", got, ok, tt.want)
			}
			if tt.want && got != pinnedExe(s.state) {
				t.Errorf("installedBrowser() = %q, want %q", got, pinnedExe(s.state))
			}
			if !tt.want && got != "" {
				t.Errorf("installedBrowser() = %q with ok false, want \"\"", got)
			}
		})
	}

	t.Run("collect uses the installed build when browser.path is unset", func(t *testing.T) {
		t.Parallel()
		if !pinned {
			t.Fatalf("no pinned build for %s/%s: this subtest needs linux/amd64", runtime.GOOS, runtime.GOARCH)
		}
		conn := &synthConn{persist: "synthetic-session-blob"}
		r := newLoginRig(t, conn, false, "synthetic")
		writeFile(t, r.s.home, ".facto/.keep", nil)
		fakeInstall{marker: sum}.write(t, r.s.state)
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
	})
}

// TestCollect_WarnsWhenPinnedChromeStale (ADR 0008 patching policy, fake
// clock): a run on the installed pinned build warns once when the pin is
// more than cft.MaxPinAge old; a fresh pin, a user-supplied browser.path
// and a run without any browser never warn.
func TestCollect_WarnsWhenPinnedChromeStale(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatalf("no pinned build for %s/%s: this test needs linux/amd64", runtime.GOOS, runtime.GOARCH)
	}
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
