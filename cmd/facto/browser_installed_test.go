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

	"github.com/FlorianRuen/facto/internal/browser/cft"
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
}
