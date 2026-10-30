package browser_test

// Chrome's private launch directories (J1 T23): TMPDIR and the XDG config,
// cache, data and state homes point into a per-launch 0700 area, so
// Chrome writes nothing (crash reports, fontconfig or dconf caches) under
// the user's ~/.config or ~/.cache, and its SingletonSocket path is
// checked against the unix socket limit before Chrome starts.
//
// Expected API (internal/browser):
//
//	// ErrSocketPathTooLong: the TMPDIR Chrome would get leaves its
//	// SingletonSocket path (TMPDIR/org.chromium.Chromium.XXXXXX/
//	// SingletonSocket) over the unix socket path limit (107 bytes on
//	// Linux). Launch fails before starting Chrome.
//	var ErrSocketPathTooLong error
//
//	// Options gains unexported privateDir and tempDir, set by the Pool
//	// only (no new exported knob: TestFlags_TestOnlyFlagsUnreachable...).
//	// They are checked like ProfileDir and in launchenv_internal_test.go.
//
//	// BuildLaunchEnv is BuildEnv with TMPDIR replaced by tmp (when not
//	// "") and XDG_CONFIG_HOME, XDG_CACHE_HOME under private (when not "").
//	func BuildLaunchEnv(lookup func(string) (string, bool), private, tmp string) []string

import (
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

func TestBuildLaunchEnv_PrivateDirs(t *testing.T) {
	t.Parallel()
	host := map[string]string{
		"HOME": "/facto-test/home", "DISPLAY": ":99", "TMPDIR": "/facto-test/tmp",
		"XDG_CONFIG_HOME": "/facto-test/home/.config", "XDG_CACHE_HOME": "/facto-test/home/.cache",
		"XDG_DATA_HOME": "/facto-test/home/.local/share", "XDG_STATE_HOME": "/facto-test/home/.local/state",
	}
	tests := []struct {
		name          string
		private, tmp  string
		wantTMP       string
		wantConfig    string
		wantCache     string
		wantNoXDGKeys bool
	}{
		{name: "private area and its TMPDIR", private: "/b/t1.1", tmp: "/b/t1.1", wantTMP: "/b/t1.1", wantConfig: "/b/t1.1/config", wantCache: "/b/t1.1/cache"},
		{name: "private area, inherited TMPDIR", private: "/b/t1.1", wantTMP: "/facto-test/tmp", wantConfig: "/b/t1.1/config", wantCache: "/b/t1.1/cache"},
		{name: "nothing private", wantTMP: "/facto-test/tmp", wantNoXDGKeys: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := browser.BuildLaunchEnv(mapLookup(host), tt.private, tt.tmp)
			got := envKeys(t, env)
			if got["TMPDIR"] != tt.wantTMP {
				t.Errorf("TMPDIR = %q, want %q", got["TMPDIR"], tt.wantTMP)
			}
			if got["HOME"] != "/facto-test/home" || got["DISPLAY"] != ":99" {
				t.Errorf("HOME/DISPLAY = %q/%q, want the user's (fonts, display)", got["HOME"], got["DISPLAY"])
			}
			if tt.wantNoXDGKeys {
				if !slices.Equal(env, browser.BuildEnv(mapLookup(host))) {
					t.Errorf("env = %q, want BuildEnv()", env)
				}
				return
			}
			if got["XDG_CONFIG_HOME"] != tt.wantConfig || got["XDG_CACHE_HOME"] != tt.wantCache {
				t.Errorf("XDG_CONFIG_HOME/XDG_CACHE_HOME = %q/%q, want %q/%q",
					got["XDG_CONFIG_HOME"], got["XDG_CACHE_HOME"], tt.wantConfig, tt.wantCache)
			}
			if want := tt.private + "/data"; got["XDG_DATA_HOME"] != want {
				t.Errorf("XDG_DATA_HOME = %q, want %q", got["XDG_DATA_HOME"], want)
			}
			if want := tt.private + "/state"; got["XDG_STATE_HOME"] != want {
				t.Errorf("XDG_STATE_HOME = %q, want %q", got["XDG_STATE_HOME"], want)
			}
		})
	}
}

func TestFlags_NoCrashReporting(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin", "windows"} {
		profile := "/facto-test/profile"
		if goos == "windows" {
			profile = `C:\facto-test\profile`
		}
		args, err := browser.Flags(browser.Options{GOOS: goos, ProfileDir: profile, AllowedDomains: testDomains})
		if err != nil {
			t.Fatalf("Flags(%s): %v", goos, err)
		}
		for _, f := range []string{"--disable-crash-reporter", "--disable-breakpad"} {
			if !slices.Contains(args, f) {
				t.Errorf("Flags(%s) lacks %s", goos, f)
			}
		}
		if err := browser.CheckFlags(goos, args); err != nil {
			t.Errorf("CheckFlags(%s) refuses the crash flags: %v", goos, err)
		}
	}
}

// socketSuffix is what Chrome appends to TMPDIR for its SingletonSocket.
const socketSuffix = "/org.chromium.Chromium.XXXXXX/SingletonSocket"

// dirOfLen returns an absolute clean path of exactly n bytes.
func dirOfLen(n int) string {
	p := "/facto-test/"
	return p + strings.Repeat("d", n-len(p))
}

// TestPrepare_InheritedTMPDIRSocketLimit: with no private area (Prepare's
// public options), the TMPDIR facto inherited is what Chrome gets: one that
// leaves the SingletonSocket path over 107 bytes fails with
// ErrSocketPathTooLong naming the cause, never a cryptic browser exit.
func TestPrepare_InheritedTMPDIRSocketLimit(t *testing.T) {
	t.Parallel()
	limit := 107 - len(socketSuffix) // longest TMPDIR that fits
	tests := []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{name: "at the limit", env: map[string]string{"TMPDIR": dirOfLen(limit)}},
		{name: "one byte over", env: map[string]string{"TMPDIR": dirOfLen(limit + 1)}, wantErr: true},
		{name: "far over", env: map[string]string{"TMPDIR": dirOfLen(300)}, wantErr: true},
		{name: "no TMPDIR: /tmp", env: map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := testHost(t, nil)
			h.LookupEnv = mapLookup(tt.env)
			o := launchOpts(t)
			o.GOOS = "linux"
			_, err := browser.Prepare(h, o)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Prepare: %v", err)
				}
				return
			}
			if !errors.Is(err, browser.ErrSocketPathTooLong) {
				t.Fatalf("Prepare = %v, want ErrSocketPathTooLong", err)
			}
			if errors.Is(err, browser.ErrBrowserGone) || errors.Is(err, browser.ErrLaunchFailed) {
				t.Errorf("error %v reads as a browser failure", err)
			}
			for _, word := range []string{"TMPDIR", "SingletonSocket", "107"} {
				if !strings.Contains(err.Error(), word) {
					t.Errorf("error %q does not name %q", err, word)
				}
			}
		})
	}
	// Only Linux Chrome takes its socket dir from TMPDIR.
	for _, goos := range []string{"darwin", "windows"} {
		h := testHost(t, nil)
		h.LookupEnv = mapLookup(map[string]string{"TMPDIR": dirOfLen(300)})
		o := launchOpts(t)
		if runtime.GOOS != goos {
			continue // the profile dir syntax is the host's
		}
		o.GOOS = goos
		if _, err := browser.Prepare(h, o); errors.Is(err, browser.ErrSocketPathTooLong) {
			t.Errorf("Prepare(%s) = %v, want no socket check", goos, err)
		}
	}
}
