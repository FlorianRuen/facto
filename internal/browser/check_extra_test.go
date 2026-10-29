package browser_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestCheckFlags_StrictBeyondDenyList: switches Flags never produces, or
// produces only on another OS, or with a weakened value, are refused too.
func TestCheckFlags_StrictBeyondDenyList(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, goos, extra string
	}{
		{"unknown switch", "linux", "--enable-automation"},
		{"pipe on windows", "windows", "--remote-debugging-pipe"},
		{"mock keychain on linux", "linux", "--use-mock-keychain"},
		{"password store on darwin", "darwin", "--password-store=basic"},
		{"webrtc policy weakened", "linux", "--force-webrtc-ip-handling-policy=default"},
		{"triple dash", "linux", "---no-sandbox"},
		{"empty name", "linux", "--=x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := slices.DeleteFunc(mustFlags(t, opts(tc.goos)), func(a string) bool {
				return a == "--password-store=basic" || a == "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
			})
			if err := browser.CheckFlags(tc.goos, append(args, tc.extra)); !errors.Is(err, browser.ErrForbiddenFlag) {
				t.Errorf("CheckFlags(%s, +%q) = %v, want ErrForbiddenFlag", tc.goos, tc.extra, err)
			}
		})
	}
	for _, args := range [][]string{
		{"--host-resolver-rules="},
		{"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE"},
		{"--user-data-dir="},
		{"--password-store=gnome-libsecret"},
	} {
		if err := browser.CheckFlags("linux", args); !errors.Is(err, browser.ErrForbiddenFlag) {
			t.Errorf("CheckFlags(linux, %q) = %v, want ErrForbiddenFlag", args, err)
		}
	}
	if err := browser.CheckFlags("plan9", nil); !errors.Is(err, browser.ErrUnsupportedOS) {
		t.Errorf("CheckFlags(plan9) = %v, want ErrUnsupportedOS", err)
	}
}

func TestFlags_WindowsProfileSyntax(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{`C:\`, `C:\a\b`} {
		o := opts("windows")
		o.ProfileDir = dir
		if _, err := browser.Flags(o); err != nil {
			t.Errorf("Flags(ProfileDir=%q) = %v, want nil", dir, err)
		}
	}
	for _, dir := range []string{`C:\a\..\b`, `C:\a\.\b`, `C:\a\\b`, `C:\a\`, `C:\a/b`, `C:\a:s`, `1:\a`} {
		o := opts("windows")
		o.ProfileDir = dir
		if _, err := browser.Flags(o); !errors.Is(err, browser.ErrNoProfileDir) {
			t.Errorf("Flags(ProfileDir=%q) = %v, want ErrNoProfileDir", dir, err)
		}
	}
}

func TestFlags_DomainCharsetAndNumericHosts(t *testing.T) {
	t.Parallel()
	for _, d := range []string{"0x7f.0.0.1", "login.supplier.123", "-a.supplier.example", "a_b.supplier.example"} {
		o := opts("linux")
		o.AllowedDomains = []string{d}
		if _, err := browser.Flags(o); !errors.Is(err, browser.ErrInvalidDomain) {
			t.Errorf("Flags(AllowedDomains=%q) = %v, want ErrInvalidDomain", d, err)
		}
	}
}

func TestLaunch_NilDependenciesFailClosed(t *testing.T) {
	t.Parallel()
	if got := browser.BuildEnv(nil); len(got) != 0 {
		t.Errorf("BuildEnv(nil) = %q, want empty", got)
	}
	if browser.ProxyAllowed(nil) {
		t.Error("ProxyAllowed(nil) = true, want false")
	}
	h := testHost(t, nil)
	if err := browser.Launch(context.Background(), h, launchOpts(t), nil); !errors.Is(err, browser.ErrLaunchFailed) {
		t.Errorf("Launch(nil start) = %v, want ErrLaunchFailed", err)
	}
	// A nil logger discards the summary instead of panicking.
	h.Log = nil
	spy := &startSpy{run: func(browser.Command) error { return errors.New("exit status 3") }}
	if err := browser.Launch(context.Background(), h, launchOpts(t), spy.start); !errors.Is(err, browser.ErrLaunchFailed) {
		t.Errorf("Launch(nil log) = %v, want ErrLaunchFailed", err)
	}
	bad := launchOpts(t)
	bad.ProfileDir = ""
	if err := browser.Launch(context.Background(), testHost(t, nil), bad, spy.start); !errors.Is(err, browser.ErrNoProfileDir) {
		t.Errorf("Launch(no profile) = %v, want ErrNoProfileDir", err)
	}
}
