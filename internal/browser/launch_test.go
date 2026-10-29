package browser_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

const canaryEnv = "FACTO_TEST_CANARY_ENV"

// mapLookup is an os.LookupEnv double over a fixed map: no process
// environment is read or changed, so tests stay parallel.
func mapLookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func envKeys(t *testing.T, env []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			t.Errorf("malformed env entry %q", kv)
			continue
		}
		if _, dup := out[k]; dup {
			t.Errorf("duplicate env key %q", k)
		}
		out[k] = v
	}
	return out
}

// proxyVars are every proxy variable Chrome, curl-style tools or Go honour.
var proxyVars = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy",
	"auto_proxy", "SOCKS_SERVER", "SOCKS_VERSION", "SOCKS_PROXY", "socks_proxy",
}

func TestLaunch_EnvAllowlisted(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Token)
	host := map[string]string{
		// Allowed, non-secret.
		"HOME": "/facto-test/home", "LANG": "C.UTF-8", "TZ": "UTC",
		"TMPDIR": "/facto-test/tmp", "XDG_RUNTIME_DIR": "/facto-test/run",
		"DISPLAY": ":99",
		// Never passed.
		canaryEnv:                      canary,
		"SSLKEYLOGFILE":                "/facto-test/keys.log",
		"LD_PRELOAD":                   "/facto-test/evil.so",
		"LD_LIBRARY_PATH":              "/facto-test/lib",
		"DYLD_INSERT_LIBRARIES":        "/facto-test/evil.dylib",
		"DYLD_LIBRARY_PATH":            "/facto-test/lib",
		"GOOGLE_API_KEY":               canary,
		"GOOGLE_DEFAULT_CLIENT_ID":     canary,
		"GOOGLE_DEFAULT_CLIENT_SECRET": canary,
		"CHROME_LOG_FILE":              "/facto-test/chrome.log",
		"NODE_OPTIONS":                 "--require=/facto-test/x.js",
		"SSL_CERT_FILE":                "/facto-test/ca.pem",
		"FACTO_ALLOW_PROXY":            "1",
		"BITWARDENCLI_APPDATA_DIR":     "/facto-test/bw",
	}
	env := browser.BuildEnv(mapLookup(host))
	got := envKeys(t, env)

	for _, k := range []string{"HOME", "LANG", "TZ", "TMPDIR", "XDG_RUNTIME_DIR", "DISPLAY"} {
		if got[k] != host[k] {
			t.Errorf("%s = %q, want %q passed through", k, got[k], host[k])
		}
	}
	for k := range host {
		switch k {
		case "HOME", "LANG", "TZ", "TMPDIR", "XDG_RUNTIME_DIR", "DISPLAY":
			continue
		}
		if _, ok := got[k]; ok {
			t.Errorf("%s passed to Chrome", k)
		}
	}
	for _, kv := range env {
		if strings.Contains(kv, canary) {
			t.Errorf("canary value reached Chrome's environment in %q", kv)
		}
	}
	// A variable the allowlist does not know is dropped even with a
	// harmless value.
	if _, ok := envKeys(t, browser.BuildEnv(mapLookup(map[string]string{"FACTO_TEST_UNKNOWN": "x"})))["FACTO_TEST_UNKNOWN"]; ok {
		t.Error("unknown variable passed to Chrome")
	}
}

func TestLaunch_ProxyEnvNotPassed(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Token)
	for _, allow := range []string{"", "1"} {
		host := map[string]string{"HOME": "/facto-test/home"}
		if allow != "" {
			host["FACTO_ALLOW_PROXY"] = allow
		}
		for _, k := range proxyVars {
			host[k] = "http://user:" + canary + "@proxy.example:3128"
		}
		env := browser.BuildEnv(mapLookup(host))
		got := envKeys(t, env)
		for _, k := range proxyVars {
			if _, ok := got[k]; ok {
				t.Errorf("FACTO_ALLOW_PROXY=%q: %s passed to Chrome", allow, k)
			}
		}
		if strings.Contains(strings.Join(env, "\n"), canary) {
			t.Errorf("FACTO_ALLOW_PROXY=%q: proxy credentials reached Chrome's environment", allow)
		}
	}
}

// fakeExecutable returns a private executable file for Prepare/Launch.
func fakeExecutable(t *testing.T) string {
	t.Helper()
	p := writeTestFile(t, t.TempDir(), "chrome", []byte("#!/bin/sh\nexit 0\n"))
	setMode(t, p, exeMode)
	return p
}

func launchOpts(t *testing.T) browser.Options {
	t.Helper()
	return browser.Options{GOOS: runtime.GOOS, ProfileDir: t.TempDir(), AllowedDomains: testDomains}
}

func testHost(t *testing.T, log *slog.Logger) browser.Host {
	t.Helper()
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return browser.Host{
		Executable: fakeExecutable(t),
		Geteuid:    func() int { return 1000 },
		LookupEnv:  mapLookup(map[string]string{"HOME": "/facto-test/home", "HTTPS_PROXY": "http://proxy.example:3128"}),
		Log:        log,
	}
}

type startSpy struct {
	mu    sync.Mutex
	calls []browser.Command
	run   func(cmd browser.Command) error
}

func (s *startSpy) start(_ context.Context, cmd browser.Command) error {
	s.mu.Lock()
	s.calls = append(s.calls, cmd)
	s.mu.Unlock()
	if s.run == nil {
		return nil
	}
	return s.run(cmd)
}

func TestLaunch_PrepareBuildsVettedCommand(t *testing.T) {
	t.Parallel()
	h := testHost(t, nil)
	o := launchOpts(t)
	cmd, err := browser.Prepare(h, o)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if cmd.Path != h.Executable {
		t.Errorf("Path = %q, want %q", cmd.Path, h.Executable)
	}
	if want := mustFlags(t, o); !slices.Equal(cmd.Args, want) {
		t.Errorf("Args = %q, want Flags() = %q", cmd.Args, want)
	}
	if want := browser.BuildEnv(h.LookupEnv); !slices.Equal(cmd.Env, want) {
		t.Errorf("Env = %q, want BuildEnv() = %q", cmd.Env, want)
	}
	if err := browser.CheckFlags(o.GOOS, cmd.Args); err != nil {
		t.Errorf("Prepare produced argv refused by CheckFlags: %v", err)
	}

	bad := h
	bad.Executable = "chrome"
	if _, err := browser.Prepare(bad, o); !errors.Is(err, browser.ErrUnsafeExecutable) {
		t.Errorf("Prepare(relative executable) = %v, want ErrUnsafeExecutable", err)
	}
}

func TestLaunch_RootRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		geteuid func() int
		wantErr bool
	}{
		{"root", func() int { return 0 }, true},
		{"no euid function fails closed", nil, true},
		{"regular user", func() int { return 1000 }, false},
		{"windows (no euid)", func() int { return -1 }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := testHost(t, nil)
			h.Geteuid = tc.geteuid
			_, perr := browser.Prepare(h, launchOpts(t))
			spy := &startSpy{}
			lerr := browser.Launch(context.Background(), h, launchOpts(t), spy.start)
			if tc.wantErr {
				if !errors.Is(perr, browser.ErrRunAsRoot) {
					t.Errorf("Prepare = %v, want ErrRunAsRoot", perr)
				}
				if !errors.Is(lerr, browser.ErrRunAsRoot) {
					t.Errorf("Launch = %v, want ErrRunAsRoot", lerr)
				}
				if len(spy.calls) != 0 {
					t.Errorf("Chrome started %d times as root", len(spy.calls))
				}
				return
			}
			if perr != nil || lerr != nil {
				t.Errorf("Prepare = %v, Launch = %v; want nil", perr, lerr)
			}
			if len(spy.calls) != 1 {
				t.Errorf("start called %d times, want 1", len(spy.calls))
			}
		})
	}
}

// Typical Chrome output on Ubuntu 24.04 when AppArmor restricts unprivileged
// user namespaces (synthetic PIDs).
const noSandboxStderr = "[4242:4242:0101/000000.000000:FATAL:zygote_host_impl_linux.cc(128)] " +
	"No usable sandbox! If you are running on Ubuntu 23.10+ or another Linux distro that has " +
	"disabled unprivileged user namespaces with AppArmor, see https://chromium.googlesource.com/x\n"

func TestLaunch_NoUsableSandboxFailsClosed(t *testing.T) {
	t.Parallel()
	exitErr := errors.New("exit status 1")
	tests := []struct {
		name   string
		chunks []string
	}{
		{"one write", []string{noSandboxStderr}},
		{"split across writes", []string{noSandboxStderr[:110], noSandboxStderr[110:118], noSandboxStderr[118:]}},
		{"after other output", []string{"[1:1:INFO:x.cc(1)] synthetic line\n", noSandboxStderr}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			spy := &startSpy{run: func(cmd browser.Command) error {
				if cmd.Stderr == nil {
					t.Fatal("Launch gave start a nil Stderr")
				}
				for _, c := range tc.chunks {
					if _, err := io.WriteString(cmd.Stderr, c); err != nil {
						t.Fatalf("stderr write: %v", err)
					}
				}
				return exitErr
			}}
			o := launchOpts(t)
			err := browser.Launch(context.Background(), testHost(t, nil), o, spy.start)
			if !errors.Is(err, browser.ErrNoUsableSandbox) {
				t.Fatalf("Launch = %v, want ErrNoUsableSandbox", err)
			}
			if len(spy.calls) != 1 {
				t.Fatalf("start called %d times, want exactly 1 (never retried with weaker flags)", len(spy.calls))
			}
			for _, c := range spy.calls {
				if cerr := browser.CheckFlags(o.GOOS, c.Args); cerr != nil {
					t.Errorf("attempt used refused flags: %v", cerr)
				}
			}
			msg := err.Error()
			for _, want := range []string{"AppArmor", "chrome_sandbox"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not name the fix %q", msg, want)
				}
			}
			for _, leaked := range []string{"zygote_host_impl_linux", "4242", "chromium.googlesource.com"} {
				if strings.Contains(msg, leaked) {
					t.Errorf("error echoes Chrome stderr (%q): %q", leaked, msg)
				}
			}
		})
	}

	// Another failure is not misreported as a sandbox problem.
	other := errors.New("exit status 2")
	spy := &startSpy{run: func(cmd browser.Command) error {
		_, _ = io.WriteString(cmd.Stderr, "[1:1:ERROR:x.cc(1)] synthetic failure\n")
		return other
	}}
	err := browser.Launch(context.Background(), testHost(t, nil), launchOpts(t), spy.start)
	if errors.Is(err, browser.ErrNoUsableSandbox) || !errors.Is(err, browser.ErrLaunchFailed) || !errors.Is(err, other) {
		t.Errorf("Launch(other failure) = %v, want ErrLaunchFailed wrapping the start error", err)
	}
}

func TestLaunch_StderrNotLoggedVerbatim(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Cookie)
	// A plain handler, not the redacting one: the test proves Launch never
	// hands stderr to the logger, not that logx would mask it.
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	big := strings.Repeat("synthetic chrome noise line\n", (browser.MaxStderrBytes/28)*4)
	spy := &startSpy{run: func(cmd browser.Command) error {
		for _, chunk := range []string{
			"[7:7:ERROR:net.cc(9)] request to https://login.supplier.example/cb?session=" + canary + "\n",
			noSandboxStderr,
			big,
			"tail " + canary + "\n",
		} {
			n, err := io.WriteString(cmd.Stderr, chunk)
			// Past the cap the writer keeps draining: Chrome must never
			// block on a full stderr pipe.
			if err != nil || n != len(chunk) {
				t.Errorf("stderr write = %d, %v; want %d, nil", n, err, len(chunk))
			}
		}
		return errors.New("exit status 1")
	}}
	err := browser.Launch(context.Background(), testHost(t, log), launchOpts(t), spy.start)
	if err == nil {
		t.Fatal("Launch succeeded, want an error")
	}

	// Left for `make leakcheck`, which greps it for the canary.
	writeTestFile(t, testsecrets.ArtifactDir(t), "launch.log", append(logs.Bytes(), []byte(err.Error())...))
	for _, out := range []string{logs.String(), err.Error()} {
		for _, leaked := range []string{canary, "login.supplier.example/cb", "synthetic chrome noise", "zygote_host_impl_linux"} {
			if strings.Contains(out, leaked) {
				t.Errorf("Chrome stderr content %q reached logs or error: %q", leaked, out)
			}
		}
	}
	if logs.Len() == 0 {
		t.Error("launch failure not logged at all; want a summary (byte count, classification)")
	}
	if len(logs.String()) > 4096 {
		t.Errorf("launch failure log is %d bytes, want a short summary", logs.Len())
	}
}
