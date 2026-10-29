// Tests for J1 task T6 (feat(browser): launch flags and executable checks),
// ADR 0008 "Hardening" and "Windows (A4)", plan decisions A4, A11, A12.
//
// Expected API of package internal/browser (written before the
// implementation; the tests below are the contract):
//
//	// Sentinel errors (errors.Is targets).
//	var (
//		ErrForbiddenFlag    error // argv holds a deny-listed, test-only, duplicate or positional argument
//		ErrNoProfileDir     error // Options.ProfileDir empty, relative, not clean or with a control character
//		ErrInvalidDomain    error // AllowedDomains refused (httpx.ParseAllowlist rules, plus IP literals,
//		                          // loopback names, ',' ';' '=' and anything that could alter a flag value)
//		ErrUnsupportedOS    error // Options.GOOS not linux, darwin or windows
//		ErrUnsafeExecutable error // browser executable relative, missing, not a regular executable file,
//		                          // group/world-writable, in a group/world-writable directory, or a
//		                          // symlink resolving to such a place
//		ErrRunAsRoot        error // euid 0, or no euid function (fail closed)
//		ErrNoUsableSandbox  error // Chrome reported "No usable sandbox"; message names the fix outside
//		                          // facto (AppArmor profile, or SUID chrome_sandbox), never retried
//		ErrLaunchFailed     error // any other start failure
//	)
//
//	// Options is the release launch configuration (built by the pool from
//	// connector.LaunchOptions). Its exported fields are exactly these: there
//	// is no extra-args channel and no test-only knob in a release build.
//	type Options struct {
//		GOOS           string   // target OS for the flags; "" means runtime.GOOS
//		ProfileDir     string   // disposable profile (A12), absolute and clean; required
//		AllowedDomains []string // connector Info().AllowedDomains (A11)
//		Visible        bool     // headful window; otherwise --headless=new
//		AllowProxy     bool     // true only when FACTO_ALLOW_PROXY is exactly "1"
//	}
//
//	// Flags returns Chrome's argv (without the executable, without a URL).
//	// The result always passes CheckFlags(opts.GOOS, ...).
//	func Flags(opts Options) ([]string, error)
//
//	// CheckFlags is the release deny-list, run at launch over the final argv.
//	// Switch prefixes "--" and "-" (and "/" for windows) are recognised, names
//	// compare case-insensitively, "=value" is ignored for deny-listed names.
//	// Refuses: the ADR 0008 deny-list, --disable-extensions-except, --vmodule,
//	// --ignore-certificate-errors-spki-list, --host-resolver-rules mapping a
//	// host to a loopback or IP target, --remote-debugging-port outside windows
//	// and any value but "0" on windows, positional arguments and "--", and any
//	// switch given twice.
//	func CheckFlags(goos string, args []string) error
//
//	// ProxyAllowed reports whether FACTO_ALLOW_PROXY is exactly "1".
//	func ProxyAllowed(lookup func(string) (string, bool)) bool
//
//	// CheckExecutable vets the browser binary. path must be absolute; it is
//	// resolved through every symlink (dangling refused), and the target must
//	// be a regular file, executable by its owner, without setuid/setgid,
//	// not group/world-writable, in a parent directory that is not
//	// group/world-writable (sticky or not). Higher ancestors may be
//	// world-writable only with the sticky bit (/tmp). Unix only for modes;
//	// on windows only absoluteness and regular-file checks apply.
//	func CheckExecutable(path string) error
//
//	// BuildEnv returns Chrome's environment ("K=V"), built like inherited()
//	// in internal/secret/bitwarden/exec.go: a fixed allowlist of non-secret
//	// variables, proxy variables never, whatever FACTO_ALLOW_PROXY says.
//	func BuildEnv(lookup func(string) (string, bool)) []string
//
//	// Host is what Prepare/Launch read from the machine, injected.
//	type Host struct {
//		Executable string
//		Geteuid    func() int // os.Geteuid in production; -1 on windows
//		LookupEnv  func(string) (string, bool)
//		Log        *slog.Logger
//	}
//
//	// Command is one vetted Chrome invocation.
//	type Command struct {
//		Path   string
//		Args   []string
//		Env    []string
//		Stderr io.Writer // set by Launch: capped at MaxStderrBytes, never logged verbatim
//	}
//
//	// StartFunc starts Chrome (exec + transport in T7). It must write
//	// Chrome's stderr to cmd.Stderr.
//	type StartFunc func(ctx context.Context, cmd Command) error
//
//	const MaxStderrBytes = 64 << 10
//
//	// Prepare: root check first, then CheckExecutable, Flags, CheckFlags,
//	// BuildEnv. Returns a Command with a nil Stderr.
//	func Prepare(h Host, opts Options) (Command, error)
//
//	// Launch: Prepare, then start exactly once. On failure the stderr is
//	// classified (ErrNoUsableSandbox / ErrLaunchFailed, wrapping start's
//	// error); only a summary (byte count, classification) is logged.
//	func Launch(ctx context.Context, h Host, opts Options, start StartFunc) error
//
//	// e2e build only (//go:build e2e), see TestFlags_TestOnlyFlagsUnreachableFromReleaseOptions:
//	type E2EOverrides struct {
//		LoopbackHosts []string // mapped to 127.0.0.1 in --host-resolver-rules
//		TestCASPKI    []string // --ignore-certificate-errors-spki-list
//	}
//	func FlagsE2E(opts Options, o E2EOverrides) ([]string, error)
//
// Golden files: testdata/TestFlags_Golden/<case>.golden, one flag per line,
// sorted (byte order); flag order is not part of the contract. Regenerate
// with `go test ./internal/browser -run TestFlags_Golden -update` and review
// the diff. --disable-save-password-bubble and --password-store=basic are
// unverified against real Chrome until T13.
package browser_test

import (
	"errors"
	"flag"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Synthetic, reserved-TLD allowlist used across the flag tests.
var testDomains = []string{"login.supplier.example", "*.cdn.supplier.example"}

const (
	unixProfile    = "/facto-test/profile"
	windowsProfile = `C:\facto-test\profile`
)

func opts(goos string) browser.Options {
	p := unixProfile
	if goos == "windows" {
		p = windowsProfile
	}
	return browser.Options{GOOS: goos, ProfileDir: p, AllowedDomains: testDomains}
}

func mustFlags(t *testing.T, o browser.Options) []string {
	t.Helper()
	got, err := browser.Flags(o)
	if err != nil {
		t.Fatalf("Flags(%+v): %v", o, err)
	}
	return got
}

// allOptionVariants covers every OS and every boolean combination.
func allOptionVariants() []browser.Options {
	var out []browser.Options
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, visible := range []bool{false, true} {
			for _, proxy := range []bool{false, true} {
				o := opts(goos)
				o.Visible, o.AllowProxy = visible, proxy
				out = append(out, o)
			}
		}
	}
	return out
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

func TestFlags_Golden(t *testing.T) {
	t.Parallel()
	visible := opts("linux")
	visible.Visible = true
	proxy := opts("linux")
	proxy.AllowProxy = true
	tests := []struct {
		name string
		in   browser.Options
	}{
		{"linux", opts("linux")},
		{"darwin", opts("darwin")},
		{"windows", opts("windows")},
		{"linux-visible", visible},
		{"linux-allow-proxy", proxy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := mustFlags(t, tc.in)
			sorted := slices.Clone(got)
			slices.Sort(sorted)
			if c := slices.Compact(slices.Clone(sorted)); len(c) != len(sorted) {
				t.Errorf("duplicate flags in %q", got)
			}
			path := filepath.Join("testdata", "TestFlags_Golden", tc.name+".golden")
			checkGolden(t, path, []byte(strings.Join(sorted, "\n")+"\n"))
			if err := browser.CheckFlags(tc.in.GOOS, got); err != nil {
				t.Errorf("Flags output refused by CheckFlags: %v", err)
			}
		})
	}
}

// TestFlags_GoldenProperties restates the security-relevant parts of the
// golden files as assertions, so a careless -update cannot drop them.
func TestFlags_GoldenProperties(t *testing.T) {
	t.Parallel()
	for _, o := range allOptionVariants() {
		got := mustFlags(t, o)
		name := o.GOOS
		if !slices.Contains(got, "--user-data-dir="+o.ProfileDir) {
			t.Errorf("%s: --user-data-dir=%s missing in %q", name, o.ProfileDir, got)
		}
		if hasFlag(got, "--headless") != !o.Visible || (!o.Visible && !slices.Contains(got, "--headless=new")) {
			t.Errorf("%s visible=%v: headless flag wrong in %q", name, o.Visible, got)
		}
		for _, f := range []string{
			"--disable-extensions", "--disable-sync", "--disable-breakpad",
			"--disable-crash-reporter", "--disable-save-password-bubble",
			"--dns-prefetch-disable",
			"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
			"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE *.cdn.supplier.example, EXCLUDE login.supplier.example",
		} {
			if !slices.Contains(got, f) {
				t.Errorf("%s: %s missing in %q", name, f, got)
			}
		}
		if hasFlag(got, "--load-extension") || hasFlag(got, "--enable-logging") {
			t.Errorf("%s: extension or logging flag in %q", name, got)
		}
	}
}

func TestFlags_Deterministic(t *testing.T) {
	t.Parallel()
	a := opts("linux")
	b := opts("linux")
	b.AllowedDomains = []string{"*.cdn.supplier.example", "LOGIN.supplier.example", "login.supplier.example"}
	if ga, gb := mustFlags(t, a), mustFlags(t, b); !slices.Equal(ga, gb) {
		t.Errorf("same allowlist in another order or case gives other flags:\n%q\n%q", ga, gb)
	}
}

func TestFlags_NoDebugPortOutsideWindows(t *testing.T) {
	t.Parallel()
	for _, o := range allOptionVariants() {
		if o.GOOS == "windows" {
			continue
		}
		got := mustFlags(t, o)
		if !slices.Contains(got, "--remote-debugging-pipe") {
			t.Errorf("%s: --remote-debugging-pipe missing in %q", o.GOOS, got)
		}
		for _, a := range got {
			if strings.Contains(a, "remote-debugging-port") {
				t.Errorf("%s: debug port flag %q", o.GOOS, a)
			}
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		for _, f := range []string{"--remote-debugging-port=0", "--remote-debugging-port=9222", "-remote-debugging-port=0"} {
			if err := browser.CheckFlags(goos, append(mustFlags(t, opts(goos)), f)); !errors.Is(err, browser.ErrForbiddenFlag) {
				t.Errorf("CheckFlags(%s, +%s) = %v, want ErrForbiddenFlag", goos, f, err)
			}
		}
	}
}

func TestFlags_WindowsPortIsZeroOnly(t *testing.T) {
	t.Parallel()
	for _, o := range allOptionVariants() {
		if o.GOOS != "windows" {
			continue
		}
		got := mustFlags(t, o)
		n := 0
		for _, a := range got {
			if strings.Contains(a, "remote-debugging-port") {
				n++
				if a != "--remote-debugging-port=0" {
					t.Errorf("windows: debug port flag %q, want --remote-debugging-port=0", a)
				}
			}
		}
		if n != 1 {
			t.Errorf("windows: %d debug port flags in %q, want 1", n, got)
		}
		if slices.Contains(got, "--remote-debugging-pipe") {
			t.Errorf("windows: pipe flag without ExtraFiles support in %q", got)
		}
	}

	base := []string{"--user-data-dir=" + windowsProfile}
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"zero", append(slices.Clone(base), "--remote-debugging-port=0"), false},
		{"fixed port", append(slices.Clone(base), "--remote-debugging-port=9222"), true},
		{"zero padded", append(slices.Clone(base), "--remote-debugging-port=00"), true},
		{"empty", append(slices.Clone(base), "--remote-debugging-port="), true},
		{"bare", append(slices.Clone(base), "--remote-debugging-port"), true},
		{"negative", append(slices.Clone(base), "--remote-debugging-port=-1"), true},
		{"twice", append(slices.Clone(base), "--remote-debugging-port=0", "--remote-debugging-port=9222"), true},
		{"slash prefix", append(slices.Clone(base), "--remote-debugging-port=0", "/remote-debugging-port=9222"), true},
		{"upper case", append(slices.Clone(base), "--REMOTE-DEBUGGING-PORT=9222"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := browser.CheckFlags("windows", tc.args)
			if tc.wantErr && !errors.Is(err, browser.ErrForbiddenFlag) {
				t.Errorf("CheckFlags(windows, %q) = %v, want ErrForbiddenFlag", tc.args, err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("CheckFlags(windows, %q) = %v, want nil", tc.args, err)
			}
		})
	}
}

func TestFlags_RequireProfileDir(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, goos, dir string
	}{
		{"empty linux", "linux", ""},
		{"empty darwin", "darwin", ""},
		{"empty windows", "windows", ""},
		{"relative", "linux", "profile"},
		{"dot relative", "linux", "./profile"},
		{"not clean", "linux", "/facto-test/../profile"},
		{"trailing newline", "linux", "/facto-test/profile\n--no-sandbox"},
		{"control character", "linux", "/facto-test/pro\x00file"},
		{"windows relative", "windows", `profile`},
		{"windows drive relative", "windows", `C:profile`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := opts(tc.goos)
			o.ProfileDir = tc.dir
			got, err := browser.Flags(o)
			if !errors.Is(err, browser.ErrNoProfileDir) {
				t.Errorf("Flags(ProfileDir=%q) = %q, %v; want ErrNoProfileDir", tc.dir, got, err)
			}
		})
	}
}

func TestFlags_UnsupportedOSRefused(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"plan9", "js", "freebsd", "Linux"} {
		o := opts("linux")
		o.GOOS = goos
		if _, err := browser.Flags(o); !errors.Is(err, browser.ErrUnsupportedOS) {
			t.Errorf("Flags(GOOS=%q) = %v, want ErrUnsupportedOS", goos, err)
		}
	}
}

// denyList is every flag of ADR 0008 "Hardening, Launch flags", plus the
// switches that are equivalent to one of them.
var denyList = []string{
	"--no-sandbox",
	"--disable-setuid-sandbox",
	"--disable-namespace-sandbox",
	"--disable-seccomp-filter-sandbox",
	"--disable-gpu-sandbox",
	"--no-zygote",
	"--single-process",
	"--disable-web-security",
	"--ignore-certificate-errors",
	"--allow-running-insecure-content",
	"--remote-allow-origins=*",
	"--remote-debugging-address=0.0.0.0",
	"--load-extension=/facto-test/ext",
	"--enable-logging=stderr",
	"--v=1",
	// Equivalents.
	"--disable-extensions-except=/facto-test/ext",
	"--vmodule=*=1",
	"--ignore-certificate-errors-spki-list=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
}

// variants spells one switch every way Chrome may accept it.
func variants(goos, flagArg string) []string {
	name := strings.TrimPrefix(flagArg, "--")
	out := []string{
		"--" + name,
		"-" + name,
		"--" + strings.ToUpper(name),
	}
	if base, _, ok := strings.Cut(name, "="); ok {
		out = append(out, "--"+base, "--"+base+"=")
	} else {
		out = append(out, "--"+name+"=1", "--"+name+"=true")
	}
	if goos == "windows" {
		out = append(out, "/"+name)
	}
	return out
}

func TestFlags_NeverSandboxWeakening(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin", "windows"} {
		release := mustFlags(t, opts(goos))
		for _, d := range denyList {
			for _, v := range variants(goos, d) {
				t.Run(goos+"/"+v, func(t *testing.T) {
					t.Parallel()
					// Appended as an extra argument after a valid argv.
					args := append(slices.Clone(release), v)
					if err := browser.CheckFlags(goos, args); !errors.Is(err, browser.ErrForbiddenFlag) {
						t.Errorf("CheckFlags(%s, release+%q) = %v, want ErrForbiddenFlag", goos, v, err)
					}
					// Alone, and first.
					if err := browser.CheckFlags(goos, append([]string{v}, release...)); !errors.Is(err, browser.ErrForbiddenFlag) {
						t.Errorf("CheckFlags(%s, %q+release) = %v, want ErrForbiddenFlag", goos, v, err)
					}
				})
			}
		}
	}

	// No option combination ever produces a deny-listed switch.
	for _, o := range allOptionVariants() {
		for _, a := range mustFlags(t, o) {
			for _, d := range denyList {
				base, _, _ := strings.Cut(d, "=")
				if a == base || strings.HasPrefix(a, base+"=") {
					t.Errorf("%s visible=%v proxy=%v: Flags produced %q", o.GOOS, o.Visible, o.AllowProxy, a)
				}
			}
		}
	}
}

// TestFlags_ExtraArgumentsRefused covers the generic argv rules that keep a
// deny-listed behaviour from coming back through another door.
func TestFlags_ExtraArgumentsRefused(t *testing.T) {
	t.Parallel()
	release := mustFlags(t, opts("linux"))
	tests := []struct {
		name  string
		extra []string
	}{
		{"positional url", []string{"https://other.example/"}},
		{"end of switches", []string{"--", "https://other.example/"}},
		{"second profile", []string{"--user-data-dir=/home/someone/.config/google-chrome"}},
		{"second resolver rules", []string{"--host-resolver-rules=MAP * other.example"}},
		{"proxy server", []string{"--proxy-server=http://proxy.example:3128"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := browser.CheckFlags("linux", append(slices.Clone(release), tc.extra...)); !errors.Is(err, browser.ErrForbiddenFlag) {
				t.Errorf("CheckFlags(release+%q) = %v, want ErrForbiddenFlag", tc.extra, err)
			}
		})
	}
}

// TestFlags_AllowedDomainsCannotInjectFlags: AllowedDomains come from
// connector.LaunchOptions and end up inside --host-resolver-rules.
func TestFlags_AllowedDomainsCannotInjectFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		domains []string
	}{
		{"empty list", nil},
		{"flag as domain", []string{"--no-sandbox"}},
		{"space then flag", []string{"login.supplier.example --no-sandbox"}},
		{"newline then flag", []string{"login.supplier.example\n--no-sandbox"}},
		{"comma adds rule", []string{"login.supplier.example,MAP"}},
		{"comma before host", []string{"x.supplier.example,other.example"}},
		{"semicolon", []string{"login.supplier.example;other.example"}},
		{"equals", []string{"login.supplier.example=x"}},
		{"bare star", []string{"*"}},
		{"ipv4 literal", []string{"192.0.2.10"}},
		{"loopback ipv4", []string{"127.0.0.1"}},
		{"loopback name", []string{"localhost"}},
		{"loopback subdomain", []string{"app.localhost"}},
		{"ipv6 literal", []string{"[::1]"}},
		{"port", []string{"login.supplier.example:443"}},
		{"scheme", []string{"https://login.supplier.example"}},
		{"public suffix wildcard", []string{"*.co.uk"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, goos := range []string{"linux", "darwin", "windows"} {
				o := opts(goos)
				o.AllowedDomains = tc.domains
				got, err := browser.Flags(o)
				if !errors.Is(err, browser.ErrInvalidDomain) {
					t.Errorf("Flags(%s, AllowedDomains=%q) = %q, %v; want ErrInvalidDomain", goos, tc.domains, got, err)
				}
			}
		})
	}
}

func TestFlags_NeverRemoteAllowOrigins(t *testing.T) {
	t.Parallel()
	for _, o := range allOptionVariants() {
		for _, a := range mustFlags(t, o) {
			if strings.Contains(strings.ToLower(a), "remote-allow-origins") {
				t.Errorf("%s: Flags produced %q", o.GOOS, a)
			}
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, v := range []string{
			"--remote-allow-origins=*",
			"--remote-allow-origins=http://127.0.0.1",
			"--remote-allow-origins=",
			"--remote-allow-origins",
			"-remote-allow-origins=*",
			"--Remote-Allow-Origins=*",
		} {
			if err := browser.CheckFlags(goos, append(mustFlags(t, opts(goos)), v)); !errors.Is(err, browser.ErrForbiddenFlag) {
				t.Errorf("CheckFlags(%s, +%q) = %v, want ErrForbiddenFlag", goos, v, err)
			}
		}
	}
}

func TestFlags_NeverRemoteDebuggingAddress(t *testing.T) {
	t.Parallel()
	for _, o := range allOptionVariants() {
		for _, a := range mustFlags(t, o) {
			if strings.Contains(strings.ToLower(a), "remote-debugging-address") {
				t.Errorf("%s: Flags produced %q", o.GOOS, a)
			}
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, v := range []string{
			"--remote-debugging-address=0.0.0.0",
			"--remote-debugging-address=127.0.0.1",
			"--remote-debugging-address=::",
			"--remote-debugging-address",
			"-remote-debugging-address=0.0.0.0",
		} {
			if err := browser.CheckFlags(goos, append(mustFlags(t, opts(goos)), v)); !errors.Is(err, browser.ErrForbiddenFlag) {
				t.Errorf("CheckFlags(%s, +%q) = %v, want ErrForbiddenFlag", goos, v, err)
			}
		}
	}
}

func TestFlags_NoProxyServerUnlessAllowed(t *testing.T) {
	t.Parallel()
	for _, o := range allOptionVariants() {
		got := mustFlags(t, o)
		if has := slices.Contains(got, "--no-proxy-server"); has == o.AllowProxy {
			t.Errorf("%s AllowProxy=%v: --no-proxy-server present=%v in %q", o.GOOS, o.AllowProxy, has, got)
		}
		for _, a := range got {
			if strings.HasPrefix(a, "--proxy-") {
				t.Errorf("%s: facto never chooses a proxy itself, got %q", o.GOOS, a)
			}
		}
	}

	tests := []struct {
		name  string
		value string
		set   bool
		want  bool
	}{
		{"unset", "", false, false},
		{"empty", "", true, false},
		{"one", "1", true, true},
		{"zero", "0", true, false},
		{"true", "true", true, false},
		{"yes", "yes", true, false},
		{"padded", " 1", true, false},
		{"newline", "1\n", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lookup := func(k string) (string, bool) {
				if k == "FACTO_ALLOW_PROXY" && tc.set {
					return tc.value, true
				}
				return "", false
			}
			if got := browser.ProxyAllowed(lookup); got != tc.want {
				t.Errorf("ProxyAllowed(FACTO_ALLOW_PROXY=%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestFlags_MockKeychainOnDarwin(t *testing.T) {
	t.Parallel()
	for _, o := range allOptionVariants() {
		got := mustFlags(t, o)
		if has := slices.Contains(got, "--use-mock-keychain"); has != (o.GOOS == "darwin") {
			t.Errorf("%s: --use-mock-keychain present=%v in %q", o.GOOS, has, got)
		}
	}
}
