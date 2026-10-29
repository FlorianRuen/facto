package browser

import (
	"fmt"
	"net/netip"
	"path"
	"runtime"
	"slices"
	"strings"

	"github.com/FlorianRuen/facto/internal/httpx"
)

// Options is the release launch configuration (built by the pool from
// connector.LaunchOptions). There is no extra-args channel and no test-only
// knob: the e2e build adds its own through FlagsE2E.
type Options struct {
	GOOS           string   // target OS for the flags; "" means runtime.GOOS
	ProfileDir     string   // disposable profile (A12), absolute and clean; required
	AllowedDomains []string // connector Info().AllowedDomains (A11)
	Visible        bool     // headful window; otherwise --headless=new
	AllowProxy     bool     // true only when FACTO_ALLOW_PROXY is exactly "1"
}

const (
	goosLinux   = "linux"
	goosDarwin  = "darwin"
	goosWindows = "windows"
)

// resolveGOOS maps "" to runtime.GOOS and refuses any OS facto does not
// launch Chrome on. The comparison is exact ("Linux" is refused).
func resolveGOOS(goos string) (string, error) {
	if goos == "" {
		goos = runtime.GOOS
	}
	switch goos {
	case goosLinux, goosDarwin, goosWindows:
		return goos, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedOS, goos)
	}
}

// baseFlags are passed on every OS. Each one turns off a feature that would
// talk to Google, store data or offer to save a password.
var baseFlags = []string{
	"--disable-background-networking",
	"--disable-breakpad",
	"--disable-component-update",
	"--disable-crash-reporter",
	"--disable-default-apps",
	"--disable-domain-reliability",
	"--disable-extensions",
	"--disable-save-password-bubble",
	"--disable-sync",
	"--dns-prefetch-disable",
	"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
	"--no-default-browser-check",
	"--no-first-run",
	"--no-pings",
}

// Flags returns Chrome's argv (without the executable, without a URL). The
// result always passes CheckFlags(opts.GOOS, ...).
func Flags(opts Options) ([]string, error) {
	goos, err := resolveGOOS(opts.GOOS)
	if err != nil {
		return nil, err
	}
	if err := checkProfileDir(goos, opts.ProfileDir); err != nil {
		return nil, err
	}
	domains, err := normalizeDomains(opts.AllowedDomains)
	if err != nil {
		return nil, err
	}
	args := slices.Clone(baseFlags)
	args = append(args,
		"--user-data-dir="+opts.ProfileDir,
		"--host-resolver-rules="+resolverRules(nil, domains),
	)
	if !opts.Visible {
		args = append(args, "--headless=new")
	}
	if !opts.AllowProxy {
		args = append(args, "--no-proxy-server")
	}
	switch goos {
	case goosLinux:
		// No desktop keyring: the profile is disposable and holds no
		// saved password anyway.
		args = append(args, "--remote-debugging-pipe", "--password-store=basic")
	case goosDarwin:
		args = append(args, "--remote-debugging-pipe", "--use-mock-keychain")
	case goosWindows:
		// ADR 0008 "Windows (A4)": no ExtraFiles, so a random loopback port.
		args = append(args, "--remote-debugging-port=0")
	}
	if err := CheckFlags(goos, args); err != nil {
		return nil, fmt.Errorf("browser: internal flag set refused: %w", err)
	}
	return args, nil
}

// resolverRules builds the --host-resolver-rules value: every host maps to
// ~NOTFOUND except the allowlist. Chrome checks EXCLUDE rules before any
// MAP rule, so extra (e2e) MAP rules must not be excluded too.
func resolverRules(extra []string, domains []string) string {
	rules := slices.Clone(extra)
	rules = append(rules, "MAP * ~NOTFOUND")
	for _, d := range domains {
		rules = append(rules, "EXCLUDE "+d)
	}
	return strings.Join(rules, ", ")
}

// checkProfileDir requires an absolute, clean path without control
// characters, in the syntax of goos.
func checkProfileDir(goos, dir string) error {
	if dir == "" {
		return fmt.Errorf("%w: empty", ErrNoProfileDir)
	}
	if hasControl(dir) {
		return fmt.Errorf("%w: control character", ErrNoProfileDir)
	}
	ok := false
	if goos == goosWindows {
		ok = cleanWindowsAbs(dir)
	} else {
		ok = path.IsAbs(dir) && path.Clean(dir) == dir
	}
	if !ok {
		return fmt.Errorf("%w: not an absolute clean path", ErrNoProfileDir)
	}
	return nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// cleanWindowsAbs accepts `X:\a\b`: a drive letter, a backslash, then
// non-empty segments other than "." and "..", without '/' or another ':'.
func cleanWindowsAbs(p string) bool {
	if len(p) < 3 || !isASCIILetter(p[0]) || p[1] != ':' || p[2] != '\\' {
		return false
	}
	rest := p[3:]
	if rest == "" {
		return true
	}
	if strings.ContainsAny(rest, `/:`) {
		return false
	}
	for seg := range strings.SplitSeq(rest, `\`) {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func isASCIILetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// normalizeDomains validates AllowedDomains with httpx.ParseAllowlist (the
// single source of truth for host patterns) plus the stricter rules a
// Chrome flag value needs, and returns them lowercased, sorted and
// deduplicated so the flags do not depend on the input order or case.
func normalizeDomains(domains []string) ([]string, error) {
	if _, err := httpx.ParseAllowlist(domains); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDomain, err)
	}
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(d)
		if err := checkFlagDomain(d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// checkFlagDomain applies the rules on top of httpx.ParseAllowlist: only
// [a-z0-9-] labels (no ',', ';', '=', space…), no IP literal or
// numeric-looking host, no loopback name. d is lowercase.
func checkFlagDomain(d string) error {
	host := strings.TrimPrefix(d, "*.")
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if l == "" || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%w: %q", ErrInvalidDomain, d)
		}
		for i := range len(l) {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("%w: %q", ErrInvalidDomain, d)
			}
		}
	}
	// Chrome parses "127.1" or "0x7f.0.0.1" as IPv4: a host whose last
	// label does not start with a letter is never a name.
	if _, err := netip.ParseAddr(host); err == nil || !isASCIILetter(labels[len(labels)-1][0]) {
		return fmt.Errorf("%w: %q is an IP literal", ErrInvalidDomain, d)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("%w: %q is a loopback name", ErrInvalidDomain, d)
	}
	return nil
}
