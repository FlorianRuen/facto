package browser

import (
	"fmt"
	"strings"
)

// deniedSwitches is the ADR 0008 "Hardening, Launch flags" deny-list plus
// the switches equivalent to one of them, lowercased, without prefix.
// They are refused whatever their value.
var deniedSwitches = map[string]string{
	"no-sandbox":                          "disables the sandbox",
	"disable-setuid-sandbox":              "disables the sandbox",
	"disable-namespace-sandbox":           "disables the sandbox",
	"disable-seccomp-filter-sandbox":      "disables the sandbox",
	"disable-gpu-sandbox":                 "disables the sandbox",
	"no-zygote":                           "weakens the sandbox",
	"single-process":                      "weakens the sandbox",
	"disable-web-security":                "disables the same-origin policy",
	"ignore-certificate-errors":           "disables TLS verification",
	"ignore-certificate-errors-spki-list": "trusts extra certificates (e2e only)",
	"allow-running-insecure-content":      "allows mixed content",
	"remote-allow-origins":                "opens CDP to web origins",
	"remote-debugging-address":            "binds CDP off loopback",
	"load-extension":                      "loads an extension",
	"disable-extensions-except":           "loads an extension",
	"enable-logging":                      "logs page data",
	"v":                                   "verbose logging",
	"vmodule":                             "verbose logging",
	"proxy-server":                        "facto never chooses a proxy",
	"proxy-pac-url":                       "facto never chooses a proxy",
	"proxy-bypass-list":                   "facto never chooses a proxy",
	"proxy-auto-detect":                   "facto never chooses a proxy",
}

// knownSwitches are the only switches a release launch may carry: Flags'
// own set. Anything else is refused, so a behaviour on the deny-list cannot
// come back under a switch the list does not know. The value says on which
// OS the switch is valid ("" for every OS).
var knownSwitches = map[string]string{
	"disable-background-networking":   "",
	"disable-breakpad":                "",
	"disable-component-update":        "",
	"disable-crash-reporter":          "",
	"disable-default-apps":            "",
	"disable-domain-reliability":      "",
	"disable-extensions":              "",
	"disable-save-password-bubble":    "",
	"disable-sync":                    "",
	"dns-prefetch-disable":            "",
	"force-webrtc-ip-handling-policy": "",
	"headless":                        "",
	"host-resolver-rules":             "",
	"no-default-browser-check":        "",
	"no-first-run":                    "",
	"no-pings":                        "",
	"no-proxy-server":                 "",
	"user-data-dir":                   "",
	"remote-debugging-pipe":           "!" + goosWindows,
	"remote-debugging-port":           goosWindows,
	"password-store":                  goosLinux,
	"use-mock-keychain":               goosDarwin,
}

// CheckFlags is the release check run at launch over the final argv.
// Switch prefixes "--" and "-" (and "/" on windows) are recognised, names
// compare case-insensitively. It refuses the ADR 0008 deny-list and its
// equivalents whatever their value, any switch Flags never produces,
// --host-resolver-rules with anything but "MAP <host> ~NOTFOUND" and
// "EXCLUDE <host>" rules (so no loopback or IP mapping),
// --remote-debugging-port outside windows and any value but "0" on
// windows, positional arguments and "--", and any switch given twice. It
// also refuses an argv missing one of the mandatory isolation switches
// (mandatorySwitches), so the launch-time check stands alone.
func CheckFlags(goos string, args []string) error {
	goos, err := resolveGOOS(goos)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(args))
	for i, a := range args {
		name, value, hasValue, ok := parseSwitch(goos, a)
		if !ok {
			return fmt.Errorf("%w: argument %d is not a switch", ErrForbiddenFlag, i)
		}
		if why, denied := deniedSwitches[name]; denied {
			return fmt.Errorf("%w: --%s %s", ErrForbiddenFlag, name, why)
		}
		if seen[name] {
			return fmt.Errorf("%w: --%s given twice", ErrForbiddenFlag, name)
		}
		seen[name] = true
		if err := checkSwitch(goos, name, value, hasValue); err != nil {
			return err
		}
	}
	for _, name := range mandatorySwitches(goos) {
		if !seen[name] {
			return fmt.Errorf("%w: mandatory switch --%s missing", ErrForbiddenFlag, name)
		}
	}
	return nil
}

// mandatorySwitches are the switches every release argv carries on goos:
// the disposable profile, the resolver allowlist, the WebRTC and DNS
// prefetch leaks closed, and the CDP transport (pipe, or the port-0
// fallback on windows, ADR 0008 "Windows (A4)").
func mandatorySwitches(goos string) []string {
	transport := "remote-debugging-pipe"
	if goos == goosWindows {
		transport = "remote-debugging-port"
	}
	return []string{
		"user-data-dir",
		"host-resolver-rules",
		"force-webrtc-ip-handling-policy",
		"dns-prefetch-disable",
		transport,
	}
}

// parseSwitch splits one argument into its lowercased name and value. ok is
// false for a positional argument, "--" or an empty name.
func parseSwitch(goos, a string) (name, value string, hasValue, ok bool) {
	var rest string
	switch {
	case strings.HasPrefix(a, "--"):
		rest = a[2:]
	case strings.HasPrefix(a, "-"):
		rest = a[1:]
	case goos == goosWindows && strings.HasPrefix(a, "/"):
		rest = a[1:]
	default:
		return "", "", false, false
	}
	name, value, hasValue = strings.Cut(rest, "=")
	name = strings.ToLower(name)
	if name == "" || strings.HasPrefix(name, "-") {
		return "", "", false, false
	}
	return name, value, hasValue, true
}

// checkSwitch vets one switch that is not deny-listed.
func checkSwitch(goos, name, value string, hasValue bool) error {
	where, known := knownSwitches[name]
	if !known {
		return fmt.Errorf("%w: unknown switch --%s", ErrForbiddenFlag, name)
	}
	if osOK := where == "" || where == goos || (strings.HasPrefix(where, "!") && where[1:] != goos); !osOK {
		return fmt.Errorf("%w: --%s not allowed on %s", ErrForbiddenFlag, name, goos)
	}
	switch name {
	case "remote-debugging-port":
		if !hasValue || value != "0" {
			return fmt.Errorf("%w: --remote-debugging-port must be 0", ErrForbiddenFlag)
		}
	case "host-resolver-rules":
		return checkResolverRules(value)
	case "user-data-dir":
		if value == "" {
			return fmt.Errorf("%w: empty --user-data-dir", ErrForbiddenFlag)
		}
	case "force-webrtc-ip-handling-policy":
		if value != "disable_non_proxied_udp" {
			return fmt.Errorf("%w: --force-webrtc-ip-handling-policy weakened", ErrForbiddenFlag)
		}
	case "password-store":
		if value != "basic" {
			return fmt.Errorf("%w: --password-store must be basic", ErrForbiddenFlag)
		}
	}
	return nil
}

// checkResolverRules accepts only "MAP <pattern> ~NOTFOUND" and
// "EXCLUDE <pattern>" rules: a release build never maps a host to a
// target, loopback, IP or otherwise. The value is not echoed.
func checkResolverRules(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: empty --host-resolver-rules", ErrForbiddenFlag)
	}
	for rule := range strings.SplitSeq(value, ",") {
		f := strings.Fields(rule)
		switch {
		case len(f) == 3 && strings.EqualFold(f[0], "MAP") && f[2] == "~NOTFOUND":
		case len(f) == 2 && strings.EqualFold(f[0], "EXCLUDE"):
		default:
			return fmt.Errorf("%w: --host-resolver-rules may only block hosts", ErrForbiddenFlag)
		}
	}
	return nil
}
