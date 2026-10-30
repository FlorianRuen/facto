//go:build e2e

package browser

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// E2EOverrides carries the test-only switches: only the e2e build can point
// allowlisted hosts at the fake site on loopback and trust its test CA.
type E2EOverrides struct {
	LoopbackHosts []string // mapped to 127.0.0.1 in --host-resolver-rules
	// LoopbackPort is the port the loopback hosts are mapped to: 0 keeps
	// the request's port ("MAP <host> 127.0.0.1"), 1-65535 gives "MAP
	// <host> 127.0.0.1:<port>" (the fake site cannot bind 443 unprivileged,
	// while Navigate only accepts https on 443).
	LoopbackPort int
	TestCASPKI   []string // --ignore-certificate-errors-spki-list
}

// FlagsE2E returns Flags(opts) with the e2e overrides applied. Every
// loopback host must be an exact entry of opts.AllowedDomains, and every
// SPKI a base64 SHA-256 digest. The result is refused by the release
// CheckFlags on purpose; it still never carries a sandbox-weakening switch.
func FlagsE2E(opts Options, o E2EOverrides) ([]string, error) {
	args, err := Flags(opts)
	if err != nil {
		return nil, err
	}
	domains, err := normalizeDomains(opts.AllowedDomains)
	if err != nil {
		return nil, err
	}
	if o.LoopbackPort < 0 || o.LoopbackPort > 65535 {
		return nil, fmt.Errorf("%w: loopback port %d out of range", ErrForbiddenFlag, o.LoopbackPort)
	}
	if o.LoopbackPort != 0 && len(o.LoopbackHosts) == 0 {
		return nil, fmt.Errorf("%w: loopback port without a loopback host", ErrForbiddenFlag)
	}
	target := "127.0.0.1"
	if o.LoopbackPort != 0 {
		target += ":" + strconv.Itoa(o.LoopbackPort)
	}
	var maps []string
	for _, h := range o.LoopbackHosts {
		h = strings.ToLower(h)
		if strings.HasPrefix(h, "*.") || !slices.Contains(domains, h) {
			return nil, fmt.Errorf("%w: loopback host %q is not an exact allowed domain", ErrInvalidDomain, h)
		}
		maps = append(maps, "MAP "+h+" "+target)
		// Chrome checks EXCLUDE before MAP: an excluded host is not mapped.
		domains = slices.DeleteFunc(domains, func(d string) bool { return d == h })
	}
	for i, a := range args {
		if strings.HasPrefix(a, "--host-resolver-rules=") {
			args[i] = "--host-resolver-rules=" + resolverRules(maps, domains)
		}
	}
	if len(o.TestCASPKI) > 0 {
		for _, s := range o.TestCASPKI {
			if b, err := base64.StdEncoding.DecodeString(s); err != nil || len(b) != 32 {
				return nil, fmt.Errorf("%w: test CA SPKI is not a base64 SHA-256 digest", ErrForbiddenFlag)
			}
		}
		args = append(args, "--ignore-certificate-errors-spki-list="+strings.Join(o.TestCASPKI, ","))
	}
	return args, nil
}

// PoolE2E is the e2e configuration of a pool (J1 T22): the port the
// allowlisted hosts are mapped to on 127.0.0.1, and the SPKI digests of the
// test CA Chrome trusts.
type PoolE2E struct {
	LoopbackPort int      // 1-65535
	TestCASPKI   []string // base64 SHA-256 digests, at least one
}

// WithE2E returns cfg with every launch of its pool built by FlagsE2E and
// vetted by CheckFlagsE2E: the exact (non-wildcard) entries of the launch's
// AllowedDomains are mapped to 127.0.0.1:<LoopbackPort>, every other host
// still resolves to nothing, and the test CA is trusted. A port out of
// range or a missing or malformed SPKI is refused with ErrForbiddenFlag.
func WithE2E(cfg PoolConfig, e PoolE2E) (PoolConfig, error) {
	if e.LoopbackPort < 1 || e.LoopbackPort > 65535 {
		return PoolConfig{}, fmt.Errorf("%w: loopback port %d out of range", ErrForbiddenFlag, e.LoopbackPort)
	}
	if len(e.TestCASPKI) == 0 {
		return PoolConfig{}, fmt.Errorf("%w: no test CA SPKI", ErrForbiddenFlag)
	}
	if err := checkSPKIs(e.TestCASPKI); err != nil {
		return PoolConfig{}, err
	}
	spki := slices.Clone(e.TestCASPKI)
	overrides := func(opts Options) E2EOverrides {
		var hosts []string
		for _, d := range opts.AllowedDomains {
			if !strings.HasPrefix(d, "*.") {
				hosts = append(hosts, strings.ToLower(d))
			}
		}
		slices.Sort(hosts)
		return E2EOverrides{LoopbackHosts: slices.Compact(hosts), LoopbackPort: e.LoopbackPort, TestCASPKI: spki}
	}
	cfg.flags = &argvPolicy{
		build: func(opts Options) ([]string, error) { return FlagsE2E(opts, overrides(opts)) },
		check: func(opts Options, args []string) error { return CheckFlagsE2E(opts.GOOS, args, overrides(opts)) },
	}
	return cfg, nil
}

// checkSPKIs refuses anything but base64 SHA-256 digests.
func checkSPKIs(spki []string) error {
	for _, s := range spki {
		if b, err := base64.StdEncoding.DecodeString(s); err != nil || len(b) != 32 {
			return fmt.Errorf("%w: test CA SPKI is not a base64 SHA-256 digest", ErrForbiddenFlag)
		}
	}
	return nil
}

// CheckFlagsE2E is the launch-time check of an e2e argv: the e2e parts
// must be exactly those of o (each loopback host mapped once to
// 127.0.0.1[:LoopbackPort], nothing else mapped to a target; the SPKI list
// present once and equal to o.TestCASPKI when o has one, absent otherwise).
// Once they are removed, the release CheckFlags vets the rest.
func CheckFlagsE2E(goos string, args []string, o E2EOverrides) error {
	g, err := resolveGOOS(goos)
	if err != nil {
		return err
	}
	if o.LoopbackPort < 0 || o.LoopbackPort > 65535 {
		return fmt.Errorf("%w: loopback port %d out of range", ErrForbiddenFlag, o.LoopbackPort)
	}
	if err := checkSPKIs(o.TestCASPKI); err != nil {
		return err
	}
	target := "127.0.0.1"
	if o.LoopbackPort != 0 {
		target += ":" + strconv.Itoa(o.LoopbackPort)
	}
	hosts := make(map[string]bool, len(o.LoopbackHosts)) // host -> mapped
	for _, h := range o.LoopbackHosts {
		h = strings.ToLower(h)
		if h == "" || strings.HasPrefix(h, "*.") {
			return fmt.Errorf("%w: loopback host is not an exact domain", ErrInvalidDomain)
		}
		hosts[h] = false
	}
	out := make([]string, 0, len(args))
	sawSPKI := false
	for _, a := range args {
		name, value, hasValue, ok := parseSwitch(g, a)
		if !ok {
			out = append(out, a) // CheckFlags refuses it
			continue
		}
		switch name {
		case "ignore-certificate-errors-spki-list":
			if sawSPKI || len(o.TestCASPKI) == 0 || !hasValue || value != strings.Join(o.TestCASPKI, ",") {
				return fmt.Errorf("%w: --%s does not match the test CA", ErrForbiddenFlag, name)
			}
			sawSPKI = true
			continue
		case "host-resolver-rules":
			rest, err := stripLoopbackMaps(value, hosts, target)
			if err != nil {
				return err
			}
			out = append(out, "--host-resolver-rules="+rest)
			continue
		}
		out = append(out, a)
	}
	if len(o.TestCASPKI) > 0 && !sawSPKI {
		return fmt.Errorf("%w: test CA SPKI list missing", ErrForbiddenFlag)
	}
	for _, mapped := range hosts {
		if !mapped {
			return fmt.Errorf("%w: a loopback host is not mapped", ErrForbiddenFlag)
		}
	}
	return CheckFlags(g, out)
}

// stripLoopbackMaps removes the "MAP <host> <target>" rules of value, each
// host of hosts once, and returns the remaining rules. Any other mapping
// to a target is refused. The value is not echoed.
func stripLoopbackMaps(value string, hosts map[string]bool, target string) (string, error) {
	var rest []string
	for rule := range strings.SplitSeq(value, ",") {
		f := strings.Fields(rule)
		if len(f) != 3 || !strings.EqualFold(f[0], "MAP") || f[2] == "~NOTFOUND" {
			rest = append(rest, strings.TrimSpace(rule))
			continue
		}
		h := strings.ToLower(f[1])
		mapped, known := hosts[h]
		if !known || mapped || f[2] != target {
			return "", fmt.Errorf("%w: --host-resolver-rules maps a host off the e2e loopback target", ErrForbiddenFlag)
		}
		hosts[h] = true
	}
	return strings.Join(rest, ", "), nil
}
