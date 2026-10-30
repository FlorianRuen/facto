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
