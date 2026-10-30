//go:build e2e

// Red-team FINDING test for the e2e browser flags (J1 task T27, T22
// review). It fails today on purpose; never weaken or skip it. Everything
// is synthetic.
package attackfindingse2e_test

import (
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestAttack_E2EWildcardAllowlistNeverReachesRealDNS (T22 review).
//
// FINDING: LOW (cat 3/5, e2e builds only). In an e2e build, an allowlist
// wildcard (*.x) is neither mapped to the loopback fake site nor
// ~NOTFOUND: FlagsE2E keeps the release rule "EXCLUDE *.x", so Chrome
// resolves every subdomain through the real DNS and connects to the real
// host. Harmless for fakeprovider (exact hosts only), but a J2 connector
// whose Info().AllowedDomains holds "*.<real supplier domain>" would make
// `make e2e` look up and reach the real supplier from CI. WithE2E only
// passes exact hosts as LoopbackHosts and FlagsE2E refuses a wildcard
// there, so there is no way to map one. Reproduce:
//
//	go test -tags e2e -count=1 -run TestAttack_E2EWildcardAllowlistNeverReachesRealDNS -v ./internal/browser/attackfindingse2e/
//
// Fix direction (implementer, test-first): in FlagsE2E, map every
// allowlist entry, wildcards included ("MAP *.x 127.0.0.1:<port>"), or
// drop the EXCLUDE of any entry not mapped, so an e2e browser never
// resolves a name outside the loopback rules.
func TestAttack_E2EWildcardAllowlistNeverReachesRealDNS(t *testing.T) {
	t.Parallel()
	args, err := browser.FlagsE2E(browser.Options{
		GOOS:           "linux",
		ProfileDir:     "/facto-test/profile",
		AllowedDomains: []string{"supplier.example", "*.supplier.example"},
	}, browser.E2EOverrides{
		LoopbackHosts: []string{"supplier.example"},
		LoopbackPort:  8443,
		TestCASPKI:    []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	})
	if err != nil {
		t.Fatalf("FlagsE2E: %v", err)
	}
	var rules string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--host-resolver-rules="); ok {
			rules = v
		}
	}
	if rules == "" {
		t.Fatal("no --host-resolver-rules in the e2e argv")
	}
	for _, r := range strings.Split(rules, ",") {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "EXCLUDE ") {
			t.Errorf("FINDING: e2e resolver rule %q sends that name to the real DNS (rules: %q)", r, rules)
		}
	}
}
