//go:build e2e

package browser_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

const dnsTestSPKI = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func resolverRulesOf(t *testing.T, args []string) string {
	t.Helper()
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--host-resolver-rules="); ok {
			return v
		}
	}
	t.Fatalf("no --host-resolver-rules in %q", args)
	return ""
}

// TestFlagsE2E_NoNameReachesRealDNS (J1 T27): whatever the allowlist, the
// e2e resolver rules are the loopback MAPs then "MAP * ~NOTFOUND", with no
// EXCLUDE; and CheckFlagsE2E refuses an e2e argv carrying one.
func TestFlagsE2E_NoNameReachesRealDNS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		domains []string
		hosts   []string
		want    string
	}{
		{"wildcard only", []string{"*.supplier.example"}, nil, "MAP * ~NOTFOUND"},
		{
			"exact host left unmapped",
			[]string{"a.supplier.example", "b.supplier.example"},
			[]string{"a.supplier.example"},
			"MAP a.supplier.example 127.0.0.1:8443, MAP * ~NOTFOUND",
		},
		{
			"host and wildcard",
			[]string{"supplier.example", "*.supplier.example"},
			[]string{"supplier.example"},
			"MAP supplier.example 127.0.0.1:8443, MAP * ~NOTFOUND",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			o := browser.Options{GOOS: "linux", ProfileDir: "/facto-test/profile", AllowedDomains: tt.domains}
			port := 0
			if len(tt.hosts) > 0 {
				port = 8443
			}
			ov := browser.E2EOverrides{LoopbackHosts: tt.hosts, LoopbackPort: port, TestCASPKI: []string{dnsTestSPKI}}
			args, err := browser.FlagsE2E(o, ov)
			if err != nil {
				t.Fatalf("FlagsE2E: %v", err)
			}
			if got := resolverRulesOf(t, args); got != tt.want {
				t.Errorf("--host-resolver-rules=%q, want %q", got, tt.want)
			}
			if err := browser.CheckFlagsE2E("linux", args, ov); err != nil {
				t.Errorf("CheckFlagsE2E refused FlagsE2E's own argv: %v", err)
			}
			tampered := slices.Clone(args)
			for i, a := range tampered {
				if strings.HasPrefix(a, "--host-resolver-rules=") {
					tampered[i] = a + ", EXCLUDE " + strings.TrimPrefix(tt.domains[0], "*.")
				}
			}
			if err := browser.CheckFlagsE2E("linux", tampered, ov); !errors.Is(err, browser.ErrForbiddenFlag) {
				t.Errorf("CheckFlagsE2E(argv with an EXCLUDE) = %v, want ErrForbiddenFlag", err)
			}
		})
	}
}
