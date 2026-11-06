//go:build e2e

package browser_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestFlagsE2E_LoopbackMappingAndTestCA: only the e2e build can point the
// allowlisted hosts at fakeprovider on loopback and trust its test CA, and
// it still never weakens the sandbox.
func TestFlagsE2E_LoopbackMappingAndTestCA(t *testing.T) {
	t.Parallel()
	o := opts("linux")
	got, err := browser.FlagsE2E(o, browser.E2EOverrides{
		LoopbackHosts: []string{"login.supplier.example"},
		TestCASPKI:    []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	})
	if err != nil {
		t.Fatalf("FlagsE2E: %v", err)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "MAP login.supplier.example 127.0.0.1") {
		t.Errorf("loopback mapping missing in %q", got)
	}
	if !slices.Contains(got, "--ignore-certificate-errors-spki-list=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Errorf("test CA SPKI missing in %q", got)
	}
	for _, d := range denyList[:len(denyList)-1] { // the SPKI flag is the one allowed here
		base, _, _ := strings.Cut(d, "=")
		if slices.ContainsFunc(got, func(a string) bool { return a == base || strings.HasPrefix(a, base+"=") }) {
			t.Errorf("FlagsE2E produced deny-listed %s", base)
		}
	}
	if err := browser.CheckFlags("linux", got); !errors.Is(err, browser.ErrForbiddenFlag) {
		t.Errorf("release CheckFlags accepted e2e flags: %v", err)
	}
}

// TestFlagsE2E_LoopbackPortMapped (J1 T13): the fake site listens on a
// random 127.0.0.1 port (443 needs privileges) while Navigate only accepts
// https on 443, so the e2e build maps the loopback hosts to
// 127.0.0.1:<LoopbackPort>. Out-of-range ports, and a port without a
// loopback host, are refused.
func TestFlagsE2E_LoopbackPortMapped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		hosts   []string
		port    int
		want    string // substring of --host-resolver-rules followed by ","
		wantErr error
	}{
		{name: "no port keeps 443", hosts: []string{"login.supplier.example"}, want: "MAP login.supplier.example 127.0.0.1,"},
		{name: "port mapped", hosts: []string{"login.supplier.example"}, port: 8443, want: "MAP login.supplier.example 127.0.0.1:8443,"},
		{name: "highest port", hosts: []string{"login.supplier.example"}, port: 65535, want: "MAP login.supplier.example 127.0.0.1:65535,"},
		{name: "negative port", hosts: []string{"login.supplier.example"}, port: -1, wantErr: browser.ErrForbiddenFlag},
		{name: "port too large", hosts: []string{"login.supplier.example"}, port: 65536, wantErr: browser.ErrForbiddenFlag},
		{name: "port without loopback host", port: 8443, wantErr: browser.ErrForbiddenFlag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := browser.FlagsE2E(opts("linux"), browser.E2EOverrides{LoopbackHosts: tt.hosts, LoopbackPort: tt.port})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("FlagsE2E(port %d) = %q, %v; want %v", tt.port, got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("FlagsE2E: %v", err)
			}
			var rules string
			for _, a := range got {
				if v, ok := strings.CutPrefix(a, "--host-resolver-rules="); ok {
					rules = v
				}
			}
			if !strings.Contains(rules+",", tt.want) {
				t.Errorf("--host-resolver-rules=%q, want it to contain %q", rules, strings.TrimSuffix(tt.want, ","))
			}
			if err := browser.CheckFlags("linux", got); !errors.Is(err, browser.ErrForbiddenFlag) {
				t.Errorf("release CheckFlags accepted the e2e loopback mapping: %v", err)
			}
		})
	}
}

// TestFlagsE2E_StaticHostMappedToLoopback (J2): in an e2e build a static
// allowlist host is mapped to the fake site like the allowed domains (it
// would resolve to nothing otherwise), and CheckFlagsE2E accepts it; a
// loopback host that is neither an allowed domain nor a static host is
// still refused.
func TestFlagsE2E_StaticHostMappedToLoopback(t *testing.T) {
	t.Parallel()
	o := opts("linux")
	o.Static = []string{"https://static.fakeprovider.test/app/"}
	ov := browser.E2EOverrides{LoopbackHosts: []string{"static.fakeprovider.test"}, LoopbackPort: 8443}
	got, err := browser.FlagsE2E(o, ov)
	if err != nil {
		t.Fatalf("FlagsE2E with a static host: %v", err)
	}
	if !slices.ContainsFunc(got, func(a string) bool {
		return strings.HasPrefix(a, "--host-resolver-rules=") && strings.Contains(a, "MAP static.fakeprovider.test 127.0.0.1:8443")
	}) {
		t.Fatalf("static host not mapped: %q", got)
	}
	if err := browser.CheckFlagsE2E("linux", got, ov); err != nil {
		t.Fatalf("CheckFlagsE2E: %v", err)
	}
	o.Static = nil
	if _, err := browser.FlagsE2E(o, ov); !errors.Is(err, browser.ErrInvalidDomain) {
		t.Fatalf("FlagsE2E mapping an unknown host = %v, want ErrInvalidDomain", err)
	}
}
