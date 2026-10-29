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
