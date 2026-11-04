// Follow-ups from the T14 review (J1 T16).
//
// Expected API (package vault):
//
//	// NewSealer returns a Sealer reading nonces from r. A nil r is refused
//	// with ErrInvalidArgument (no Sealer), instead of panicking at the first
//	// Seal.
//	func NewSealer(r io.Reader) (*Sealer, error)
//
//	// ValidConnectorID reports whether id matches the registry rule
//	// ^[a-z0-9]+(-[a-z0-9]+)*$ and is at most 40 bytes: exactly the IDs
//	// connector.ValidateInfo accepts. Seal, Open and the Store use it.
//	func ValidConnectorID(id string) bool
package vault_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/vault"
)

func mustSealer(t *testing.T, r io.Reader) *vault.Sealer {
	t.Helper()
	s, err := vault.NewSealer(r)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func TestNewSealer_NilRandRefused(t *testing.T) {
	t.Parallel()
	s, err := vault.NewSealer(nil)
	if !errors.Is(err, vault.ErrInvalidArgument) {
		t.Fatalf("NewSealer(nil): err = %v, want ErrInvalidArgument", err)
	}
	if s != nil {
		t.Fatalf("NewSealer(nil) returned a Sealer alongside the error")
	}
}

// connectorIDCases is the shared table and fuzz seed corpus: valid IDs,
// boundary lengths, and every shape the registry refuses.
var connectorIDCases = []string{
	// valid
	"edf", "ileo", "fakeprovider", "bouygues-telecom", "a", "0", "a1", "1a",
	"a-b-c", "x0-9y", strings.Repeat("a", 40), strings.Repeat("ab-", 12) + "abcd",
	// invalid
	"", strings.Repeat("a", 41), strings.Repeat("ab-", 13) + "ab",
	"-edf", "edf-", "e--df", "-", "--",
	"EDF", "Edf", "edf_old", "edf.sess", "edf.", ".edf", "e df", " edf", "edf ",
	"../edf", "..", ".", "a/b", `a\b`, "edf\x00", "edf\n", "\tedf",
	"édf", "edf\u200b", "ｅｄｆ", "edf\xff",
}

// registryAccepts reports whether the connector registry accepts id; the
// other Info fields are valid so only the ID decides.
func registryAccepts(id string) bool {
	err := connector.ValidateInfo(connector.Info{
		ID:             id,
		Name:           "Synthetic",
		Category:       "services",
		AllowedDomains: []string{"supplier.example.test"},
	})
	return err == nil
}

func TestValidConnectorID_MatchesRegistry(t *testing.T) {
	t.Parallel()
	if !registryAccepts("edf") {
		t.Fatalf("control: registry refuses the valid id \"edf\"; fix the Info fixture")
	}
	for _, id := range connectorIDCases {
		if got, want := vault.ValidConnectorID(id), registryAccepts(id); got != want {
			t.Errorf("ValidConnectorID(%q) = %v, registry accepts = %v", id, got, want)
		}
	}
}

func FuzzValidConnectorID_MatchesRegistry(f *testing.F) {
	for _, id := range connectorIDCases {
		f.Add(id)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if got, want := vault.ValidConnectorID(id), registryAccepts(id); got != want {
			t.Fatalf("ValidConnectorID(%q) = %v, registry accepts = %v", id, got, want)
		}
	})
}
