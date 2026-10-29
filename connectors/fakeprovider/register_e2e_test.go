//go:build e2e

package fakeprovider_test

import (
	"errors"
	"testing"

	"github.com/FlorianRuen/facto/connectors/fakeprovider"
	"github.com/FlorianRuen/facto/internal/connector"
)

// In the e2e build, Register adds the fake connector to an injected
// registry (there is no package-level registry).
func TestRegister_E2EBuildAddsFakeprovider(t *testing.T) {
	t.Parallel()
	r := connector.NewRegistry()
	if err := fakeprovider.Register(r); err != nil {
		t.Fatalf("Register: %v", err)
	}
	c, ok := r.Get(fakeprovider.ID)
	if !ok {
		t.Fatalf("registry has no %q after Register", fakeprovider.ID)
	}
	if got := c.Info().ID; got != fakeprovider.ID {
		t.Fatalf("registered connector ID = %q", got)
	}
	if err := fakeprovider.Register(r); !errors.Is(err, connector.ErrDuplicateID) {
		t.Fatalf("second Register = %v, want ErrDuplicateID", err)
	}
}
