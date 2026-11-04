//go:build e2e

package fakeprovider

import (
	"fmt"

	"github.com/FlorianRuen/facto/internal/connector"
)

// Register adds the fake connector, with default options, to r. It exists
// in e2e builds only (plan J1 T17): the release binary never carries
// fakeprovider. There is no package-level registry, hence a function and
// not init().
func Register(r *connector.Registry) error {
	if err := r.Register(New(Options{})); err != nil {
		return fmt.Errorf("fakeprovider: register: %w", err)
	}
	return nil
}
