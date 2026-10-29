//go:build !linux

package proc_test

import (
	"testing"

	"github.com/FlorianRuen/facto/internal/proc"
)

// TestHarden_NoopElsewhere: on non-Linux platforms Harden must succeed
// without doing anything, and stay idempotent.
func TestHarden_NoopElsewhere(t *testing.T) {
	t.Parallel()
	for i := range 2 {
		if err := proc.Harden(); err != nil {
			t.Fatalf("Harden() call %d: %v, want nil no-op", i+1, err)
		}
	}
}
