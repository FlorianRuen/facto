//go:build darwin

package browser_test

import (
	"testing"
	"time"
)

// TestChrome_ParentDeathGapDarwin documents the macOS gap recorded in ADR
// 0008: there is no Pdeathsig, and the browser has its own process group, so
// a browser that ignores pipe EOF outlives a SIGKILLed facto. Real Chrome
// exiting on pipe EOF is unverified. If this test fails, macOS now kills the
// browser on parent death: update ADR 0008 and assert the Linux behaviour
// (TestChrome_ExitsWhenParentDies) here instead.
func TestChrome_ParentDeathGapDarwin(t *testing.T) {
	t.Parallel()
	parent, pid := startParentOfFake(t)
	killParent(t, parent)
	<-time.After(2 * time.Second) // observation window for the documented gap
	if processGone(pid) {
		t.Errorf("browser pid %d died with its parent: the recorded macOS gap is gone, update ADR 0008", pid)
	}
}
