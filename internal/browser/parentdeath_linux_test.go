//go:build linux

package browser_test

import "testing"

// TestChrome_ExitsWhenParentDies: on Linux StartPipe sets Pdeathsig, so a
// browser that ignores pipe EOF still dies when facto is SIGKILLed (no
// cleanup code runs). The fake here never reads its pipe.
func TestChrome_ExitsWhenParentDies(t *testing.T) {
	t.Parallel()
	parent, pid := startParentOfFake(t)
	killParent(t, parent)
	if !waitGone(pid) {
		t.Errorf("browser pid %d survived its parent's SIGKILL: Pdeathsig not set", pid)
	}
}
