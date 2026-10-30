package browser_test

import (
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestPage_WaitVisiblePollsAgainAcrossCommit: a document committed during
// a WaitVisible poll is not an error; the next poll runs in the new
// document's own isolated world.
func TestPage_WaitVisiblePollsAgainAcrossCommit(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.navigate(t, loginURL)
	e.f.setElem("#login", fakeElem{visibleAfter: 2})
	committed := false
	e.f.setOnFunction(func(decl string) {
		if decl == browser.JSVisible && !committed {
			committed = true // WaitVisible polls one at a time: no concurrent hook
			e.f.setLoader("loader-commit")
		}
	})
	m := e.f.mark()
	if err := e.p.WaitVisible(testCtx(t), "#login"); err != nil {
		t.Fatalf("WaitVisible = %v, want nil (a commit mid-poll means poll again)", err)
	}
	if n := len(filter(e.f.since(m), "Page.createIsolatedWorld")); n != 2 {
		t.Errorf("createIsolatedWorld calls = %d, want 2 (one per document)", n)
	}
}
