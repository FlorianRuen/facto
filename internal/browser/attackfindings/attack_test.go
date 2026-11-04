// Red-team FINDING tests for the in-browser allowlist (J1 task T27): each
// test here fails today on purpose and documents one weakness for the
// implementer to fix test-first. Never weaken or skip them; once the fix
// lands they pass and stay as regression tests. The passing attacks live
// in internal/browser/attackunit (scripted CDP) and
// internal/browser/attack_test.go (real Chrome). Everything is synthetic.
package attackfindings_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
)

const (
	ctxID     = "ctx-find"
	targetID  = "tgt-find"
	sessionID = "sess-find"
	waitLimit = 20 * time.Second
)

type call struct {
	Method  string
	Session string
	Params  map[string]any
}

// peer is a minimal scripted CDP browser (browser.Transport).
type peer struct {
	mu      sync.Mutex
	calls   []call
	changed chan struct{}
	out     chan []byte
	once    sync.Once
	closed  chan struct{}
}

func newPeer() *peer {
	return &peer{changed: make(chan struct{}), out: make(chan []byte, 1024), closed: make(chan struct{})}
}

func (p *peer) Send(msg []byte) error {
	var req struct {
		ID        int64          `json:"id"`
		Method    string         `json:"method"`
		SessionID string         `json:"sessionId"`
		Params    map[string]any `json:"params"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return fmt.Errorf("%w: peer", browser.ErrBadFrame)
	}
	p.mu.Lock()
	p.calls = append(p.calls, call{Method: req.Method, Session: req.SessionID, Params: req.Params})
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	var result any = map[string]any{}
	switch req.Method {
	case "Target.createBrowserContext":
		result = map[string]any{"browserContextId": ctxID}
	case "Target.createTarget":
		result = map[string]any{"targetId": targetID}
	case "Target.attachToTarget":
		result = map[string]any{"sessionId": sessionID}
	}
	resp := map[string]any{"id": req.ID, "result": result}
	if req.SessionID != "" {
		resp["sessionId"] = req.SessionID
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	p.push(b)
	return nil
}

func (p *peer) Recv() ([]byte, error) {
	select {
	case b := <-p.out:
		return b, nil
	case <-p.closed:
		return nil, fmt.Errorf("%w: peer closed", browser.ErrBrowserGone)
	}
}

func (p *peer) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *peer) push(b []byte) {
	select {
	case p.out <- b:
	case <-p.closed:
	}
}

func (p *peer) emit(t *testing.T, session, method string, params any) {
	t.Helper()
	ev := map[string]any{"method": method, "params": params}
	if session != "" {
		ev["sessionId"] = session
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	p.push(b)
}

func (p *peer) snapshot() []call {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

func (p *peer) waitCall(t *testing.T, match func(c call) bool) {
	t.Helper()
	timer := time.NewTimer(waitLimit)
	defer timer.Stop()
	for {
		p.mu.Lock()
		found := slices.ContainsFunc(p.calls, match)
		ch := p.changed
		p.mu.Unlock()
		if found {
			return
		}
		select {
		case <-ch:
		case <-timer.C:
			t.Fatal("peer: expected call never came")
		}
	}
}

func newPage(t *testing.T) *peer {
	t.Helper()
	p := newPeer()
	c := browser.NewClient(p)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()
	pg, err := browser.NewPage(ctx, c, browser.PageOptions{
		AllowedDomains: []string{"supplier.example", "*.supplier.example"},
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return p
}

// TestAttack_SharedWorkerGetsAutoAttachBeforeResume (T13 review).
//
// FINDING: LOW (cat 3, latent). A shared_worker target (attached on the
// browser session by the browser-level auto-attach) is resumed with
// Fetch.enable on its session but without Target.setAutoAttach
// (fetch.go onAttached: nested is page, iframe and worker only). Any
// dedicated worker it starts is then never attached nor paused, so the page
// never decides on it; its IP-literal requests would bypass the resolver
// rules too. Not exploitable on the pinned Chrome for Testing 156, which
// refuses `new Worker` inside a shared worker (real-Chrome proof:
// TestAttack_ChromeSharedWorkerNestedWorkerFetchBlocked reports
// "nested-unsupported" and no /leak), but one Chrome bump away.
// Reproduce:
//
//	go test -count=1 -run TestAttack_SharedWorkerGetsAutoAttachBeforeResume -v ./internal/browser/attackfindings/
//
// Fix (plan T27, T13 review): nest shared_worker like worker
// (setAutoAttach with waitForDebuggerOnStart before resume), and fail
// closed (close the target, never resume) if Chrome refuses it.
func TestAttack_SharedWorkerGetsAutoAttachBeforeResume(t *testing.T) {
	t.Parallel()
	p := newPage(t)
	const child, tgt = "sess-shared", "tgt-shared"
	p.emit(t, "", "Target.attachedToTarget", map[string]any{
		"sessionId": child, "waitingForDebugger": true,
		"targetInfo": map[string]any{"targetId": tgt, "type": "shared_worker", "url": "", "attached": true, "browserContextId": ctxID},
	})
	resumed := func(c call) bool { return c.Method == "Runtime.runIfWaitingForDebugger" && c.Session == child }
	closed := func(c call) bool { return c.Method == "Target.closeTarget" && c.Params["targetId"] == tgt }
	p.waitCall(t, func(c call) bool { return resumed(c) || closed(c) })
	calls := p.snapshot()
	iRun := slices.IndexFunc(calls, resumed)
	if iRun < 0 {
		return // closed, never resumed: fail closed is acceptable
	}
	iAuto := slices.IndexFunc(calls, func(c call) bool {
		return c.Method == "Target.setAutoAttach" && c.Session == child &&
			c.Params["autoAttach"] == true && c.Params["waitForDebuggerOnStart"] == true && c.Params["flatten"] == true
	})
	if iAuto < 0 || iAuto > iRun {
		t.Errorf("FINDING: shared worker resumed without Target.setAutoAttach {autoAttach, waitForDebuggerOnStart, flatten} on its session: its nested dedicated workers would run unattached")
	}
}
