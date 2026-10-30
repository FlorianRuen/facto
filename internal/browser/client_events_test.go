// Tests for J1 task T9, client part: the read loop dispatches CDP events
// (ADR 0008 "In-browser allowlist": Fetch.requestPaused and
// Target.attachedToTarget must reach the page).
//
// Expected API (client.go), written before the implementation:
//
//	// Event is one CDP event (a message without an id).
//	type Event struct {
//		Method    string
//		SessionID string          // "" for the browser session
//		Params    json.RawMessage // a copy owned by the subscriber
//	}
//
//	// SubscribeOptions bounds one subscription's queue.
//	type SubscribeOptions struct {
//		// Buffer is the queue capacity; <= 0 means DefaultEventBuffer.
//		Buffer int
//		// FailClosed: when the queue is full the client dies with
//		// ErrEventOverflow (pending and later calls fail with it, the fatal
//		// hook runs) instead of dropping the event. Used for
//		// Fetch.requestPaused: a dropped pause would leave a request
//		// neither failed nor continued.
//		FailClosed bool
//	}
//
//	// DefaultEventBuffer is the queue capacity when Buffer <= 0.
//	const DefaultEventBuffer = 256
//
//	// ErrEventOverflow: a FailClosed subscription's queue was full.
//	var ErrEventOverflow = errors.New("browser: cdp event queue overflow")
//
//	// Subscribe delivers, in arrival order, every event whose method and
//	// session id equal method and sessionID. The read loop never blocks
//	// on a subscriber: a full queue drops the event (counted by Dropped)
//	// or, with FailClosed, kills the client. Events without a subscriber
//	// are dropped silently, as before.
//	func (c *Client) Subscribe(method, sessionID string, opts SubscribeOptions) *Subscription
//
//	type Subscription struct{ ... }
//	// C is closed after Close or when the client dies.
//	func (s *Subscription) C() <-chan Event
//	// Dropped counts events dropped because the queue was full.
//	func (s *Subscription) Dropped() int64
//	// Close stops the delivery and closes C. Idempotent.
//	func (s *Subscription) Close()
//
// Errors (ErrEventOverflow, ErrBadFrame for an event that does not decode)
// never quote the method, the session id or the params.
package browser_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// newEventClient returns a client over a fresh fake peer.
func newEventClient(t *testing.T) (*fakeCDP, *browser.Client) {
	t.Helper()
	f := newFakeCDP(t)
	c := browser.NewClient(f)
	t.Cleanup(func() { _ = c.Close() })
	return f, c
}

// recvEvent reads one event or fails after 20 s.
func recvEvent(t *testing.T, s *browser.Subscription) (browser.Event, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	select {
	case ev, ok := <-s.C():
		return ev, ok
	case <-ctx.Done():
		t.Fatal("no event within 20 s")
		return browser.Event{}, false
	}
}

// barrier makes a round trip: every frame the fake emitted before it has
// been read (and dispatched) when it returns.
func barrier(t *testing.T, c *browser.Client) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	_, err := c.Call(ctx, "", "Barrier.ping", nil)
	return err
}

func TestClient_EventsDispatchedToSubscribers(t *testing.T) {
	t.Parallel()

	t.Run("per method and session, in order", func(t *testing.T) {
		t.Parallel()
		f, c := newEventClient(t)
		s1 := c.Subscribe("Fetch.requestPaused", "s1", browser.SubscribeOptions{})
		s2 := c.Subscribe("Fetch.requestPaused", "s2", browser.SubscribeOptions{})
		att := c.Subscribe("Target.attachedToTarget", "", browser.SubscribeOptions{})
		t.Cleanup(func() { s1.Close(); s2.Close(); att.Close() })

		f.emit("s1", "Fetch.requestPaused", map[string]any{"requestId": "a"})
		f.emit("s2", "Fetch.requestPaused", map[string]any{"requestId": "b"})
		f.emit("", "Fetch.requestPaused", map[string]any{"requestId": "browser-level"})
		f.emit("s1", "Network.requestWillBeSent", map[string]any{"requestId": "other-method"})
		f.emit("", "Target.attachedToTarget", map[string]any{"sessionId": "child"})
		f.emit("s1", "Fetch.requestPaused", map[string]any{"requestId": "c"})
		if err := barrier(t, c); err != nil {
			t.Fatalf("Call after events = %v, want nil (events must not break responses)", err)
		}

		want := []struct {
			sub     *browser.Subscription
			name    string
			session string
			reqIDs  []string
		}{
			{s1, "s1", "s1", []string{"a", "c"}},
			{s2, "s2", "s2", []string{"b"}},
		}
		for _, w := range want {
			for _, id := range w.reqIDs {
				ev, ok := recvEvent(t, w.sub)
				if !ok {
					t.Fatalf("%s: channel closed, want requestId %q", w.name, id)
				}
				var p struct {
					RequestID string `json:"requestId"`
				}
				if err := json.Unmarshal(ev.Params, &p); err != nil {
					t.Fatalf("%s: params %s: %v", w.name, ev.Params, err)
				}
				if ev.Method != "Fetch.requestPaused" || ev.SessionID != w.session || p.RequestID != id {
					t.Errorf("%s: got %s on %q requestId %q, want Fetch.requestPaused on %q requestId %q",
						w.name, ev.Method, ev.SessionID, p.RequestID, w.session, id)
				}
			}
			select {
			case ev := <-w.sub.C():
				t.Errorf("%s: extra event %s on %q %s (another session or method leaked in)", w.name, ev.Method, ev.SessionID, ev.Params)
			default:
			}
		}
		ev, ok := recvEvent(t, att)
		if !ok || ev.Method != "Target.attachedToTarget" || ev.SessionID != "" {
			t.Errorf("attachedToTarget subscriber got %+v (ok %v), want the browser-session event", ev, ok)
		}
	})

	t.Run("responses still matched while events flow", func(t *testing.T) {
		t.Parallel()
		f, c := newEventClient(t)
		s := c.Subscribe("Page.frameNavigated", fakeSessionID, browser.SubscribeOptions{})
		t.Cleanup(s.Close)
		f.setIntercept("Page.getFrameTree", func(cdpCall) any {
			// The event is queued before the response.
			f.emit(fakeSessionID, "Page.frameNavigated", map[string]any{"frame": map[string]any{"id": fakeFrameID}})
			return nil
		})
		ctx := testCtx(t)
		if _, err := c.Call(ctx, fakeSessionID, "Page.getFrameTree", nil); err != nil {
			t.Fatalf("Call = %v", err)
		}
		if ev, ok := recvEvent(t, s); !ok || ev.Method != "Page.frameNavigated" {
			t.Errorf("event = %+v (ok %v), want Page.frameNavigated", ev, ok)
		}
	})

	t.Run("no subscriber: dropped, client alive", func(t *testing.T) {
		t.Parallel()
		f, c := newEventClient(t)
		for i := range 2 * browser.DefaultEventBuffer {
			f.emit("", "Some.event", map[string]any{"i": i})
		}
		if err := barrier(t, c); err != nil {
			t.Errorf("Call = %v, want nil", err)
		}
	})

	t.Run("Close stops delivery and closes C; idempotent", func(t *testing.T) {
		t.Parallel()
		f, c := newEventClient(t)
		s := c.Subscribe("Fetch.requestPaused", "s1", browser.SubscribeOptions{})
		s.Close()
		s.Close()
		f.emit("s1", "Fetch.requestPaused", map[string]any{"requestId": "late"})
		if err := barrier(t, c); err != nil {
			t.Fatalf("Call = %v", err)
		}
		if ev, ok := recvEvent(t, s); ok {
			t.Errorf("closed subscription delivered %+v, want a closed channel", ev)
		}
	})

	t.Run("client death closes C", func(t *testing.T) {
		t.Parallel()
		_, c := newEventClient(t)
		s := c.Subscribe("Fetch.requestPaused", "s1", browser.SubscribeOptions{})
		_ = c.Close()
		if ev, ok := recvEvent(t, s); ok {
			t.Errorf("subscription of a dead client delivered %+v, want a closed channel", ev)
		}
	})
}

func TestClient_SlowSubscriberNeverBlocksResponses(t *testing.T) {
	t.Parallel()

	t.Run("bounded queue drops and counts", func(t *testing.T) {
		t.Parallel()
		f, c := newEventClient(t)
		const buf, sent = 2, 50
		s := c.Subscribe("Network.dataReceived", fakeSessionID, browser.SubscribeOptions{Buffer: buf})
		t.Cleanup(s.Close)
		// Nobody reads s: the response queued behind the events must still
		// arrive.
		for i := range sent {
			f.emit(fakeSessionID, "Network.dataReceived", map[string]any{"i": i})
		}
		if err := barrier(t, c); err != nil {
			t.Fatalf("Call behind %d unread events = %v, want nil", sent, err)
		}
		if got := s.Dropped(); got != sent-buf {
			t.Errorf("Dropped = %d, want %d (queue of %d, %d events)", got, sent-buf, buf, sent)
		}
		// The queued events are the first ones, in order.
		for i := range buf {
			ev, ok := recvEvent(t, s)
			var p struct{ I int }
			if !ok || json.Unmarshal(ev.Params, &p) != nil || p.I != i {
				t.Errorf("queued event %d = %s (ok %v), want i=%d", i, ev.Params, ok, i)
			}
		}
		// Still usable afterwards.
		if err := barrier(t, c); err != nil {
			t.Errorf("later Call = %v, want nil", err)
		}
	})

	t.Run("fail closed: overflow kills the client", func(t *testing.T) {
		t.Parallel()
		f, c := newEventClient(t)
		s := c.Subscribe("Fetch.requestPaused", fakeSessionID, browser.SubscribeOptions{Buffer: 1, FailClosed: true})
		t.Cleanup(s.Close)
		for i := range 3 {
			f.emit(fakeSessionID, "Fetch.requestPaused", map[string]any{"requestId": fmt.Sprint(i)})
		}
		err := barrier(t, c)
		if !errors.Is(err, browser.ErrEventOverflow) {
			t.Fatalf("Call after overflow = %v, want ErrEventOverflow (a dropped pause would hang a request unchecked)", err)
		}
		// Later calls fail the same way: the client is dead.
		if err := barrier(t, c); !errors.Is(err, browser.ErrEventOverflow) {
			t.Errorf("second Call = %v, want ErrEventOverflow (sticky)", err)
		}
		// C delivers what was queued, then is closed.
		n := 0
		for {
			_, ok := recvEvent(t, s)
			if !ok {
				break
			}
			n++
		}
		if n > 1 {
			t.Errorf("delivered %d events from a queue of 1", n)
		}
	})

	t.Run("fail closed on another subscription does not fire for a lossy one", func(t *testing.T) {
		t.Parallel()
		f, c := newEventClient(t)
		lossy := c.Subscribe("Network.dataReceived", fakeSessionID, browser.SubscribeOptions{Buffer: 1})
		strict := c.Subscribe("Fetch.requestPaused", fakeSessionID, browser.SubscribeOptions{Buffer: 4, FailClosed: true})
		t.Cleanup(func() { lossy.Close(); strict.Close() })
		for range 10 {
			f.emit(fakeSessionID, "Network.dataReceived", map[string]any{})
		}
		f.emit(fakeSessionID, "Fetch.requestPaused", map[string]any{"requestId": "r"})
		if err := barrier(t, c); err != nil {
			t.Errorf("Call = %v, want nil (only the lossy queue overflowed)", err)
		}
	})
}

func TestClient_EventsCarryNoSecretsInErrors(t *testing.T) {
	t.Parallel()

	t.Run("overflow error", func(t *testing.T) {
		t.Parallel()
		canary := testsecrets.Canary(t, testsecrets.Token)
		session := "sess-" + canary
		f, c := newEventClient(t)
		s := c.Subscribe("Fetch.requestPaused", session, browser.SubscribeOptions{Buffer: 1, FailClosed: true})
		t.Cleanup(s.Close)
		for range 3 {
			f.emit(session, "Fetch.requestPaused", map[string]any{
				"requestId": canary,
				"request":   map[string]any{"url": "https://evil.test/?t=" + canary, "headers": map[string]any{"Cookie": canary}},
			})
		}
		err := barrier(t, c)
		if !errors.Is(err, browser.ErrEventOverflow) {
			t.Fatalf("Call = %v, want ErrEventOverflow", err)
		}
		if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "evil.test") {
			t.Errorf("overflow error quotes the event: %q", err)
		}
	})

	for name, frame := range map[string]string{
		"method not a string":  `{"method":12,"sessionId":"%[1]s","params":{"v":"%[1]s"}}`,
		"session not a string": `{"method":"Fetch.requestPaused","sessionId":{"x":"%[1]s"},"params":{}}`,
		"params truncated":     `{"method":"Fetch.requestPaused","params":{"v":"%[1]s"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Token)
			f, c := newEventClient(t)
			s := c.Subscribe("Fetch.requestPaused", "", browser.SubscribeOptions{FailClosed: true})
			t.Cleanup(s.Close)
			f.emitRaw(fmt.Sprintf(frame, canary))
			err := barrier(t, c)
			if err == nil {
				t.Fatal("Call after a malformed event = nil, want the client dead (ErrBadFrame)")
			}
			if !errors.Is(err, browser.ErrBadFrame) {
				t.Errorf("Call = %v, want ErrBadFrame", err)
			}
			if strings.Contains(err.Error(), canary) {
				t.Errorf("error quotes the event: %q", err)
			}
		})
	}
}
