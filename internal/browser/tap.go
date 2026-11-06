package browser

import (
	"context"
	"fmt"
	"sync"
)

// Network tap of `facto record` (J2). It reads, never alters: the
// in-browser allowlist (fetch.go) still pauses and vets every request.

// tapBuffer is the event queue of a tap. A full queue drops events
// (counted by Dropped): a recording may miss an entry, the browser never
// stalls nor dies for it.
const tapBuffer = 4096

// tapMaxResourceBytes and tapMaxTotalBytes bound what Chrome buffers for
// Network.getResponseBody (Network.enable parameters).
const (
	tapMaxResourceBytes = 20 << 20
	tapMaxTotalBytes    = 100 << 20
)

// tapMethods are the Network events a tap delivers.
var tapMethods = []string{
	"Network.requestWillBeSent",
	"Network.requestWillBeSentExtraInfo",
	"Network.responseReceived",
	"Network.responseReceivedExtraInfo",
	"Network.loadingFinished",
	"Network.loadingFailed",
}

// NetworkTap delivers the Network events of the login page session (its
// frames' requests included; requests of workers and pop-ups, which run on
// other sessions, are not). Its events carry every header and cookie as
// the browser saw them: a consumer must redact them before keeping
// anything (internal/har).
type NetworkTap struct {
	p    *Page
	sub  *Subscription
	once sync.Once
}

// Tap enables the Network domain on the page session and returns its tap.
func (p *Page) Tap(ctx context.Context) (*NetworkTap, error) {
	sub := p.c.subscribeMethods(tapMethods, p.sessionID, SubscribeOptions{Buffer: tapBuffer})
	p.subsMu.Lock()
	if p.stopped {
		p.subsMu.Unlock()
		sub.Close()
		return nil, fmt.Errorf("tap: %w", ErrBrowserGone)
	}
	p.taps = append(p.taps, sub)
	p.subsMu.Unlock()
	if _, err := p.c.Call(ctx, p.sessionID, "Network.enable", map[string]any{
		"maxResourceBufferSize": tapMaxResourceBytes,
		"maxTotalBufferSize":    tapMaxTotalBytes,
	}); err != nil {
		sub.Close()
		return nil, fmt.Errorf("tap: enable network: %w", err)
	}
	return &NetworkTap{p: p, sub: sub}, nil
}

// Events delivers the events in arrival order. It is closed by Close or
// when the browser goes away.
func (t *NetworkTap) Events() <-chan Event { return t.sub.C() }

// Dropped counts the events lost because the queue was full.
func (t *NetworkTap) Dropped() int64 { return t.sub.Dropped() }

// Body returns the body of a finished response (Network.getResponseBody)
// and whether it is base64. The error never quotes the browser's answer.
func (t *NetworkTap) Body(ctx context.Context, requestID string) (string, bool, error) {
	if requestID == "" {
		return "", false, fmt.Errorf("tap: body: %w: empty request id", errPageScript)
	}
	if t.sub.closedFlag() {
		return "", false, fmt.Errorf("tap: body: %w", ErrBrowserGone)
	}
	var res struct {
		Body          string `json:"body"`
		Base64Encoded bool   `json:"base64Encoded"`
	}
	if err := t.p.call(ctx, t.p.sessionID, "Network.getResponseBody", map[string]any{"requestId": requestID}, &res); err != nil {
		return "", false, fmt.Errorf("tap: body: %w", err)
	}
	return res.Body, res.Base64Encoded, nil
}

// Close stops the delivery. Network stays enabled until the page closes.
func (t *NetworkTap) Close() { t.once.Do(t.sub.Close) }

// closedFlag reports whether the subscription is closed.
func (s *Subscription) closedFlag() bool {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	return s.closed
}

// Tap returns a NetworkTap on the lease's current page (Page.Tap).
func (b *PoolBrowser) Tap(ctx context.Context) (*NetworkTap, error) {
	pg, err := b.current()
	if err != nil {
		return nil, err
	}
	return pg.Tap(ctx)
}
