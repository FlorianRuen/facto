package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// Client is a CDP client over one Transport: it numbers requests, matches
// responses by id and session id, dispatches events to subscribers
// (Subscribe) and drops anything else (unknown ids, responses for another
// session, late duplicates, events nobody subscribed to). Errors never
// quote a message, a parameter, a session id or a CDP error text.
type Client struct {
	t Transport
	// fatal is called once when the stream is unusable (oversized or
	// non-JSON message, read or write failure): StartPipe kills the
	// browser's process group there. Nil for a bare NewClient.
	fatal func()

	nextID atomic.Int64

	mu      sync.Mutex
	pending map[int64]*pendingCall
	subs    map[eventKey][]*Subscription
	err     error // sticky: set once, the client is then dead

	fatalOnce sync.Once
}

type pendingCall struct {
	session string
	ch      chan response // buffered 1: the reader never blocks
}

type response struct {
	result json.RawMessage
	err    error
}

// request is one outgoing CDP command.
type request struct {
	ID        int64  `json:"id"`
	Method    string `json:"method"`
	SessionID string `json:"sessionId,omitempty"`
	Params    any    `json:"params,omitempty"`
}

// incoming is the part of a browser message the client reads. An event has
// no id. A method or session id that is not a string fails the decoding:
// the client dies with ErrBadFrame.
type incoming struct {
	ID        *int64          `json:"id"`
	Method    string          `json:"method"`
	SessionID string          `json:"sessionId"`
	Params    json.RawMessage `json:"params"`
	Result    json.RawMessage `json:"result"`
	Error     *struct {
		Code int64 `json:"code"`
	} `json:"error"`
}

// NewClient starts reading t in a goroutine. Close (or the end of t) stops
// it.
func NewClient(t Transport) *Client {
	return newClient(t, nil)
}

func newClient(t Transport, fatal func()) *Client {
	c := &Client{t: t, fatal: fatal, pending: map[int64]*pendingCall{}, subs: map[eventKey][]*Subscription{}}
	go c.readLoop()
	return c
}

// Call sends method with params to the target of sessionID (the browser
// target when empty) and returns the "result" of the response carrying the
// same id and session id. It returns when that response arrives, when ctx
// ends (the browser keeps running; a late answer is dropped) or when the
// client dies (ErrBrowserGone, ErrMessageTooLarge, ErrBadFrame). A CDP error
// object gives ErrCDP with its numeric code only. params is encoded with
// encoding/json: a secret.Secret encodes masked, so only an exposed value
// (at the last call site) reaches the browser.
func (c *Client) Call(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cdp call: %w", err)
	}
	id := c.nextID.Add(1)
	msg, err := json.Marshal(request{ID: id, Method: method, SessionID: sessionID, Params: params})
	if err != nil {
		// The encoder error may quote a value: never wrapped.
		return nil, fmt.Errorf("%w: cannot encode the cdp request", ErrBadFrame)
	}

	pc := &pendingCall{session: sessionID, ch: make(chan response, 1)}
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return nil, err
	}
	c.pending[id] = pc
	c.mu.Unlock()

	// Send runs aside so that a browser that stops reading cannot hold
	// Call past ctx; closing the transport unblocks it.
	// A failed or partial write leaves the stream unusable: the client dies
	// here, even when Call has already returned on ctx.
	// Once Send has returned, the encoded request (which may hold a value
	// exposed at the last call site, such as Input.insertText) is cleared:
	// "wiped where feasible" (ADR 0008).
	sent := make(chan error, 1)
	go func() {
		err := c.t.Send(msg)
		clear(msg)
		if err != nil && !errors.Is(err, ErrBadFrame) {
			c.die(err)
		}
		sent <- err
	}()

	// A response may overtake Send's return (the peer answers while the
	// write call is unwinding): it is held until Send has returned, so a
	// result never comes back while the transport may still read msg.
	respCh := pc.ch
	var held *response
	for {
		select {
		case err := <-sent:
			sent = nil
			if err != nil {
				c.forget(id)
				return nil, err
			}
			if held != nil {
				return held.result, held.err
			}
		case r := <-respCh:
			if sent == nil {
				return r.result, r.err
			}
			respCh = nil
			held = &r
		case <-ctx.Done():
			c.forget(id)
			return nil, fmt.Errorf("cdp call: %w", ctx.Err())
		}
	}
}

// Close fails pending and later calls with ErrBrowserGone and closes the
// transport. It is idempotent.
func (c *Client) Close() error {
	c.fail(fmt.Errorf("%w: client closed", ErrBrowserGone))
	return c.t.Close() //nolint:wrapcheck // PipeTransport.Close already wraps
}

func (c *Client) forget(id int64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// fail records err as the client's final error (the first one wins), fails
// every pending call with it and closes the transport.
func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	for id, pc := range c.pending {
		pc.ch <- response{err: c.err}
		delete(c.pending, id)
	}
	for k, list := range c.subs {
		for _, s := range list {
			s.closeLocked()
		}
		delete(c.subs, k)
	}
	c.mu.Unlock()
	_ = c.t.Close()
}

// die fails the client and runs the fatal hook once.
func (c *Client) die(err error) {
	c.fail(err)
	c.fatalOnce.Do(func() {
		if c.fatal != nil {
			c.fatal()
		}
	})
}

func (c *Client) readLoop() {
	for {
		msg, err := c.t.Recv()
		if err != nil {
			c.die(err)
			return
		}
		var m incoming
		if json.Unmarshal(msg, &m) != nil {
			// Never quote the frame nor the decoder error.
			c.die(fmt.Errorf("%w: incoming frame is not a cdp message", ErrBadFrame))
			return
		}
		if m.ID == nil {
			if !c.dispatch(m) {
				// Never quote the method, the session id or the params.
				c.die(fmt.Errorf("%w: a fail-closed subscription is full", ErrEventOverflow))
				return
			}
			continue
		}
		c.mu.Lock()
		pc, ok := c.pending[*m.ID]
		if ok && pc.session == m.SessionID {
			delete(c.pending, *m.ID)
		} else {
			ok = false
		}
		c.mu.Unlock()
		if !ok {
			continue // unknown id, other session or late duplicate
		}
		if m.Error != nil {
			pc.ch <- response{err: &cdpError{code: m.Error.Code}}
			continue
		}
		pc.ch <- response{result: m.Result}
	}
}

// codeMethodNotFound is the JSON-RPC "method not found" error code.
const codeMethodNotFound = -32601

// cdpError is a CDP error object: only its numeric code is kept (the
// message may quote page data). It wraps ErrCDP.
type cdpError struct{ code int64 }

func (e *cdpError) Error() string { return fmt.Sprintf("%v: code %d", ErrCDP, e.code) }

func (e *cdpError) Unwrap() error { return ErrCDP }

// isMethodNotFound reports whether err is a CDP "method not found" answer.
func isMethodNotFound(err error) bool {
	var ce *cdpError
	return errors.As(err, &ce) && ce.code == codeMethodNotFound
}
