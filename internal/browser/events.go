package browser

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync/atomic"
)

// ErrEventOverflow reports that a FailClosed subscription's queue was full.
// The client is then dead: pending and later calls fail with it, the fatal hook runs.
var ErrEventOverflow = errors.New("browser: cdp event queue overflow")

// DefaultEventBuffer is a subscription's queue capacity when
// SubscribeOptions.Buffer <= 0.
const DefaultEventBuffer = 256

// Event is one CDP event (a message without an id).
type Event struct {
	Method    string
	SessionID string          // "" for the browser session
	Params    json.RawMessage // a copy owned by the subscriber
}

// SubscribeOptions bounds one subscription's queue.
type SubscribeOptions struct {
	// Buffer is the queue capacity; <= 0 means DefaultEventBuffer.
	Buffer int
	// FailClosed: when the queue is full the client dies with
	// ErrEventOverflow instead of dropping the event. Used for
	// Fetch.requestPaused: a dropped pause would leave a request neither
	// failed nor continued.
	FailClosed bool
}

// eventKey selects the events of one subscription.
type eventKey struct {
	method, session string
}

// Subscription is one event queue (Client.Subscribe).
type Subscription struct {
	c          *Client
	keys       []eventKey
	failClosed bool
	ch         chan Event
	closed     bool // guarded by c.mu
	dropped    atomic.Int64
}

// Subscribe delivers, in arrival order, every event whose method and
// session id equal method and sessionID. The read loop never blocks on a
// subscriber: a full queue drops the event (counted by Dropped) or, with
// FailClosed, kills the client. Events without a subscriber are dropped
// silently. On a dead client the subscription is returned closed.
func (c *Client) Subscribe(method, sessionID string, opts SubscribeOptions) *Subscription {
	return c.subscribeMethods([]string{method}, sessionID, opts)
}

// subscribeMethods is Subscribe for several methods sharing one queue:
// their events keep their relative arrival order.
func (c *Client) subscribeMethods(methods []string, sessionID string, opts SubscribeOptions) *Subscription {
	n := opts.Buffer
	if n <= 0 {
		n = DefaultEventBuffer
	}
	s := &Subscription{c: c, failClosed: opts.FailClosed, ch: make(chan Event, n)}
	for _, m := range methods {
		s.keys = append(s.keys, eventKey{method: m, session: sessionID})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		s.closeLocked()
		return s
	}
	for _, k := range s.keys {
		c.subs[k] = append(c.subs[k], s)
	}
	return s
}

// C delivers the events. It is closed after Close or when the client dies;
// events queued before are still delivered.
func (s *Subscription) C() <-chan Event { return s.ch }

// Dropped counts the events dropped because the queue was full.
func (s *Subscription) Dropped() int64 { return s.dropped.Load() }

// Close stops the delivery and closes C. It is idempotent.
func (s *Subscription) Close() {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.closed {
		return
	}
	for _, k := range s.keys {
		list := s.c.subs[k]
		for i, x := range list {
			if x == s {
				list = append(list[:i:i], list[i+1:]...)
				break
			}
		}
		if len(list) == 0 {
			delete(s.c.subs, k)
		} else {
			s.c.subs[k] = list
		}
	}
	s.closeLocked()
}

// closeLocked closes the queue once; c.mu is held.
func (s *Subscription) closeLocked() {
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
}

// dispatch queues m for its subscribers without blocking. It returns false
// when a FailClosed queue is full: the caller kills the client.
func (c *Client) dispatch(m incoming) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ok := true
	for _, s := range c.subs[eventKey{method: m.Method, session: m.SessionID}] {
		ev := Event{Method: m.Method, SessionID: m.SessionID, Params: bytes.Clone(m.Params)}
		select {
		case s.ch <- ev:
		default:
			if s.failClosed {
				ok = false
				continue
			}
			s.dropped.Add(1)
		}
	}
	return ok
}
