package browser

import "context"

// Test hooks for the enforcement bookkeeping (J1 T9 review).

// Handlers returns the page's subscriptions and running handler goroutines.
func (p *Page) Handlers() (subs, running int) {
	p.subsMu.Lock()
	defer p.subsMu.Unlock()
	return p.subCount(), p.running
}

// WaitHandlers blocks until the page has at most subs subscriptions and
// running handler goroutines, or ctx ends.
func (p *Page) WaitHandlers(ctx context.Context, subs, running int) error {
	for {
		p.subsMu.Lock()
		s, r, ch := p.subCount(), p.running, p.subsChanged
		p.subsMu.Unlock()
		if s <= subs && r <= running {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Subscriptions returns the number of live subscriptions of c.
func (c *Client) Subscriptions() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, l := range c.subs {
		n += len(l)
	}
	return n
}
