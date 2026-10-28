package httpx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// minHeaderSecret is the shortest header value searched for in error
// messages; shorter values ("1", "gzip") would only cause false positives.
const minHeaderSecret = 6

// hopsKey is the context key of the per-call hopLog.
type hopsKey struct{}

// hopLog records the sensitive parts of every hop of one Do call: query,
// fragment, userinfo and header values.
type hopLog struct {
	mu      sync.Mutex
	secrets []string
}

func withHops(ctx context.Context, h *hopLog) context.Context {
	return context.WithValue(ctx, hopsKey{}, h)
}

func (h *hopLog) add(req *http.Request) {
	parts := urlSecrets(req.URL)
	for _, vs := range req.Header {
		for _, v := range vs {
			if len(v) >= minHeaderSecret {
				parts = append(parts, v)
			}
		}
	}
	h.mu.Lock()
	h.secrets = append(h.secrets, parts...)
	h.mu.Unlock()
}

func (h *hopLog) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.secrets
}

// urlSecrets returns the parts of u that must never appear in an error.
func urlSecrets(u *url.URL) []string {
	var out []string
	for _, s := range []string{u.RawQuery, u.Query().Encode(), u.Fragment, u.RawFragment} {
		if s != "" {
			out = append(out, s)
		}
	}
	if u.User != nil {
		// An empty part would match every message.
		if n := u.User.Username(); n != "" {
			out = append(out, n)
		}
		if p, ok := u.User.Password(); ok && p != "" {
			out = append(out, p)
		}
	}
	return out
}

// sanitize turns the error of http.Client.Do into one that names the method
// and host only. The *url.Error wrapper, which embeds the full URL, is
// dropped and its cause kept. A cause that would still echo a recorded URL
// part or header value is replaced by errURLWithheld, at the cost of its
// chain.
func sanitize(ctx context.Context, req *http.Request, hops *hopLog, err error) error {
	cause := err
	var uerr *url.Error
	if errors.As(err, &uerr) {
		cause = uerr.Err
	}
	secrets := append(urlSecrets(req.URL), hops.all()...)
	for _, vs := range req.Header {
		for _, v := range vs {
			if len(v) >= minHeaderSecret {
				secrets = append(secrets, v)
			}
		}
	}
	if leaks(cause, secrets) {
		cause = errURLWithheld
	}
	// The transport may report a deadline or a cancellation as its own
	// error type: make sure errors.Is still sees the context error.
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(cause, ctxErr) {
		cause = fmt.Errorf("%w: %w", ctxErr, cause)
	}
	return fmt.Errorf("httpx: %s %s: %w", req.Method, req.URL.Host, cause)
}

// leaks reports whether any error in err's chain has a message containing
// one of secrets, or describes a malformed Location header (net/http quotes
// the raw header, query included).
func leaks(err error, secrets []string) bool {
	stack := []error{err}
	for len(stack) > 0 {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if e == nil {
			continue
		}
		msg := e.Error()
		if strings.Contains(msg, "Location header") {
			return true
		}
		for _, s := range secrets {
			if strings.Contains(msg, s) {
				return true
			}
		}
		if u := errors.Unwrap(e); u != nil {
			stack = append(stack, u)
		} else if j, ok := e.(interface{ Unwrap() []error }); ok {
			stack = append(stack, j.Unwrap()...)
		}
	}
	return false
}
