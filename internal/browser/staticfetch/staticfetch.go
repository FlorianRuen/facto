// Package staticfetch is the facto-side download of the login browser's
// path-scoped static allowlist (internal/browser static.go, SEC-J2-1,
// ADR 0008 "Static allowlist"): Chrome never resolves a static host; an
// allowed request is downloaded here through httpx.NewPinned (exact host on
// port 443, path prefix on every redirect hop, before any connection) and
// handed back to Chrome by the page.
//
// Besides internal/browser/cft, this is the only package that may call
// httpx.NewPinned (forbidigo, internal/httpx/pinned_callers_test.go).
package staticfetch

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// Pinned returns the production browser.StaticClients: one
// httpx.NewPinned(host, prefix, opts) client per static entry, without a
// cookie jar (a Set-Cookie of the static host is never sent back).
func Pinned(opts httpx.Options) browser.StaticClients {
	opts.NoCookies, opts.Jar = true, nil
	return func(host, prefix string) (browser.StaticGet, error) {
		c, err := httpx.NewPinned(host, prefix, opts)
		if err != nil {
			return nil, fmt.Errorf("staticfetch: %w", err)
		}
		return FromClient(c), nil
	}
}

// FromClient adapts a pinned client: GET or HEAD with the given request
// headers, the body read up to browser.MaxStaticBody (one byte more is
// an error, never a truncated file handed to the page).
func FromClient(c *httpx.Client) browser.StaticGet {
	return func(ctx context.Context, method, rawURL string, header map[string][]string) (browser.StaticResponse, error) {
		resp, err := c.Send(ctx, method, rawURL, header)
		if err != nil {
			return browser.StaticResponse{}, fmt.Errorf("staticfetch: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, browser.MaxStaticBody+1))
		if err != nil {
			return browser.StaticResponse{}, fmt.Errorf("staticfetch: read body: %w", err)
		}
		if len(body) > browser.MaxStaticBody {
			return browser.StaticResponse{}, errTooLarge
		}
		return browser.StaticResponse{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
	}
}

var errTooLarge = errors.New("staticfetch: body over browser.MaxStaticBody")
