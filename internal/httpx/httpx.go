// Package httpx is the only way facto does network I/O (CLAUDE.md rule 5).
// A Client enforces a per-connector domain allowlist on every request and
// every redirect hop before any connection is made (default HTTPS port only,
// no public-suffix entry), speaks HTTPS only with TLS >= 1.2 and certificate
// verification always on, never reads proxy environment variables, bounds
// every request with a timeout and keeps cookies in a jar. Its errors keep their cause chain but never carry a
// query string, fragment, userinfo or header value. See docs/spec.md
// "Threat model" (exfiltration by a connector).
//
// NewPinned builds the same client restricted to one exact host and one
// path prefix instead of an allowlist, for downloads from shared storage
// hosts that ParseAllowlist refuses (Chrome for Testing, ADR 0008).
//
// httpx imports only the standard library: internal/connector delegates
// AllowedDomains validation to ParseAllowlist.
package httpx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Sentinel errors (errors.Is).
var (
	ErrDomainNotAllowed = errors.New("httpx: domain not allowed")
	ErrInsecureScheme   = errors.New("httpx: only https is allowed")
	ErrInvalidAllowlist = errors.New("httpx: invalid allowlist")
	ErrBodyTooLarge     = errors.New("httpx: body too large")
	// ErrPathNotAllowed reports, on a NewPinned client, a URL path outside
	// the pinned prefix or not in canonical form (dot segment, empty
	// segment, percent-encoding, backslash).
	ErrPathNotAllowed = errors.New("httpx: path not allowed")
)

// Defaults applied when the matching Options field is zero.
const (
	DefaultTimeout      = 60 * time.Second
	DefaultMaxRedirects = 10
)

// Transport tuning, not configurable: generous for slow supplier sites,
// bounded so a stuck peer cannot hang a run.
const (
	dialTimeout         = 30 * time.Second
	tlsHandshakeTimeout = 15 * time.Second
	idleConnTimeout     = 90 * time.Second
)

// errNilContext is returned by Get for a nil context.
var errNilContext = errors.New("httpx: nil context")

// errURLWithheld replaces a cause whose message would echo part of a URL or
// a header value.
var errURLWithheld = errors.New("request failed (cause withheld: it embeds the url)")

// Options configures a Client. The zero value is a production client.
type Options struct {
	// RootCAs replaces the system roots when non-nil. Verification is never
	// disabled.
	RootCAs *x509.CertPool
	// Timeout bounds the whole request, redirects and body read included.
	// 0 means DefaultTimeout.
	Timeout time.Duration
	// Jar stores cookies. nil means a fresh in-memory cookiejar.
	Jar http.CookieJar
	// MaxRedirects is the number of redirects followed. 0 means
	// DefaultMaxRedirects.
	MaxRedirects int
	// Proxy is nil by default: no proxy, and proxy environment variables
	// (HTTPS_PROXY…) are ignored; httpx never reads the environment.
	// cmd/facto sets Proxy = http.ProxyFromEnvironment only when
	// FACTO_ALLOW_PROXY=1.
	Proxy func(*http.Request) (*url.URL, error)
	// DialContext replaces the TCP dialer (tests, resolver pinning). TLS
	// verification still applies on top of it.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Client is an allowlisted HTTPS client. Safe for concurrent use.
type Client struct {
	allow Allowlist
	// pin, when non-nil, replaces allow: exact host and path prefix
	// (NewPinned).
	pin     *pin
	hc      *http.Client
	timeout time.Duration
}

// New parses allowed with ParseAllowlist and builds a client: TLS >= 1.2,
// certificate verification on, HTTPS only, timeouts, cookie jar.
func New(allowed []string, opts Options) (*Client, error) {
	allow, err := ParseAllowlist(allowed)
	if err != nil {
		return nil, err
	}
	return newClient(allow, nil, opts)
}

// newClient builds a client enforcing allow, or p when p is non-nil.
func newClient(allow Allowlist, p *pin, opts Options) (*Client, error) {
	var err error
	jar := opts.Jar
	if jar == nil {
		// Without a public suffix list the jar is strict per host, which
		// is enough: the allowlist already bounds where cookies go.
		jar, err = cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("httpx: cookie jar: %w", err)
		}
	}
	dial := opts.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialTimeout, KeepAlive: dialTimeout}).DialContext
	}
	maxRedirects := opts.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	c := &Client{allow: allow, pin: p, timeout: timeout}
	tr := &http.Transport{
		Proxy:       opts.Proxy, // nil: never the environment
		DialContext: dial,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    opts.RootCAs,
		},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		IdleConnTimeout:       idleConnTimeout,
		ExpectContinueTimeout: time.Second,
	}
	c.hc = &http.Client{
		// guard re-checks every hop, redirects included, before the
		// transport may dial.
		Transport: guard{c: c, next: tr},
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("httpx: stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
	return c, nil
}

// Jar returns the cookie jar (Options.Jar or the default one), so cookies
// captured by the browser at login can be injected.
func (c *Client) Jar() http.CookieJar {
	return c.hc.Jar
}

// Get builds a GET request with ctx and calls Do. A nil ctx is an error
// naming the context; a malformed rawURL is an error that does not echo
// rawURL. Neither dials.
func (c *Client) Get(ctx context.Context, rawURL string) (*http.Response, error) {
	if ctx == nil {
		return nil, errNilContext
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		// err is a *url.Error embedding rawURL: drop it.
		return nil, errors.New("httpx: malformed url")
	}
	return c.Do(req)
}

// Do sends req. Before any connection, for the request and for every
// redirect hop, a scheme other than https wraps ErrInsecureScheme and a host
// (URL host or explicit req.Host) outside the allowlist, or with a port
// other than 443, or a URL with a non-empty Opaque, wraps
// ErrDomainNotAllowed. On such an early rejection, as
// on a nil URL, req.Body is closed like net/http.Client.Do does; a hop the
// guard rejects later (a 307/308 redirect replaying the body through
// req.GetBody) has its body closed exactly once too. Following more than
// MaxRedirects redirects is an error. Errors keep their cause chain and name the host, but no error in
// the chain contains a query string, fragment, userinfo or header value. The
// timeout covers reading the body: close it to release the request.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("httpx: nil request")
	}
	if req.URL == nil {
		closeBody(req)
		return nil, errors.New("httpx: nil url")
	}
	if err := c.check(req); err != nil {
		closeBody(req)
		return nil, err
	}
	ctx, cancel := context.WithTimeout(req.Context(), c.timeout)
	hops := &hopLog{}
	resp, err := c.hc.Do(req.WithContext(withHops(ctx, hops)))
	if err != nil {
		err = sanitize(ctx, req, hops, err) // before cancel: it reads ctx.Err
		cancel()
		return nil, err
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// closeBody closes req.Body, if any, on a rejection that happens before
// net/http takes ownership of it. A close error is irrelevant: the request
// already failed.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// check enforces the scheme and the allowlist, or the pin of a NewPinned
// client, on one hop.
func (c *Client) check(req *http.Request) error {
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("%w: %s", ErrInsecureScheme, req.URL.Host)
	}
	// An opaque URL makes net/http write the request line in absolute
	// form from Opaque ("GET https://other/x"), whose authority a front end
	// honours over Host: the dialled, allowlisted host would not be the
	// effective target. Opaque is never echoed: it may carry a query.
	if req.URL.Opaque != "" {
		return fmt.Errorf("%w: %s (opaque url)", ErrDomainNotAllowed, req.URL.Host)
	}
	if c.pin != nil {
		return c.pin.check(req)
	}
	if !c.allow.Allows(req.URL.Host) {
		return fmt.Errorf("%w: %s", ErrDomainNotAllowed, req.URL.Host)
	}
	if req.Host != "" && req.Host != req.URL.Host && !c.allow.Allows(req.Host) {
		return fmt.Errorf("%w: %s (host header)", ErrDomainNotAllowed, req.Host)
	}
	return nil
}

// guard is the RoundTripper every hop goes through: it refuses a hop the
// allowlist forbids before the transport can dial, and records the hop so
// sanitize knows which URL parts must not appear in an error.
type guard struct {
	c    *Client
	next http.RoundTripper
}

func (g guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if h, ok := req.Context().Value(hopsKey{}).(*hopLog); ok {
		h.add(req)
	}
	if err := g.c.check(req); err != nil {
		// The RoundTripper contract: always close the body, even on error.
		// On a 307/308 redirect this is the body net/http replayed through
		// req.GetBody, which nobody else closes.
		closeBody(req)
		return nil, err
	}
	resp, err := g.next.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("round trip: %w", err)
	}
	return resp, nil
}

// cancelBody releases the request's timeout context when the body is closed.
type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	defer b.cancel()
	if err := b.ReadCloser.Close(); err != nil {
		return fmt.Errorf("httpx: close body: %w", err)
	}
	return nil
}
