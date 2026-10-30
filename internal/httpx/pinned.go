package httpx

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// pin is the policy of a NewPinned client: one exact host on the default
// HTTPS port and one path prefix.
type pin struct {
	host   string // lowercase bare host name
	prefix string // "/a/b/": clean, starts and ends with "/"
}

// NewPinned builds a client like New that may only reach https://host/...
// on port 443, under pathPrefix. It exists for downloads from shared
// storage hosts (the Chrome for Testing archives live on a host that
// ParseAllowlist refuses on purpose, ADR 0008): the path prefix is what
// narrows the host to one tenant. ParseAllowlist is unchanged.
//
// host must be a lowercase bare host name with at least two labels: no
// wildcard, port, userinfo, IP literal, trailing dot or non-ASCII byte.
// pathPrefix must start and end with "/", be longer than "/", and be in
// canonical form (no "." or ".." segment, no empty segment, no
// percent-encoding, backslash, "*", "?" or "#"). Anything else wraps
// ErrInvalidAllowlist.
//
// On the first request and on every redirect hop, before any connection:
// a scheme other than https wraps ErrInsecureScheme; a host that is not
// byte for byte host (case and trailing dot included), a port other than
// 443, userinfo, an opaque URL, or a Host header naming another host wraps
// ErrDomainNotAllowed; a path that is not under pathPrefix or not in
// canonical form (dot segments, double slashes, any percent-encoding such
// as %2e%2e or %2f, a backslash) wraps ErrPathNotAllowed. Errors never
// carry the path, query or fragment.
func NewPinned(host, pathPrefix string, opts Options) (*Client, error) {
	if !validHost(host) || host != strings.ToLower(host) || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return nil, fmt.Errorf("%w: pinned host %q", ErrInvalidAllowlist, host)
	}
	if !canonicalPrefix(pathPrefix) {
		return nil, fmt.Errorf("%w: pinned path prefix %q", ErrInvalidAllowlist, pathPrefix)
	}
	return newClient(Allowlist{}, &pin{host: host, prefix: pathPrefix}, opts)
}

// canonicalPrefix reports whether p is a usable pinned path prefix.
func canonicalPrefix(p string) bool {
	if len(p) < 3 || p[0] != '/' || p[len(p)-1] != '/' {
		return false
	}
	return canonicalPath(p)
}

// canonicalPath reports whether p is an absolute, printable ASCII path
// with no encoding, no backslash, no wildcard, and no ".", ".." or empty
// segment (a trailing "/" is allowed).
func canonicalPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	for i := range len(p) {
		c := p[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`%\*?#`, c) >= 0 {
			return false
		}
	}
	trimmed := strings.TrimSuffix(p, "/")
	return trimmed == "" || path.Clean(trimmed) == trimmed
}

// allowsHost reports whether h (a URL host or Host header) is exactly the
// pinned host, optionally followed by ":443".
func (p *pin) allowsHost(h string) bool {
	if rest, ok := strings.CutPrefix(h, p.host); ok {
		return rest == "" || rest == ":"+defaultHTTPSPort
	}
	return false
}

// allowsPath reports whether u's path is canonical and under the prefix.
// The escaped form is checked too: any percent-encoding is refused, so
// "%2e%2e" or "%2f" cannot hide a segment from the prefix check.
func (p *pin) allowsPath(u *url.URL) bool {
	if u.RawPath != "" || u.EscapedPath() != u.Path {
		return false
	}
	return canonicalPath(u.Path) && strings.HasPrefix(u.Path, p.prefix)
}

// check enforces the pin on one hop (the scheme and opaque checks already
// ran in Client.check).
func (p *pin) check(req *http.Request) error {
	if req.URL.User != nil {
		return fmt.Errorf("%w: %s (credentials in the url)", ErrDomainNotAllowed, req.URL.Host)
	}
	if !p.allowsHost(req.URL.Host) {
		return fmt.Errorf("%w: %s", ErrDomainNotAllowed, req.URL.Host)
	}
	if req.Host != "" && req.Host != req.URL.Host && !p.allowsHost(req.Host) {
		return fmt.Errorf("%w: %s (host header)", ErrDomainNotAllowed, req.Host)
	}
	if !p.allowsPath(req.URL) {
		return fmt.Errorf("%w: %s (outside the pinned path prefix)", ErrPathNotAllowed, req.URL.Host)
	}
	return nil
}
