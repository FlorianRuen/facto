package browser

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// Path-scoped static allowlist (J2; ADR 0008 A11 "per-connector CDN").
//
// A supplier's JavaScript app may be served from shared storage
// (https://storage.googleapis.com/<bucket>/…) that httpx.ParseAllowlist
// refuses as a whole host, on purpose: anyone can publish there. A static
// entry "https://<host>/<prefix>/" lets the login page, its frames and
// workers GET or HEAD that exact host under that path prefix, and nothing
// more.
//
// Chrome itself never reaches a static host (SEC-J2-1): the host stays
// ~NOTFOUND in --host-resolver-rules like any other name. Fetch pauses a
// request before name resolution; an allowed one is downloaded on facto's
// side, through the entry's StaticGet (httpx.NewPinned: exact host, path
// prefix on every redirect hop, internal/browser/staticfetch), and handed
// to Chrome with Fetch.fulfillRequest. So:
//   - no other path of the host, no other method (no POST: nothing typed
//     on the page can be sent there), and no WebSocket, which Fetch never
//     sees but which cannot resolve the host either;
//   - never a document (Navigate refuses it; a top-level or frame document
//     load is blocked), so no page of the shared host runs as the login
//     page or receives a typed secret;
//   - only a few request headers are forwarded (staticRequestHeaders: no
//     cookie, no authorization, nothing the page chose freely) and a few
//     response headers handed back (staticResponseHeaders: no Set-Cookie);
//   - cookies of the host are never exported (Cookies keeps the domain
//     allowlist), and connectors' HTTP clients stay on AllowedDomains.

// StaticResponse is a facto-side download handed to Chrome for a paused
// static request.
type StaticResponse struct {
	Status int
	Header map[string][]string
	Body   []byte
}

// StaticGet downloads rawURL with method GET or HEAD and the given request
// headers, on facto's side. It fails on a body over MaxStaticBody.
type StaticGet func(ctx context.Context, method, rawURL string, header map[string][]string) (StaticResponse, error)

// StaticClients builds the StaticGet of one static entry: host is a
// lowercase host name, prefix an escaped path ending in "/". In production
// it is internal/browser/staticfetch.Pinned (httpx.NewPinned).
type StaticClients func(host, prefix string) (StaticGet, error)

// MaxStaticBody caps one facto-side static download: its base64 form must
// fit one CDP message (MaxMessageBytes).
const MaxStaticBody = 8 << 20

// ErrInvalidStatic reports a static entry ParseStatic refuses.
var ErrInvalidStatic = errors.New("browser: invalid static allowlist entry")

// staticEntry is one parsed entry: lowercase host, escaped path prefix
// ending in "/".
type staticEntry struct {
	host, prefix string
}

// Static is a parsed static allowlist.
type Static struct {
	entries []staticEntry
}

// ParseStatic validates entries: "https://<host>/<seg>/…/" exactly, host a
// DNS name of at least two labels ([a-z0-9-], flag-safe, not an IP literal
// nor a loopback name, no wildcard, no port), a path of at least one
// segment ending in "/", segments of [A-Za-z0-9._~-] other than "." and
// "..", no query, fragment or userinfo.
func ParseStatic(entries []string) (Static, error) {
	var s Static
	for _, raw := range entries {
		e, err := parseStaticEntry(raw)
		if err != nil {
			return Static{}, err
		}
		s.entries = append(s.entries, e)
	}
	return s, nil
}

func parseStaticEntry(raw string) (staticEntry, error) {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrInvalidStatic, why) }
	if raw == "" || hasUnsafeChar(raw) {
		return staticEntry{}, bad("empty, control character, space or backslash")
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return staticEntry{}, bad("not a URL")
	case u.Scheme != "https":
		return staticEntry{}, bad("not https")
	case u.User != nil, u.Opaque != "":
		return staticEntry{}, bad("userinfo or opaque URL")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "?#"):
		return staticEntry{}, bad("query or fragment")
	case u.Port() != "" || strings.HasSuffix(u.Host, ":"):
		return staticEntry{}, bad("port")
	}
	host := strings.ToLower(u.Hostname())
	if strings.HasPrefix(host, "*") {
		return staticEntry{}, bad("wildcard host")
	}
	if _, err := netip.ParseAddr(host); err == nil || strings.HasPrefix(u.Host, "[") {
		return staticEntry{}, bad("IP literal")
	}
	if err := checkFlagDomain(host); err != nil || !strings.Contains(host, ".") {
		return staticEntry{}, bad("host")
	}
	p := u.EscapedPath()
	if p != u.Path || !strings.HasSuffix(p, "/") || len(p) < 3 {
		return staticEntry{}, bad("path must be /<segment>/…/ without escapes")
	}
	for seg := range strings.SplitSeq(p[1:len(p)-1], "/") {
		if seg == "" || seg == "." || seg == ".." || !safeSegment(seg) {
			return staticEntry{}, bad("path segment")
		}
	}
	return staticEntry{host: host, prefix: p}, nil
}

func safeSegment(seg string) bool {
	for i := range len(seg) {
		c := seg[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' && c != '~' {
			return false
		}
	}
	return true
}

// Hosts returns the distinct hosts, sorted.
func (s Static) Hosts() []string {
	var out []string
	for _, e := range s.entries {
		out = append(out, e.host)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// readMethods are the only methods a static entry allows.
var readMethods = []string{"GET", "HEAD"}

// match returns the index of the entry raw may go to, or -1:
// https, method GET or HEAD, no userinfo, port 443 (or none), host equal
// to an entry's, and a path under its prefix with no percent-encoding and
// no empty, "." or ".." segment (what the pinned client accepts).
func (s Static) match(raw, method string) int {
	if len(s.entries) == 0 || !slices.Contains(readMethods, method) || hasUnsafeChar(raw) {
		return -1
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return -1
	}
	if port := u.Port(); (port != "" && port != defaultHTTPSPort) || strings.HasSuffix(u.Host, ":") {
		return -1
	}
	host := strings.ToLower(u.Hostname())
	p := u.EscapedPath()
	// Same rule as the pinned client that downloads it (httpx canonical
	// path): no percent-encoding at all, no empty, "." or ".." segment.
	if strings.Contains(p, "%") || strings.Contains(p, "//") {
		return -1
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." {
			return -1
		}
	}
	for i, e := range s.entries {
		if host == e.host && strings.HasPrefix(p, e.prefix) {
			return i
		}
	}
	return -1
}

// staticGets builds one StaticGet per entry of s.
func staticGets(s Static, clients StaticClients) ([]StaticGet, error) {
	if len(s.entries) == 0 {
		return nil, nil
	}
	if clients == nil {
		return nil, fmt.Errorf("%w: no facto-side static client", ErrInvalidStatic)
	}
	out := make([]StaticGet, 0, len(s.entries))
	for _, e := range s.entries {
		g, err := clients(e.host, e.prefix)
		if err != nil {
			return nil, fmt.Errorf("%w: static client: %w", ErrInvalidStatic, err)
		}
		if g == nil {
			return nil, fmt.Errorf("%w: nil static client", ErrInvalidStatic)
		}
		out = append(out, g)
	}
	return out, nil
}
