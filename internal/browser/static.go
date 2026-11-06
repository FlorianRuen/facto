package browser

import (
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
// more:
//   - no other path of the host, no other method (no POST: nothing typed
//     on the page can be sent there), no WebSocket;
//   - never a document (Navigate refuses it; a top-level or frame document
//     load is blocked), so no page of the shared host runs as the login
//     page or receives a typed secret;
//   - cookies of the host are never exported (Cookies keeps the domain
//     allowlist), and httpx never sees static entries: connectors' HTTP
//     clients stay on AllowedDomains.
// The host is added to the --host-resolver-rules exclusions (paths are
// never put in flags).

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

// allows reports whether a subresource request may go to a static entry:
// https, method GET or HEAD, no userinfo, port 443 (or none), host equal
// to an entry's, and an escaped path under its prefix that no decoding
// can move out of it (no "..", "." segments, no escaped "/", "\" or ".").
func (s Static) allows(raw, method string) bool {
	if len(s.entries) == 0 || !slices.Contains(readMethods, method) || hasUnsafeChar(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return false
	}
	if port := u.Port(); (port != "" && port != defaultHTTPSPort) || strings.HasSuffix(u.Host, ":") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	p := u.EscapedPath()
	low := strings.ToLower(p)
	if strings.Contains(low, "%2f") || strings.Contains(low, "%5c") || strings.Contains(low, "%2e") {
		return false
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	for _, e := range s.entries {
		if host == e.host && strings.HasPrefix(p, e.prefix) {
			return true
		}
	}
	return false
}
