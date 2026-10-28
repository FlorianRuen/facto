package httpx

import (
	"fmt"
	"net"
	"strings"
)

// Allowlist is a parsed set of host patterns. The zero value allows nothing.
type Allowlist struct {
	exact    map[string]struct{} // lowercased hosts
	suffixes []string            // ".example.com" for "*.example.com"
}

// ParseAllowlist accepts one or more patterns, each either a bare host
// ("api.example.com") or "*." followed by a bare host. Refused (wraps
// ErrInvalidAllowlist): empty list, empty entry, scheme, path, port,
// userinfo, query, fragment, backslash, whitespace or control character,
// non-ASCII byte, any other "*", leading or trailing ".", "..". This is the
// single source of truth for connector.Info.AllowedDomains.
func ParseAllowlist(patterns []string) (Allowlist, error) {
	if len(patterns) == 0 {
		return Allowlist{}, fmt.Errorf("%w: empty list", ErrInvalidAllowlist)
	}
	a := Allowlist{exact: map[string]struct{}{}}
	for _, p := range patterns {
		host, wildcard := strings.CutPrefix(p, "*.")
		if !validHost(host) {
			return Allowlist{}, fmt.Errorf("%w: entry %q", ErrInvalidAllowlist, p)
		}
		host = strings.ToLower(host)
		if wildcard {
			a.suffixes = append(a.suffixes, "."+host)
		} else {
			a.exact[host] = struct{}{}
		}
	}
	return a, nil
}

// validHost reports whether h is a non-empty bare ASCII host name or IPv4
// literal: no scheme, port, path, userinfo, query, wildcard, whitespace or
// control character, no empty label at either end or in the middle.
func validHost(h string) bool {
	if h == "" || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return false
	}
	for i := range len(h) {
		c := h[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`*/:@?#\`, c) >= 0 {
			return false
		}
	}
	return true
}

// Allows reports whether host (optionally "host:port"; any port) matches.
// Comparison is ASCII case-insensitive. "example.com" matches only
// example.com. "*.example.com" matches any host ending in ".example.com"
// with at least one more label, but not example.com itself. A trailing dot,
// an empty host, IP literals that are not listed and non-ASCII hosts never
// match.
func (a Allowlist) Allows(host string) bool {
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err != nil {
			return false
		}
		host = h
	}
	if !validHost(host) {
		return false
	}
	host = strings.ToLower(host)
	if _, ok := a.exact[host]; ok {
		return true
	}
	for _, s := range a.suffixes {
		if len(host) > len(s) && strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}
