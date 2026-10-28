package httpx

import (
	"fmt"
	"net"
	"strings"
)

// defaultHTTPSPort is the only port Allows accepts.
const defaultHTTPSPort = "443"

// Allowlist is a parsed set of host patterns. The zero value allows nothing.
type Allowlist struct {
	exact    map[string]struct{} // lowercased hosts
	suffixes []string            // ".example.com" for "*.example.com"
}

// publicSuffixes are multi-label public suffixes refused as allowlist
// entries, exact or after "*.". It is a small built-in guard, not the full
// public suffix list (no dependency): single-label suffixes ("com", "fr")
// are refused by a separate rule, and these cover the common second-level
// registries.
var publicSuffixes = map[string]struct{}{
	"co.uk": {}, "org.uk": {}, "gov.uk": {}, "ac.uk": {}, "me.uk": {}, "net.uk": {},
	"ltd.uk": {}, "plc.uk": {}, "nhs.uk": {}, "police.uk": {},
	"com.au": {}, "net.au": {}, "org.au": {}, "edu.au": {}, "gov.au": {},
	"co.nz": {}, "org.nz": {}, "net.nz": {}, "govt.nz": {},
	"co.jp": {}, "ne.jp": {}, "or.jp": {}, "ac.jp": {}, "go.jp": {},
	"com.br": {}, "net.br": {}, "org.br": {}, "gov.br": {},
	"com.cn": {}, "net.cn": {}, "org.cn": {}, "gov.cn": {},
	"gouv.fr": {}, "asso.fr": {}, "nom.fr": {}, "com.fr": {}, "tm.fr": {}, "presse.fr": {},
	"co.za": {}, "co.in": {}, "co.kr": {}, "com.mx": {}, "com.tr": {},
	"com.sg": {}, "com.hk": {}, "com.tw": {}, "com.ar": {}, "co.il": {},
}

// ParseAllowlist accepts one or more patterns, each either a bare host
// ("api.example.com") or "*." followed by a bare host. Refused (wraps
// ErrInvalidAllowlist): empty list, empty entry, scheme, path, port,
// userinfo, query, fragment, backslash, whitespace or control character,
// non-ASCII byte, any other "*", leading or trailing ".", "..", and, exact
// or after "*.", a single-label host ("com", "*.fr", "localhost") or a
// built-in multi-label public suffix ("co.uk", "*.gouv.fr"), compared
// case-insensitively. "*.example.co.uk" and "*.impots.gouv.fr" stay valid.
// This is the single source of truth for connector.Info.AllowedDomains.
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
		if _, ps := publicSuffixes[host]; ps || !strings.Contains(host, ".") {
			return Allowlist{}, fmt.Errorf("%w: entry %q is a public suffix", ErrInvalidAllowlist, p)
		}
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

// Allows reports whether host matches. host may carry the default HTTPS
// port (":443"); any other port, an empty one or a zero-padded one
// (":0443") never matches, so a connector cannot reach another service on
// an allowed host. Comparison is ASCII case-insensitive. "example.com" matches only
// example.com. "*.example.com" matches any host ending in ".example.com"
// with at least one more label, but not example.com itself. A trailing dot,
// an empty host, IP literals that are not listed and non-ASCII hosts never
// match.
func (a Allowlist) Allows(host string) bool {
	if strings.Contains(host, ":") {
		h, port, err := net.SplitHostPort(host)
		if err != nil || port != defaultHTTPSPort {
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
