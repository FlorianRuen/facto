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

// sharedHostingSuffixes are private suffixes under which unrelated tenants
// get sibling subdomains: allowing one of them, exact or after "*.", would
// allow every tenant. One tenant's host ("myproject.github.io") or a
// wildcard below it ("*.myproject.github.io") stays valid.
var sharedHostingSuffixes = map[string]struct{}{
	"github.io": {}, "pages.dev": {}, "netlify.app": {}, "vercel.app": {},
	"herokuapp.com": {}, "appspot.com": {}, "blogspot.com": {},
	"cloudfront.net": {}, "amazonaws.com": {}, "azurewebsites.net": {},
	"web.app": {}, "firebaseapp.com": {},
	// Object storage and edge/PaaS hosting.
	"s3.amazonaws.com": {}, "blob.core.windows.net": {}, "r2.dev": {},
	"workers.dev": {}, "storage.googleapis.com": {}, "googleusercontent.com": {},
	"onrender.com": {}, "fly.dev": {},
}

// sharedHosting reports whether host (lowercased) is a shared-hosting
// suffix: one of sharedHostingSuffixes, or an Amazon S3 regional endpoint
// "s3.<region>.amazonaws.com", "s3-website.<region>.amazonaws.com" or
// "s3.dualstack.<region>.amazonaws.com" for any region label.
func sharedHosting(host string) bool {
	if _, ok := sharedHostingSuffixes[host]; ok {
		return true
	}
	rest, ok := strings.CutSuffix(host, ".amazonaws.com")
	if !ok {
		return false
	}
	for _, prefix := range []string{"s3.dualstack.", "s3-website.", "s3."} {
		if region, ok := strings.CutPrefix(rest, prefix); ok && region != "" && !strings.Contains(region, ".") {
			return true
		}
	}
	return false
}

// awsWildcardRefused reports whether a wildcard over base (lowercased) is
// refused because base is below amazonaws.com, where AWS keeps adding
// multi-tenant endpoints (s3-<region>, s3-website-<region>, s3-fips,
// s3-accesspoint, execute-api, elb…). The only exception is a base that is
// one tenant label directly below a known shared endpoint other than
// amazonaws.com itself ("mybucket.s3.eu-west-3.amazonaws.com").
func awsWildcardRefused(base string) bool {
	if !strings.HasSuffix(base, ".amazonaws.com") {
		return false
	}
	_, parent, _ := strings.Cut(base, ".")
	return parent == "amazonaws.com" || !sharedHosting(parent)
}

// ParseAllowlist accepts one or more patterns, each either a bare host
// ("api.example.com") or "*." followed by a bare host. Refused (wraps
// ErrInvalidAllowlist): empty list, empty entry, scheme, path, port,
// userinfo, query, fragment, backslash, whitespace or control character,
// non-ASCII byte, any other "*", leading or trailing ".", "..", and, exact
// or after "*.", a single-label host ("com", "*.fr", "localhost") or a
// built-in multi-label public suffix ("co.uk", "*.gouv.fr") or shared-hosting
// suffix, compared case-insensitively. The shared-hosting suffixes are
// github.io, pages.dev, netlify.app, vercel.app, herokuapp.com, appspot.com,
// blogspot.com, cloudfront.net, amazonaws.com, azurewebsites.net, web.app,
// firebaseapp.com, and the object-storage and edge hosts s3.amazonaws.com,
// s3.<region>.amazonaws.com (any region label, also s3-website.<region> and
// s3.dualstack.<region>), blob.core.windows.net, r2.dev, workers.dev,
// storage.googleapis.com, googleusercontent.com, onrender.com and fly.dev.
// "*.example.co.uk", "*.impots.gouv.fr", "myproject.github.io",
// "*.myproject.github.io" and "mybucket.s3.eu-west-3.amazonaws.com" stay
// valid. A wildcard below amazonaws.com is refused too ("*.s3-eu-west-3…",
// "*.execute-api.<region>…", "*.<region>.elb…"), unless its base is one
// tenant directly below one of the S3 suffixes above
// ("*.mybucket.s3.eu-west-3.amazonaws.com"); an exact tenant host
// ("abc123.execute-api.eu-west-3.amazonaws.com") stays valid.
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
		if sharedHosting(host) {
			return Allowlist{}, fmt.Errorf("%w: entry %q is a shared-hosting suffix", ErrInvalidAllowlist, p)
		}
		if wildcard && awsWildcardRefused(host) {
			return Allowlist{}, fmt.Errorf("%w: entry %q is a wildcard below amazonaws.com", ErrInvalidAllowlist, p)
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
