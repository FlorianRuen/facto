package logx

import (
	"regexp"
	"strings"
)

var (
	// jwtRe matches a JWT: "eyJ" header, payload and (possibly empty)
	// signature in base64url, separated by dots.
	jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`)
	// urlRe matches an http(s) URL up to whitespace or a quoting character.
	urlRe = regexp.MustCompile(`(?i)https?://[^\s"'<>` + "`" + `]+`)
)

// minTokenRun is the number of consecutive alphanumerics that make a run of
// base64 characters look like a token.
const minTokenRun = 16

// Clean masks token patterns in s, in this order: JWTs, long base64 runs,
// then URL userinfo (removed) and query/fragment (replaced by "?***").
// File names, slugs, UUIDs, paths, hex digests and plain words survive.
func Clean(s string) string {
	s = jwtRe.ReplaceAllLiteralString(s, Mask)
	s = maskBase64(s)
	return urlRe.ReplaceAllStringFunc(s, cleanURL)
}

// isB64 reports whether c belongs to the standard or URL-safe base64
// alphabet (padding included).
func isB64(c byte) bool {
	return isAlnum(c) || c == '+' || c == '/' || c == '=' || c == '_' || c == '-'
}

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// maskBase64 replaces every maximal run of base64 characters that holds a
// token-like stretch (see tokenLike) by Mask.
func maskBase64(s string) string {
	var b strings.Builder
	last := 0 // s[:last] is already in b
	for i := 0; i < len(s); {
		if !isB64(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isB64(s[j]) {
			j++
		}
		if tokenLike(s[i:j]) {
			b.WriteString(s[last:i])
			b.WriteString(Mask)
			last = j
		}
		i = j
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// tokenLike reports whether run contains at least minTokenRun consecutive
// alphanumerics that are neither all lowercase hex (digests, numeric ids)
// nor all lowercase letters (words).
func tokenLike(run string) bool {
	for i := 0; i < len(run); {
		if !isAlnum(run[i]) {
			i++
			continue
		}
		j, hex, lower := i, true, true
		for j < len(run) && isAlnum(run[j]) {
			c := run[j]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				hex = false
			}
			if c < 'a' || c > 'z' {
				lower = false
			}
			j++
		}
		if j-i >= minTokenRun && !hex && !lower {
			return true
		}
		i = j
	}
	return false
}

// cleanURL removes the userinfo of u and replaces everything from the first
// "?" or "#" by "?***".
func cleanURL(u string) string {
	sep := strings.Index(u, "://") + len("://")
	scheme, rest := u[:sep], u[sep:]
	authEnd := strings.IndexAny(rest, "/?#")
	if authEnd < 0 {
		authEnd = len(rest)
	}
	if at := strings.LastIndexByte(rest[:authEnd], '@'); at >= 0 {
		rest = rest[at+1:]
	}
	if q := strings.IndexAny(rest, "?#"); q >= 0 {
		rest = rest[:q] + "?" + Mask
	}
	return scheme + rest
}
