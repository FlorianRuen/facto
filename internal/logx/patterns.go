package logx

import (
	"regexp"
	"strings"
)

var (
	// jwtRe matches a JWT: "eyJ" header, payload and (possibly empty)
	// signature in base64url, separated by dots.
	jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`)
	// urlRe matches a URL of any scheme (RFC 3986: a letter, then letters,
	// digits, "+", "." or "-") followed by "://", up to whitespace or a
	// quoting character.
	urlRe = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s"'<>` + "`" + `]+`)
	// userinfoRe matches a scheme and everything up to the last "@" before the
	// end of the authority ("/", "?", "#" or a line break). Unlike urlRe it does
	// not stop at spaces or quotes: url.Parse quotes the raw URL in its error
	// precisely when the userinfo holds such characters. It may over-mask text
	// between a scheme and a later "@", which is the safe direction.
	userinfoRe = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/?#\r\n]*@`)
	// parseArgRe matches the raw URL that a net/url error quotes after
	// "parse" (url.Error with Op "parse"), up to the last double quote of
	// the line followed by ": " or the end of the line. It is greedy on
	// purpose: the URL may hold escaped or unescaped quotes, and running
	// past the real end only masks more.
	parseArgRe = regexp.MustCompile(`(?m)\bparse "([^\r\n]*)"(: |$)`)
	// invalidPortRe matches the port quoted by net/url's "invalid port"
	// error, which is part of the password when the userinfo holds an
	// unencoded "/", "?" or "#".
	invalidPortRe = regexp.MustCompile(`\binvalid port "(?:[^"\\\r\n]|\\.)*"`)
)

// minTokenRun is the number of consecutive alphanumerics that make a run of
// base64 characters look like a token.
const minTokenRun = 16

// Clean masks token patterns in s, in this order: the raw URL quoted by
// net/url parse errors (see maskParseErrors), JWTs, long base64 runs,
// then the userinfo of URLs of any scheme (removed) and query/fragment (replaced by "?***").
// File names, slugs, UUIDs, paths, hex digests and plain words survive.
func Clean(s string) string {
	s = maskParseErrors(s)
	s = jwtRe.ReplaceAllLiteralString(s, Mask)
	s = maskBase64(s)
	s = userinfoRe.ReplaceAllString(s, "$1")
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

// maskParseErrors masks the raw URL that a net/url parse error quotes
// (`parse "<raw>": <reason>`). The URL patterns cannot be trusted there: a
// userinfo holding an unencoded "/", "?" or "#" ends the authority inside the
// password, and url.Parse cuts the quoted URL at "#". Everything up to the
// last "@" becomes "***@" (the scheme goes too, so the URL patterns leave the
// rest alone), the query and fragment of what remains become "?***", and an
// argument without "@" is replaced whole: `parse "***"`. The port quoted by
// an "invalid port" reason is masked as well.
func maskParseErrors(s string) string {
	if !strings.Contains(s, `parse "`) {
		return s
	}
	s = parseArgRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := parseArgRe.FindStringSubmatch(m)
		arg, end := sub[1], sub[2]
		masked := Mask
		if at := strings.LastIndexByte(arg, '@'); at >= 0 {
			tail := arg[at+1:]
			if q := strings.IndexAny(tail, "?#"); q >= 0 {
				tail = tail[:q] + "?" + Mask
			}
			masked = Mask + "@" + tail
		}
		return `parse "` + masked + `"` + end
	})
	return invalidPortRe.ReplaceAllLiteralString(s, `invalid port "`+Mask+`"`)
}
