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
	// schemeRe matches a URL scheme followed by ":" at the start of a
	// string (RFC 3986 scheme syntax).
	schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
	// invalidPortRe matches the port quoted by net/url's "invalid port"
	// error, which is part of the password when the userinfo holds an
	// unencoded "/", "?" or "#".
	invalidPortRe = regexp.MustCompile(`\binvalid port "(?:[^"\\\r\n]|\\.)*"`)
	// reQuotedPortRe is invalidPortRe for an error re-quoted with %q or JSON
	// (`invalid port \":pa\" after host`): it runs to the last escaped quote
	// followed by " after host" on the line, over-masking rather than
	// stopping inside a password.
	reQuotedPortRe = regexp.MustCompile(`\binvalid port (\\+)"[^\r\n]*\\+" after host`)
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

// parseVerb introduces the raw URL quoted by a net/url parse error
// (url.Error with Op "parse").
const parseVerb = "parse "

// maskParseErrors masks the raw URL that a net/url parse error quotes
// (`parse "<raw>": <reason>`). The URL patterns cannot be trusted there: a
// userinfo holding an unencoded "/", "?" or "#" ends the authority inside the
// password, and url.Parse cuts the quoted URL at "#". Only an argument that
// looks like a URL (see urlLooking) is touched, so config or file parse
// errors survive. Everything up to the last "@" becomes "***@" (the scheme
// goes too, so the URL patterns leave the rest alone), the query and
// fragment of what remains become "?***", and an argument without "@" is
// replaced whole: `parse "***"`. The port quoted by an "invalid port" reason
// is masked as well. The same applies when the error was re-quoted with %q
// or JSON at any depth, where the delimiting quotes are escaped
// (`parse \"…\": …`).
func maskParseErrors(s string) string {
	if !strings.Contains(s, parseVerb) {
		return s
	}
	var b strings.Builder
	done := 0 // s[:done] is already written to b
	for from := 0; ; {
		j := strings.Index(s[from:], parseVerb)
		if j < 0 {
			break
		}
		start := from + j
		from = start + len(parseVerb)
		if start > 0 && isWordByte(s[start-1]) {
			continue
		}
		k := 0 // escaping depth: the delimiter is k backslashes and a quote
		for from+k < len(s) && s[from+k] == '\\' {
			k++
		}
		if from+k >= len(s) || s[from+k] != '"' {
			continue
		}
		delim := s[from : from+k+1]
		argStart := from + k + 1
		lineEnd := len(s)
		if e := strings.IndexAny(s[argStart:], "\r\n"); e >= 0 {
			lineEnd = argStart + e
		}
		line := s[argStart:lineEnd]
		first, last := parseArgEnds(line, delim, k)
		if first < 0 {
			continue
		}
		if !urlLooking(line[:first]) {
			from = argStart + first + len(delim)
			continue
		}
		// A password may hold quotes: with an "@" in sight, run to the last
		// closing delimiter of the line, which can only mask more.
		end := first
		if strings.Contains(line[:last], "@") {
			end = last
		}
		b.WriteString(s[done:argStart])
		b.WriteString(maskParseArg(line[:end]))
		from = argStart + end
		done = from
	}
	if done > 0 {
		b.WriteString(s[done:])
		s = b.String()
	}
	s = invalidPortRe.ReplaceAllLiteralString(s, `invalid port "`+Mask+`"`)
	return reQuotedPortRe.ReplaceAllString(s, `invalid port ${1}"`+Mask+`${1}" after host`)
}

// parseArgEnds returns the offsets in line of the first and last closing
// delimiters of a quoted parse argument, or -1, -1. A closing delimiter is
// delim followed by ": ", by the end of the line or, when the argument is
// re-quoted (k > 0), by a less escaped quote that closes the outer string.
func parseArgEnds(line, delim string, k int) (first, last int) {
	first, last = -1, -1
	for i := 0; ; {
		j := strings.Index(line[i:], delim)
		if j < 0 {
			return first, last
		}
		p := i + j
		rest := line[p+len(delim):]
		if rest == "" || strings.HasPrefix(rest, ": ") || k > 0 && closesOuter(rest, k) {
			if first < 0 {
				first = p
			}
			last = p
		}
		i = p + 1
	}
}

// closesOuter reports whether rest starts with fewer than k backslashes and a
// quote, which closes a string enclosing the re-quoted argument.
func closesOuter(rest string, k int) bool {
	n := 0
	for n < len(rest) && rest[n] == '\\' {
		n++
	}
	return n < k && n < len(rest) && rest[n] == '"'
}

// urlLooking reports whether a quoted parse argument looks like a URL: it
// contains "://" or starts with a scheme and ":".
func urlLooking(arg string) bool {
	return strings.Contains(arg, "://") || schemeRe.MatchString(arg)
}

// maskParseArg masks a URL-looking parse argument: "***@" plus what follows
// its last "@" with the query and fragment masked, or "***" without "@".
func maskParseArg(arg string) string {
	at := strings.LastIndexByte(arg, '@')
	if at < 0 {
		return Mask
	}
	tail := arg[at+1:]
	if q := strings.IndexAny(tail, "?#"); q >= 0 {
		tail = tail[:q] + "?" + Mask
	}
	return Mask + "@" + tail
}

// isWordByte reports whether c is a regexp word character ([0-9A-Za-z_]).
func isWordByte(c byte) bool { return isAlnum(c) || c == '_' }
