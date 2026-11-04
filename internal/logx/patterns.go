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
)

// minTokenRun is the number of consecutive alphanumerics that make a run of
// base64 characters look like a token.
const minTokenRun = 16

// Clean masks token patterns in s, in this order: the raw URL quoted by
// net/url parse errors (see maskParseErrors), JWTs, long base64 runs,
// then the userinfo of URLs of any scheme (removed) and query/fragment (replaced by "?***"),
// then the value following a sensitive key or an authorization scheme in
// free text (see maskKeyValues). When that last step changed a text holding
// a URL, the URL patterns and it run once more: a mask may have swallowed
// the "/", "?" or "#" that ended an authority, letting the userinfo pattern
// reach a later "@", and a second Clean must change nothing.
// File names, slugs, UUIDs, paths, hex digests and plain words survive.
func Clean(s string) string {
	s = maskParseErrors(s)
	s = jwtRe.ReplaceAllLiteralString(s, Mask)
	s = maskBase64(s)
	s = maskURLs(s)
	out := maskKeyValues(s)
	if out != s && strings.Contains(out, "://") {
		if again := maskURLs(out); again != out {
			out = maskKeyValues(again)
		}
	}
	return out
}

// maskURLs removes the userinfo of URLs of any scheme and replaces their
// query and fragment by "?***".
func maskURLs(s string) string {
	if !strings.Contains(s, "://") { // both URL patterns need it
		return s
	}
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

// maxQuoteDepth bounds the backslash run of a parse argument delimiter that
// is parsed precisely; 31 covers five levels of re-quoting (2^d - 1
// backslashes). A deeper delimiter fails closed (see maskParseLine).
const maxQuoteDepth = 31

// quotedReasons introduce a quoted reason of a net/url error that repeats
// password bytes: the port when the userinfo holds an unencoded "/", "?" or
// "#", the bad escape when it holds a "%", and the bracketed text that
// netip.ParseAddr rejects (`invalid host: ParseAddr("…"): … (at "…")`) when
// the userinfo starts with "[" and the authority ends inside it.
var quotedReasons = []string{"invalid port ", "invalid URL escape ", "ParseAddr(", "(at "}

// maskParseErrors masks the raw URL that a net/url parse error quotes
// (`parse "<raw>": <reason>`). The URL patterns cannot be trusted there: a
// userinfo holding an unencoded "/", "?" or "#" ends the authority inside the
// password, and url.Parse cuts the quoted URL at "#". Only an argument that
// looks like a URL (see maskParseLine) is touched, so config or file parse
// errors survive. Everything up to the last "@" becomes "***@" (the scheme
// goes too, so the URL patterns leave the rest alone), the query and
// fragment of what remains become "?***", and an argument without "@" is
// replaced whole: `parse "***"`. The quoted text of a reason that repeats
// password bytes (see quotedReasons) is masked as well. The same applies when the
// error was re-quoted with %q or JSON at any depth, where the delimiting
// quotes are escaped (`parse \"…\": …`). It runs in time linear in len(s).
func maskParseErrors(s string) string {
	if !strings.Contains(s, parseVerb) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for rest := s; rest != ""; {
		line, sep := rest, ""
		rest = ""
		if n := strings.IndexAny(line, "\r\n"); n >= 0 {
			line, sep, rest = line[:n], line[n:n+1], line[n+1:]
		}
		b.WriteString(maskQuotedReasons(maskParseLine(line)))
		b.WriteString(sep)
	}
	return b.String()
}

// lineScan holds forward-only search caches over one line so that scanning
// every parse token of the line stays linear: each cache answers "next
// occurrence at or after p" for nondecreasing p and only rescans past its
// previous answer.
type lineScan struct {
	s         string
	sep, at   nextCache
	ends      [maxQuoteDepth + 1]nextCache
	lastEnds  [maxQuoteDepth + 1]int
	lastKnown [maxQuoteDepth + 1]bool
}

// nextCache remembers the answer pos of the last query; pos == len(s) means
// none.
type nextCache struct {
	pos   int
	valid bool
}

func (c *nextCache) next(p, n int, find func(from int) int) int {
	if c.valid && c.pos >= p {
		return c.pos
	}
	c.pos, c.valid = find(p), true
	if c.pos < 0 {
		c.pos = n
	}
	return c.pos
}

func (l *lineScan) index(p int, sub string) int {
	if i := strings.Index(l.s[p:], sub); i >= 0 {
		return p + i
	}
	return -1
}

// nextEnd returns the offset of the quote of the first closing delimiter of
// depth k at or after p, or len(s).
func (l *lineScan) nextEnd(p, k int) int {
	return l.ends[k].next(p, len(l.s), func(from int) int {
		for q := from; q < len(l.s); q++ {
			j := strings.IndexByte(l.s[q:], '"')
			if j < 0 {
				return -1
			}
			q += j
			if q-k >= from && isClosing(l.s, q, k) {
				return q
			}
		}
		return -1
	})
}

// lastEnd returns the offset of the quote of the last closing delimiter of
// depth k on the line, or -1, computed once per depth by a backward scan.
func (l *lineScan) lastEnd(k int) int {
	if !l.lastKnown[k] {
		l.lastKnown[k], l.lastEnds[k] = true, -1
		for q := strings.LastIndexByte(l.s, '"'); q >= 0; q = strings.LastIndexByte(l.s[:q], '"') {
			if isClosing(l.s, q, k) {
				l.lastEnds[k] = q
				break
			}
		}
	}
	return l.lastEnds[k]
}

// isClosing reports whether the quote at s[q] closes a parse argument
// delimited by k backslashes and a quote. Its backslash run r must be the
// delimiter's: at depth k a delimiter keeps r ≡ k (mod 2(k+1)), while a quote
// escaped inside the argument gets r ≡ 2k+1. It must not open a quoted
// reason (see quotedReasons), and be followed
// by ": ", the end of the line or, when re-quoted (k > 0), by a less escaped
// quote that closes the outer string.
func isClosing(s string, q, k int) bool {
	r := backslashesBefore(s, q)
	if r < k || (r-k)%(2*(k+1)) != 0 {
		return false
	}
	for _, reason := range quotedReasons {
		if strings.HasSuffix(s[:q-k], reason) {
			return false
		}
	}
	rest := s[q+1:]
	return rest == "" || strings.HasPrefix(rest, ": ") || k > 0 && closesOuter(rest, k)
}

// backslashesBefore returns the length of the run of backslashes ending
// right before s[i].
func backslashesBefore(s string, i int) int {
	n := 0
	for i-n > 0 && s[i-n-1] == '\\' {
		n++
	}
	return n
}

// closesOuter reports whether rest starts with fewer than k backslashes and a
// quote, which closes a string enclosing the re-quoted argument.
func closesOuter(rest string, k int) bool {
	n := 0
	for n < len(rest) && n < k && rest[n] == '\\' {
		n++
	}
	return n < k && n < len(rest) && rest[n] == '"'
}

// maskParseLine masks the URL-looking parse arguments of one line. An
// argument looks like a URL when it contains "://", starts with "//" or
// starts with a scheme and ":". It ends at its first closing delimiter or,
// when an "@" lies before the last closing delimiter of the line and that
// delimiter does not merely close the error's quoted reason (closesReason),
// at that last one (a password may hold quotes, so this can only mask more). A
// URL-looking argument without any closing delimiter (a truncated line), or
// one whose delimiter is deeper than maxQuoteDepth while the rest of the line
// holds "//" or "@", is masked to the end of the line.
func maskParseLine(line string) string {
	if !strings.Contains(line, parseVerb) {
		return line
	}
	l := &lineScan{s: line}
	n := len(line)
	var b strings.Builder
	done := 0 // line[:done] is already written to b
	for from := 0; from < n; {
		start := l.index(from, parseVerb)
		if start < 0 {
			break
		}
		from = start + len(parseVerb)
		k := 0 // escaping depth: the delimiter is k backslashes and a quote
		for from+k < n && line[from+k] == '\\' {
			k++
		}
		if from+k >= n || line[from+k] != '"' {
			continue
		}
		argStart := from + k + 1
		if k > maxQuoteDepth {
			tail := line[argStart:]
			if !strings.Contains(tail, "//") && !strings.Contains(tail, "@") {
				break
			}
			b.WriteString(line[done:argStart])
			b.WriteString(Mask)
			done = n
			break
		}
		first := l.nextEnd(argStart, k)
		argEnd := first - k // the argument is line[argStart:argEnd]
		if first == n {
			argEnd = n
		}
		if !l.urlLooking(argStart, argEnd) {
			continue // a parse token inside this argument is still scanned
		}
		if first < n {
			if last := l.lastEnd(k); last > first && !closesReason(line, first, last) &&
				l.at.next(argStart, n, func(p int) int { return l.index(p, "@") }) < last-k {
				first, argEnd = last, last-k
			}
		}
		b.WriteString(line[done:argStart])
		b.WriteString(maskParseArg(line[argStart:argEnd]))
		done = argEnd
		from = first + 1
	}
	if done == 0 {
		return line
	}
	b.WriteString(line[done:])
	return b.String()
}

// urlLooking reports whether line[i:j] contains "://", starts with "//" or
// starts with a scheme followed by ":".
func (l *lineScan) urlLooking(i, j int) bool {
	arg := l.s[i:j]
	if strings.HasPrefix(arg, "//") || hasScheme(arg) {
		return true
	}
	return l.sep.next(i, len(l.s), func(p int) int { return l.index(p, "://") })+len("://") <= j
}

// hasScheme reports whether s starts with an RFC 3986 scheme and ":".
func hasScheme(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == ':':
			return true
		case isAlnum(c) || c == '+' || c == '.' || c == '-':
		default:
			return false
		}
	}
	return false
}

func isAlpha(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// maskQuotedReasons replaces the quoted text after every quotedReasons entry
// of a line by Mask, at any quoting depth.
func maskQuotedReasons(line string) string {
	for _, reason := range quotedReasons {
		line = maskQuotedReason(line, reason)
	}
	return line
}

// maskQuotedReason replaces the quoted text after every reason of a line by
// Mask. The quote that closes it is the first one whose backslash run is the
// opening delimiter's (see isClosing); without one, the line is masked to its
// end.
func maskQuotedReason(line, reason string) string {
	if !strings.Contains(line, reason) {
		return line
	}
	var b strings.Builder
	done := 0 // line[:done] is already written to b
	for from := 0; ; {
		i := strings.Index(line[from:], reason)
		if i < 0 {
			break
		}
		open, k, ok := quotedAt(line, from+i+len(reason))
		from = open
		if !ok {
			continue
		}
		end := len(line)
		if q := closingQuote(line, open, k); q >= 0 {
			end = q - k
		}
		b.WriteString(line[done:open])
		b.WriteString(Mask)
		done, from = end, end
	}
	if done == 0 {
		return line
	}
	b.WriteString(line[done:])
	return b.String()
}

// quotedAt reports whether line[p:] starts with k backslashes and a quote,
// and returns the offset right after that quote.
func quotedAt(line string, p int) (open, k int, ok bool) {
	for p+k < len(line) && line[p+k] == '\\' {
		k++
	}
	if p+k >= len(line) || line[p+k] != '"' {
		return p + k, k, false
	}
	return p + k + 1, k, true
}

// closingQuote returns the offset of the first quote at or after from whose
// backslash run closes a string opened by k backslashes and a quote (see
// isClosing), or -1.
func closingQuote(line string, from, k int) int {
	for q := from; q < len(line); q++ {
		j := strings.IndexByte(line[q:], '"')
		if j < 0 {
			return -1
		}
		q += j
		if r := backslashesBefore(line, q); r >= k && (r-k)%(2*(k+1)) == 0 && q-k >= from {
			return q
		}
	}
	return -1
}

// closesReason reports whether the parse argument closed by the quote at
// line[first] is followed by ": ", a quoted reason (see quotedReasons) and
// the quote at line[last] that closes it: last then ends the reason, not a
// password holding quotes.
func closesReason(line string, first, last int) bool {
	rest := line[first+1:]
	for _, reason := range quotedReasons {
		if !strings.HasPrefix(rest, ": "+reason) {
			continue
		}
		open, k, ok := quotedAt(line, first+1+len(": ")+len(reason))
		return ok && closingQuote(line, open, k) == last
	}
	return false
}

// maskParseArg masks a URL-looking parse argument: "***@" plus what follows
// its last "@" with the query and fragment masked, or "***" when there is no
// "@" or what follows it may be password. url.Parse cuts the quoted URL at
// "#", so when the password holds "@" and "#" the last quoted "@" is the
// password's own and the quoted URL ends inside the password. What follows
// that "@" is then kept only when it looks like a host and path (see
// isHostPathByte) and, in a hierarchical URL ("//"), holds a non-empty host
// without "%" followed by a path: an authority cut short at "#" has none.
// A password holding "@", then "/", then "#" still cannot be told apart from
// a host and path and keeps its bytes between the "@" and the "#".
func maskParseArg(arg string) string {
	at := strings.LastIndexByte(arg, '@')
	if at < 0 {
		return Mask
	}
	tail, query := arg[at+1:], ""
	if q := strings.IndexAny(tail, "?#"); q >= 0 {
		tail, query = tail[:q], "?"+Mask
	}
	hierarchical := strings.Contains(arg[:at], "//")
	if !hierarchical && strings.IndexByte(arg[:at], '\\') >= 0 {
		// An opaque URL (no "//") only fails to parse on a control character,
		// which the error quotes escaped; url.Parse has then cut it at "#", so
		// what follows the last "@" may be password.
		return Mask
	}
	if hierarchical {
		host, _, cut := strings.Cut(tail, "/")
		if !cut || host == "" || strings.IndexByte(host, '%') >= 0 {
			return Mask
		}
	}
	for i := 0; i < len(tail); i++ {
		if !isHostPathByte(tail[i]) {
			return Mask
		}
	}
	if !keptByLaterPatterns(tail) {
		return Mask
	}
	return Mask + "@" + tail + query
}

// keptByLaterPatterns reports whether the patterns Clean applies after the
// parse errors leave tail unchanged. A tail they would mask in part (a
// token-like run, a key and its value) is masked whole instead: the "*" they
// leave is no host or path byte, so a second Clean would mask the whole
// argument anyway (Clean must be idempotent; masks only grow).
func keptByLaterPatterns(tail string) bool {
	return !jwtRe.MatchString(tail) && maskBase64(tail) == tail && maskKeyValues(tail) == tail
}

// isHostPathByte reports whether c may appear, unescaped, in the host, port
// or path that maskParseArg keeps: letters, digits and "-._~:[]%/".
func isHostPathByte(c byte) bool {
	return isAlnum(c) || strings.IndexByte("-._~:[]%/", c) >= 0
}
