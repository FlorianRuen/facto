package logx

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// defaultFragments are defaultKeys split like a Handler splits them, for
// Clean, which has no Options.
var defaultFragments = splitFragments(defaultKeys)

// fragments are sensitive key fragments: keys matched with strings.Contains
// on the lowercased key, words matched as whole words (see words).
type fragments struct {
	keys, words []string
	keyBytes    [][]byte // keys as bytes, for bytes.Contains
	wordBytes   [][]byte // words as bytes, for bytes.Contains
}

// splitFragments lowercases list and sorts each entry into long fragments
// and whole-word ones (shortFragment bytes or fewer). Empty entries are
// dropped: they would match every key.
func splitFragments(list []string) fragments {
	var f fragments
	for _, k := range list {
		switch k = strings.ToLower(k); {
		case k == "":
		case len(k) <= shortFragment && isWord(k):
			f.words = append(f.words, k)
			f.wordBytes = append(f.wordBytes, []byte(k))
		default:
			f.keys = append(f.keys, k)
			f.keyBytes = append(f.keyBytes, []byte(k))
		}
	}
	return f
}

// maxFastKey is the longest key match lowercases into a stack buffer.
const maxFastKey = 64

// match reports whether key, lowercased, contains a long fragment or has a
// short one as a whole word (see words). A short ASCII key, the common case,
// is matched without allocating.
func (f fragments) match(key string) bool {
	if len(key) > maxFastKey {
		return f.matchUnicode(key)
	}
	var buf [maxFastKey]byte
	lk := buf[:len(key)]
	for i := range len(key) {
		c := key[i]
		if c >= utf8.RuneSelf {
			return f.matchUnicode(key)
		}
		lk[i] = lowerASCII(c)
	}
	for _, frag := range f.keyBytes {
		if bytes.Contains(lk, frag) {
			return true
		}
	}
	// A whole word is also a substring: split into words only when one of
	// them may match.
	for _, w := range f.wordBytes {
		if bytes.Contains(lk, w) {
			return f.hasWord(key)
		}
	}
	return false
}

// hasWord reports whether a word of key (split as words does, without
// building the slice) is a whole-word fragment.
func (f fragments) hasWord(key string) bool {
	start := -1
	for i := 0; i <= len(key); i++ {
		boundary := i == len(key) || !isAlnum(key[i])
		camel := !boundary && i > 0 && 'A' <= key[i] && key[i] <= 'Z' && 'a' <= key[i-1] && key[i-1] <= 'z'
		if (boundary || camel) && start >= 0 {
			if f.isWord(key[start:i]) {
				return true
			}
			start = -1
		}
		if !boundary && start < 0 {
			start = i
		}
	}
	return false
}

// matchUnicode is match for a long key or one holding non-ASCII bytes,
// whose Unicode lowercasing may turn a letter into an ASCII one (U+212A
// KELVIN SIGN → k).
func (f fragments) matchUnicode(key string) bool {
	k := strings.ToLower(key)
	for _, frag := range f.keys {
		if strings.Contains(k, frag) {
			return true
		}
	}
	for _, w := range words(key) {
		if f.isWord(w) {
			return true
		}
	}
	return false
}

// isWord reports whether w equals a whole-word fragment, ignoring ASCII
// case.
func (f fragments) isWord(w string) bool {
	if len(w) > shortFragment {
		return false
	}
	for _, fw := range f.words {
		if equalLowerASCII(w, fw) {
			return true
		}
	}
	return false
}

// equalLowerASCII reports whether s equals lower (lowercase) ignoring ASCII
// case. Hand-written: strings.EqualFold is much slower under -race.
func equalLowerASCII(s, lower string) bool {
	if len(s) != len(lower) {
		return false
	}
	for i := range len(s) {
		if lowerASCII(s[i]) != lower[i] {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// isKeyByte reports whether c may appear in a free-text key: letters,
// digits, "_", "-" and ".".
func isKeyByte(c byte) bool {
	return isAlnum(c) || c == '_' || c == '-' || c == '.'
}

// isValueEnd reports whether c ends an unquoted free-text value.
func isValueEnd(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '&', ';', ',', '"', '\'', '`', '\\', '<', '>', '(', ')', '[', ']', '{', '}':
		return true
	}
	return false
}

// isAuthScheme reports whether w is an HTTP authorization scheme whose
// parameter is a credential.
func isAuthScheme(w string) bool {
	return equalLowerASCII(w, "bearer") || equalLowerASCII(w, "basic")
}

// skipSpaces returns the first offset at or after i that is not a space or
// a tab.
func skipSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// maskKeyValues masks, in free text, the value that follows a sensitive key
// (the default fragments, matched like attribute keys) and the credential
// that follows an authorization scheme, case-insensitively:
//
//	password=v, password: v, password = "v", "password":"v",
//	\"password\":\"v\", Bearer v, Basic v
//
// An unquoted value ends at whitespace or at one of `&;,"'` + "`" + `\<>()[]{}`;
// a quoted one at its closing quote (backslash escapes honoured). A value
// that is itself an authorization scheme (Authorization: Bearer v) keeps the
// scheme and masks what follows it.
//
// Header lines go further, up to the end of the line ("\r" or "\n"), when
// the key is unquoted, holds "cookie" or "authorization" (Set-Cookie,
// Proxy-Authorization) and the separator is ":". An authorization line is
// masked whole after its Bearer or Basic scheme, or whole when the scheme is
// another one (Token, Digest, Negotiate…). A cookie line has its first value
// masked as above, then every later pair's value and every bare token,
// except the Set-Cookie attributes (see isCookieAttr), which are kept. A
// header value opening with "[" (fmt's rendering of an http.Header, all
// headers on one line) ends at the next "]" instead of the end of the line.
//
// Masks only grow: a masked value (or credential) that holds a sensitive
// key and its separator whose own value runs past it (token: password: v,
// Bearer pwd='v', password="a pwd="v") is masked together with that value,
// and so on down the chain (see extendSpan).
// The kept value of a Set-Cookie attribute (Path=/ password=v) is scanned
// for keys like any other text, so a header found there starts its own
// header-line rule (see cookieSegments).
//
// The scan jumps from candidate to
// candidate (a separator, or a "b" that may start a scheme) with
// strings.IndexAny; the key before a separator lies between it and the
// previous separator, a masked span is searched once more for inner keys,
// a cookie line's segments are walked once, the line end, the next "]" and
// the next ";" are cached for the headers nested in it (see headerCache),
// and the scan never moves back, so it runs in time linear in len(s).
func maskKeyValues(s string) string {
	const candidates = ":=bB"
	var b strings.Builder
	var hc headerCache
	done := 0       // s[:done] is already in b
	cookieEnd := -1 // end of the cookie header value being walked, or -1
	attrEnd := -1   // end of the kept attribute value being scanned, or -1
	for i := 0; i < len(s); {
		if cookieEnd >= 0 && attrEnd < 0 {
			if i >= cookieEnd {
				cookieEnd = -1
				continue
			}
			done, i, attrEnd = cookieSegments(&b, s, done, i, cookieEnd, &hc)
			if attrEnd < 0 {
				cookieEnd = -1
			}
			continue
		}
		limit := len(s)
		if attrEnd >= 0 {
			limit = attrEnd
		}
		p := strings.IndexAny(s[i:limit], candidates)
		if p < 0 {
			if attrEnd < 0 {
				break
			}
			i, attrEnd = attrEnd, -1 // the next segment
			continue
		}
		p += i
		var vs, ve, rest int
		var ok bool
		if c := s[p]; c == ':' || c == '=' {
			vs, ve, rest, ok = valueAfterKey(s, p, &hc)
		} else {
			vs, ve, ok = valueAfterScheme(s, p)
		}
		if !ok {
			i = p + 1
			continue
		}
		if ve > vs {
			grown := extendSpan(s, vs, ve, &hc)
			if rest > 0 && grown > ve {
				// A cookie line's first value grew: on to the end of its
				// segment, so that the walk starts where it would have.
				grown = max(grown, min(rest, hc.semicolon.find(s, grown, semicolonIndex)))
			}
			ve = grown
			if s[vs:ve] != Mask {
				done = putMask(&b, s, done, vs, ve)
			}
		}
		i = max(ve, p+1)
		switch {
		case rest > ve: // a cookie line, possibly nested in an attribute value
			cookieEnd, attrEnd, i = rest, -1, ve
		case attrEnd >= 0 && i > attrEnd:
			// The value ran past the attribute's segment: what is left of
			// the segment it ends in, past the closing quote, is masked like
			// a bare segment (the walk would have masked it), then the walk
			// goes on.
			attrEnd = -1
			if i < cookieEnd {
				e := min(cookieEnd, hc.semicolon.find(s, i, semicolonIndex))
				vs := i
				for vs < e && (s[vs] == '"' || s[vs] == '\'' || s[vs] == '\\') {
					vs++ // the closing quote of a quoted value
				}
				vs, ve := skipSpaces(s, vs), e
				for ve > vs && (s[ve-1] == ' ' || s[ve-1] == '\t') {
					ve--
				}
				if ve > vs && s[vs:ve] != Mask {
					done = putMask(&b, s, done, vs, ve)
				}
				i = e
			}
		}
	}
	if done == 0 {
		return s
	}
	b.WriteString(s[done:])
	return b.String()
}

// putMask writes s[done:vs] and Mask to b, s[:done] being already in it, and
// returns ve, the new done. A span right after a Mask, written before or
// already in s (an earlier pattern's), is merged into it: two adjacent masks
// would render as "******", which a second Clean masks again (Clean must be
// idempotent).
func putMask(b *strings.Builder, s string, done, vs, ve int) int {
	b.WriteString(s[done:vs])
	if !strings.HasSuffix(b.String(), Mask) {
		b.WriteString(Mask)
	}
	return ve
}

// valueAfterScheme returns the span of the credential following the
// authorization scheme that starts at s[p], if a whole word "Bearer" or
// "Basic" starts there and is followed by a space or a tab.
func valueAfterScheme(s string, p int) (vs, ve int, ok bool) {
	if p > 0 && isKeyByte(s[p-1]) {
		return 0, 0, false
	}
	j := p
	for j < len(s) && j-p <= len("bearer") && isKeyByte(s[j]) {
		j++
	}
	if !isAuthScheme(s[p:j]) || (j < len(s) && isKeyByte(s[j])) {
		return 0, 0, false
	}
	k := skipSpaces(s, j)
	if k == j || k >= len(s) || isValueEnd(s[k]) {
		return 0, 0, false
	}
	return k, unquotedEnd(s, k), true
}

// headerKind tells which header-line rule applies after a key.
type headerKind int

const (
	headerNone headerKind = iota
	headerCookie
	headerAuthorization
)

// keyHeaderKind returns the header-line rule of an unquoted key followed by
// sep.
func keyHeaderKind(key string, sep byte) headerKind {
	switch {
	case sep != ':':
		return headerNone
	case containsLowerASCII(key, "authorization"):
		return headerAuthorization
	case containsLowerASCII(key, "cookie"):
		return headerCookie
	}
	return headerNone
}

// containsLowerASCII reports whether s contains sub (lowercase), ignoring
// ASCII case.
func containsLowerASCII(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalLowerASCII(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

// headerCache remembers the next line break and the next "]" headerValue
// found, the next ";" of a cookie line and the next end of an unquoted
// value, so that the headers nested in one cookie line (Cookie: a; Path=
// Cookie: b; Path=…) do not each scan to the end of the line again.
type headerCache struct {
	lineEnd, bracket, semicolon, valueEnd nextIndex
	// quoted[q][d] caches quotedEnd for quote q ('"' 0, '\'' 1) at
	// depth d.
	quoted [2][maxCachedDepth + 1]nextIndex
	// failClosed, set while extendSpan runs, makes a deeper quoted value
	// run to the end of its line.
	failClosed bool
}

// maxCachedDepth is the deepest quoting (backslashes before the quote)
// whose value ends are cached.
const maxCachedDepth = 4

// quotedEnd is quotedEnd(s, k, quote, depth), from a cache up to
// maxCachedDepth; k follows the opening quote. The closing quotes (and
// line breaks) a search finds do not depend on where it starts, since a
// backslash run after an opening quote starts after it, so a search is
// reused for any later k it covers. Deeper, a failClosed search returns the
// end of the line, which is never before the real end.
func (hc *headerCache) quotedEnd(s string, k int, quote byte, depth int) int {
	if depth > maxCachedDepth {
		if hc.failClosed {
			return hc.lineEnd.find(s, k, lineBreakIndex)
		}
		return quotedEnd(s, k, quote, depth)
	}
	qi := 0
	if quote == '\'' {
		qi = 1
	}
	return hc.quoted[qi][depth].find(s, k, func(t string) int {
		if e := quotedEnd(t, 0, quote, depth); e < len(t) {
			return e
		}
		return -1
	})
}

// nextIndex is the result of a forward search started at from: at is the
// first match at or after from, or len(s) when there is none.
type nextIndex struct {
	set      bool
	from, at int
}

// find returns the first offset at or after k where search (an index
// function) matches, len(s) when it does not, reusing the last search when
// it started at or before k and ended at or after it.
func (n *nextIndex) find(s string, k int, search func(string) int) int {
	if n.set && n.from <= k && k <= n.at {
		return n.at
	}
	at := len(s)
	if e := search(s[k:]); e >= 0 {
		at = k + e
	}
	*n = nextIndex{set: true, from: k, at: at}
	return at
}

func lineBreakIndex(s string) int { return strings.IndexAny(s, "\r\n") }

func closingBracketIndex(s string) int { return strings.IndexByte(s, ']') }

func semicolonIndex(s string) int { return strings.IndexByte(s, ';') }

// valueEndIndex is the index of the first byte ending an unquoted value
// (see isValueEnd), or -1.
func valueEndIndex(s string) int { return strings.IndexAny(s, " \t\r\n&;,\"'`\\<>()[]{}") }

// headerValue returns the bounds of the header value starting at k: up to
// the end of the line ("\r", "\n" or len(s)), or, when it opens with "[",
// from after the bracket to the next "]" on the line.
func headerValue(s string, k int, hc *headerCache) (start, end int) {
	end = hc.lineEnd.find(s, k, lineBreakIndex)
	if k < end && s[k] == '[' {
		end = min(end, hc.bracket.find(s, k, closingBracketIndex))
		return k + 1, end
	}
	return k, end
}

// valueAfterKey returns the span of the value following the separator s[p]
// (":" or "=") when the key before it, optionally quoted (possibly with
// escaped quotes) and followed by spaces, is sensitive. An unquoted value
// that is an authorization scheme yields an empty span right before it, so
// the caller rescans it as a scheme. Header lines (see maskKeyValues): on an
// authorization line the span covers the value after its Bearer or Basic
// scheme, or the whole value; on a cookie line rest is the end of the
// header value, past the first value's end ve, for cookieSegments (rest is 0
// otherwise). hc caches the header value bounds.
func valueAfterKey(s string, p int, hc *headerCache) (vs, ve, rest int, ok bool) {
	ke := p
	for ke > 0 && (s[ke-1] == ' ' || s[ke-1] == '\t') {
		ke--
	}
	quotedKey := false
	if ke > 0 && (s[ke-1] == '"' || s[ke-1] == '\'') {
		quotedKey = true
		ke--
		for ke > 0 && s[ke-1] == '\\' {
			ke--
		}
	}
	ks := ke
	for ks > 0 && isKeyByte(s[ks-1]) {
		ks--
	}
	if ks == ke || !defaultFragments.match(s[ks:ke]) {
		return 0, 0, 0, false
	}
	k := skipSpaces(s, p+1)
	// Optional opening quote of the value, possibly escaped.
	q := k
	for q < len(s) && s[q] == '\\' {
		q++
	}
	if q < len(s) && (s[q] == '"' || s[q] == '\'') {
		start := q + 1
		return start, hc.quotedEnd(s, start, s[q], q-k), 0, true
	}
	hdr := headerNone
	if !quotedKey && !preMasked(s, k) {
		hdr = keyHeaderKind(s[ks:ke], s[p])
	}
	switch hdr {
	case headerAuthorization:
		vs, ve = authorizationValue(s, k, hc)
		return vs, ve, 0, true
	case headerCookie:
		start, end := headerValue(s, k, hc)
		if start > k { // bracketed: every pair is walked by cookieSegments
			return start, start, end, true
		}
		ve = hc.valueEnd.find(s, k, valueEndIndex)
		return k, ve, end, true
	case headerNone:
	}
	if k >= len(s) || isValueEnd(s[k]) {
		return k, k, 0, true
	}
	end := hc.valueEnd.find(s, k, valueEndIndex)
	if isAuthScheme(s[k:end]) {
		return k, k, 0, true // rescanned as a scheme
	}
	return k, end, 0, true
}

// extendSpan returns the end of the masked span [vs, ve) grown over the
// values of the sensitive keys inside it that run past ve: one ending the
// span (token: password: v, Bearer pwd='v) or opening a quoted value in it
// (password="a pwd='x" v'), then theirs in turn. A mask therefore never
// ends before the value of a key it covers, and never shrinks.
//
// Every separator and scheme in the span is looked at, the grown part
// included, as the main scan would have looked at those of the grown part; a
// header line found there grows the span to the end of its value (cookie
// line included: the whole of it is masked). Value ends come from caches
// (see headerCache), and a quoted inner value opened by more than
// maxCachedDepth backslashes is taken to run to the end of its line (fail
// closed), so each byte is read a bounded number of times.
//
// A grown quoted span ends at its own closing quote again (quotedEnd from
// the inner end), so that a second Clean, which reads the mask as that
// quoted value, ends it at the same place.
func extendSpan(s string, vs, ve int, hc *headerCache) int {
	var quote byte
	depth := 0
	if vs > 0 && (s[vs-1] == '"' || s[vs-1] == '\'') {
		quote, depth = s[vs-1], backslashesBefore(s, vs-1)
	}
	hc.failClosed = true
	defer func() { hc.failClosed = false }()
	for i := vs; i < ve; {
		p := strings.IndexAny(s[i:ve], ":=bB")
		if p < 0 {
			break
		}
		p += i
		i = p + 1
		var ivs, ive, rest int
		var ok bool
		if c := s[p]; c == ':' || c == '=' {
			ivs, ive, rest, ok = valueAfterKey(s, p, hc)
		} else {
			ivs, ive, ok = valueAfterScheme(s, p)
		}
		if !ok {
			continue
		}
		end := rest    // a whole cookie line, or 0
		if ive > ivs { // not an empty span (a scheme rescanned by the caller)
			end = max(end, ive)
		}
		if end > ve {
			ve = end
			if quote != 0 {
				ve = hc.quotedEnd(s, end, quote, depth)
			}
		}
	}
	return ve
}

// preMasked reports whether the value at k is already Mask alone, followed
// by a space, a "]", a line break or the end of s: the handler renders a
// sensitive map entry as "Authorization:***" among the other entries of
// "map[…]" on one line, which the header-line rules would swallow.
func preMasked(s string, k int) bool {
	if !strings.HasPrefix(s[k:], Mask) {
		return false
	}
	e := k + len(Mask)
	return e == len(s) || s[e] == ' ' || s[e] == ']' || s[e] == '\r' || s[e] == '\n'
}

// authorizationValue returns the span to mask in the authorization header
// value starting at k (see headerValue): what follows a Bearer or Basic
// scheme and its spaces, or the whole value. A scheme with nothing after it
// yields an empty span.
func authorizationValue(s string, k int, hc *headerCache) (vs, ve int) {
	start, end := headerValue(s, k, hc)
	j := start
	for j < end && isKeyByte(s[j]) {
		j++
	}
	if isAuthScheme(s[start:j]) && (j == end || s[j] == ' ' || s[j] == '\t') {
		c := skipSpaces(s, j)
		if c >= end {
			return end, end
		}
		return c, end
	}
	return start, end
}

// cookieSegments walks s[from:end], the rest of a cookie header value after
// its first value: segments are separated by ";", and a segment's value
// (after "=") or the whole bare segment is masked unless its name is a
// Set-Cookie attribute. A pair whose name is not a cookie name (see
// isCookieName) is masked whole: it is a value swallowed by an earlier key
// (Cookie: password: v =). At the first attribute with a value it stops and
// returns that value's start as next and its segment's end as attrEnd, for
// the caller to scan the value for keys (Path=/ password=v) and come back at
// attrEnd; attrEnd is -1 when the walk reached end. hc caches the next ";".
// s[:done] is already in b; it returns the new done.
func cookieSegments(b *strings.Builder, s string, done, from, end int, hc *headerCache) (newDone, next, attrEnd int) {
	for seg := from; seg < end; {
		segEnd := min(end, hc.semicolon.find(s, seg, semicolonIndex))
		ns := seg
		for ns < segEnd && (s[ns] == ' ' || s[ns] == '\t' || s[ns] == ',') {
			ns++
		}
		name, vs := s[ns:segEnd], ns
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
			vs = skipSpaces(s, ns+eq+1)
			if !isCookieName(name) { // a swallowed value, not a pair
				name, vs = "", ns
			}
		}
		name = strings.TrimRight(name, " \t")
		ve := segEnd
		for ve > vs && (s[ve-1] == ' ' || s[ve-1] == '\t') {
			ve--
		}
		switch {
		case ve <= vs || s[vs:ve] == Mask:
		case !isCookieAttr(name):
			done = putMask(b, s, done, vs, ve)
		default:
			return done, vs, segEnd
		}
		seg = segEnd + 1
	}
	return done, end, -1
}

// isCookieName reports whether name is a non-empty run of key bytes, the
// shape of real cookie names (sid, __Host-sid, _ga.x). Stricter than the RFC
// 6265 token on purpose: what it refuses is masked.
func isCookieName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		if !isKeyByte(name[i]) {
			return false
		}
	}
	return true
}

// isCookieAttr reports whether name is a Set-Cookie attribute (RFC 6265bis
// and common extensions), whose value is not a credential.
func isCookieAttr(name string) bool {
	for _, a := range [...]string{"path", "domain", "expires", "max-age", "samesite", "priority", "secure", "httponly", "partitioned"} {
		if equalLowerASCII(name, a) {
			return true
		}
	}
	return false
}

// unquotedEnd returns the end of the unquoted value starting at k.
func unquotedEnd(s string, k int) int {
	for k < len(s) && !isValueEnd(s[k]) {
		k++
	}
	return k
}

// quotedEnd returns the end of a value opened by quote after depth
// backslashes: the offset of the first closing quote (preceded by depth
// backslashes when depth > 0, which are excluded from the value), or the end
// of the line, or of s. At depth 0 a backslash escapes the next byte.
func quotedEnd(s string, k int, quote byte, depth int) int {
	for k < len(s) {
		c := s[k]
		switch {
		case c == '\n' || c == '\r':
			return k
		case depth == 0 && c == '\\':
			k += 2
			continue
		case c == quote:
			if depth == 0 {
				return k
			}
			if n := backslashesBefore(s, k); n >= depth {
				return k - n
			}
		}
		k++
	}
	return len(s)
}
