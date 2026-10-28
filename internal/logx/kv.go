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
// The scan jumps from candidate to
// candidate (a separator, or a "b" that may start a scheme) with
// strings.IndexAny; the key before a separator lies between it and the
// previous separator, and a header line is consumed once, so it runs in
// time linear in len(s).
func maskKeyValues(s string) string {
	const candidates = ":=bB"
	var b strings.Builder
	done := 0 // s[:done] is already in b
	for i := 0; i < len(s); {
		p := strings.IndexAny(s[i:], candidates)
		if p < 0 {
			break
		}
		p += i
		var vs, ve, rest int
		var ok bool
		if c := s[p]; c == ':' || c == '=' {
			vs, ve, rest, ok = valueAfterKey(s, p)
		} else {
			vs, ve, ok = valueAfterScheme(s, p)
		}
		if !ok {
			i = p + 1
			continue
		}
		if ve > vs && s[vs:ve] != Mask {
			b.WriteString(s[done:vs])
			b.WriteString(Mask)
			done = ve
		}
		i = max(ve, p+1)
		if rest > ve {
			done = maskCookieRest(&b, s, done, ve, rest)
			i = rest
		}
	}
	if done == 0 {
		return s
	}
	b.WriteString(s[done:])
	return b.String()
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

// headerValue returns the bounds of the header value starting at k: up to
// the end of the line ("\r", "\n" or len(s)), or, when it opens with "[",
// from after the bracket to the next "]" on the line.
func headerValue(s string, k int) (start, end int) {
	end = len(s)
	if e := strings.IndexAny(s[k:], "\r\n"); e >= 0 {
		end = k + e
	}
	if k < end && s[k] == '[' {
		if e := strings.IndexByte(s[k:end], ']'); e >= 0 {
			end = k + e
		}
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
// header value, past the first value's end ve, for maskCookieRest (rest is 0
// otherwise).
func valueAfterKey(s string, p int) (vs, ve, rest int, ok bool) {
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
		return start, quotedEnd(s, start, s[q], q-k), 0, true
	}
	hdr := headerNone
	if !quotedKey && !preMasked(s, k) {
		hdr = keyHeaderKind(s[ks:ke], s[p])
	}
	switch hdr {
	case headerAuthorization:
		vs, ve = authorizationValue(s, k)
		return vs, ve, 0, true
	case headerCookie:
		start, end := headerValue(s, k)
		if start > k { // bracketed: every pair is masked by maskCookieRest
			return start, start, end, true
		}
		ve = unquotedEnd(s, k)
		return k, ve, end, true
	case headerNone:
	}
	if k >= len(s) || isValueEnd(s[k]) {
		return k, k, 0, true
	}
	end := unquotedEnd(s, k)
	if isAuthScheme(s[k:end]) {
		return k, k, 0, true // rescanned as a scheme
	}
	return k, end, 0, true
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
func authorizationValue(s string, k int) (vs, ve int) {
	start, end := headerValue(s, k)
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

// maskCookieRest masks s[from:end], the rest of a cookie header value after
// its first value: segments are separated by ";", and a segment's value
// (after "=") or the whole bare segment is masked unless its name is a
// Set-Cookie attribute. s[:done] is already in b; it returns the new done.
func maskCookieRest(b *strings.Builder, s string, done, from, end int) int {
	for seg := from; seg < end; {
		segEnd := end
		if e := strings.IndexByte(s[seg:end], ';'); e >= 0 {
			segEnd = seg + e
		}
		ns := seg
		for ns < segEnd && (s[ns] == ' ' || s[ns] == '\t' || s[ns] == ',') {
			ns++
		}
		name, vs := s[ns:segEnd], ns
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
			vs = skipSpaces(s, ns+eq+1)
		}
		name = strings.TrimRight(name, " \t")
		ve := segEnd
		for ve > vs && (s[ve-1] == ' ' || s[ve-1] == '\t') {
			ve--
		}
		if ve > vs && !isCookieAttr(name) && s[vs:ve] != Mask {
			b.WriteString(s[done:vs])
			b.WriteString(Mask)
			done = ve
		}
		seg = segEnd + 1
	}
	return done
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
