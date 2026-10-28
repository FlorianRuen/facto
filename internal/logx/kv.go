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
// scheme and masks what follows it. The scan jumps from candidate to
// candidate (a separator, or a "b" that may start a scheme) with
// strings.IndexAny; the key before a separator lies between it and the
// previous separator, so it runs in time linear in len(s).
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
		var vs, ve int
		var ok bool
		if c := s[p]; c == ':' || c == '=' {
			vs, ve, ok = valueAfterKey(s, p)
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

// valueAfterKey returns the span of the value following the separator s[p]
// (":" or "=") when the key before it, optionally quoted (possibly with
// escaped quotes) and followed by spaces, is sensitive. An unquoted value
// that is an authorization scheme yields an empty span right before it, so
// the caller rescans it as a scheme.
func valueAfterKey(s string, p int) (vs, ve int, ok bool) {
	ke := p
	for ke > 0 && (s[ke-1] == ' ' || s[ke-1] == '\t') {
		ke--
	}
	if ke > 0 && (s[ke-1] == '"' || s[ke-1] == '\'') {
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
		return 0, 0, false
	}
	k := skipSpaces(s, p+1)
	// Optional opening quote of the value, possibly escaped.
	q := k
	for q < len(s) && s[q] == '\\' {
		q++
	}
	if q < len(s) && (s[q] == '"' || s[q] == '\'') {
		start := q + 1
		return start, quotedEnd(s, start, s[q], q-k), true
	}
	if k >= len(s) || isValueEnd(s[k]) {
		return k, k, true
	}
	end := unquotedEnd(s, k)
	if isAuthScheme(s[k:end]) {
		return k, k, true // rescanned as a scheme
	}
	return k, end, true
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
