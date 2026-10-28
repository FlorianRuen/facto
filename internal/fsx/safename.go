package fsx

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxNameLen is the maximum length, in bytes, of a SafeName result. It leaves
// room under the 255-byte NAME_MAX for the WriteAtomic temp prefix and a "_vN"
// version suffix.
const MaxNameLen = 200

// maxExtLen is the longest extension (dot included) SafeName keeps when it
// truncates a name.
const maxExtLen = 10

// windowsReserved lists the device names Windows refuses as a file stem
// (upper case). Go's internal/filepathlite isReservedName is the reference;
// COM0 and LPT0 are added defensively.
var windowsReserved = map[string]struct{}{
	"CON": {}, "PRN": {}, "AUX": {}, "NUL": {}, "CONIN$": {}, "CONOUT$": {},
	"COM0": {}, "COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {},
	"COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
	"COM\u00b9": {}, "COM\u00b2": {}, "COM\u00b3": {},
	"LPT0": {}, "LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {},
	"LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
	"LPT\u00b9": {}, "LPT\u00b2": {}, "LPT\u00b3": {},
}

// SafeName turns any string (supplier-provided invoice number, seller name,
// inbox file name, test name…) into ONE path component that is safe on Linux,
// macOS and Windows. It never fails and never returns "", "." or "..". Steps,
// in order:
//  1. every rune that is invalid UTF-8, NUL, a C0/C1 control or DEL, a Unicode
//     format character (unicode.Cf: bidi overrides, zero-width…), a separator
//     ('/' or '\\') or a Windows-forbidden character (< > : " | ? *) is
//     replaced by '_';
//  2. runs of dots are collapsed to one dot (so ".." never appears);
//  3. leading and trailing dots and spaces are trimmed (no hidden files, no
//     Windows trailing dot/space);
//  4. if the stem (text before the first dot, trailing spaces ignored as
//     Windows does), compared case-insensitively, is a Windows reserved device
//     name (CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM0–COM9, COM¹–COM³,
//     LPT0–LPT9, LPT¹–LPT³) the result is prefixed with '_';
//  5. the result is truncated to at most MaxNameLen bytes on a rune boundary,
//     keeping the extension (from the last dot, up to 10 bytes) when there is
//     one, then steps 2 and 3 are applied again, and step 4 again when the
//     truncation exposed a reserved stem;
//  6. an empty result becomes "_".
//
// SafeName is idempotent. Other Unicode (accents, CJK) is kept as is:
// transliteration is normalize's job.
func SafeName(s string) string {
	s = trimDotsSpaces(collapseDots(replaceUnsafe(s)))
	if isReserved(s) {
		s = "_" + s
	}
	if len(s) > MaxNameLen {
		s = trimDotsSpaces(collapseDots(truncate(s)))
		// Truncation can expose a reserved stem ("CON" + spaces + tail). The
		// prefixed result starts with '_', so truncating it again is safe.
		if isReserved(s) {
			s = "_" + s
			if len(s) > MaxNameLen {
				s = trimDotsSpaces(collapseDots(truncate(s)))
			}
		}
	}
	if s == "" {
		return "_"
	}
	return s
}

// replaceUnsafe is step 1.
func replaceUnsafe(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i, w := 0, 0; i < len(s); i += w {
		r, size := utf8.DecodeRuneInString(s[i:])
		w = size
		switch {
		case r == utf8.RuneError && size == 1,
			r == 0, unicode.IsControl(r), unicode.Is(unicode.Cf, r),
			strings.ContainsRune(`/\<>:"|?*`, r):
			b.WriteByte('_')
		default:
			b.WriteString(s[i : i+size])
		}
	}
	return b.String()
}

// collapseDots is step 2.
func collapseDots(s string) string {
	if !strings.Contains(s, "..") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prevDot := false
	for i := range len(s) {
		c := s[i]
		if c == '.' && prevDot {
			continue
		}
		prevDot = c == '.'
		b.WriteByte(c)
	}
	return b.String()
}

// trimDotsSpaces is step 3.
func trimDotsSpaces(s string) string { return strings.Trim(s, ". ") }

// isReserved is the step 4 test.
func isReserved(s string) bool {
	stem, _, _ := strings.Cut(s, ".")
	stem = strings.TrimRight(stem, " ")
	_, ok := windowsReserved[strings.ToUpper(stem)]
	return ok
}

// truncate is step 5 without the final clean-up: it cuts s to MaxNameLen
// bytes on a rune boundary, keeping a short extension.
func truncate(s string) string {
	ext := ""
	if i := strings.LastIndexByte(s, '.'); i > 0 && len(s)-i <= maxExtLen {
		ext = s[i:]
		s = s[:i]
	}
	n := MaxNameLen - len(ext)
	if n < len(s) {
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n]
	}
	return s + ext
}

// JoinWithin joins slash-separated relative parts under root and returns the
// cleaned OS path (filepath.Join semantics). It is lexical only (symlinks are
// handled by Root/os.Root). It fails with ErrInvalidName when root is empty, a
// part is empty, absolute or contains NUL, or the result is not strictly inside
// root (equal to root, or escaping it through ".."). Parts may contain several
// segments ("2026/housing") and inner ".." that stays inside root ("a/../b").
func JoinWithin(root string, parts ...string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("%w: empty root", ErrInvalidName)
	}
	elems := make([]string, 0, len(parts)+1)
	elems = append(elems, root)
	for _, p := range parts {
		osPart := filepath.FromSlash(p)
		if p == "" || strings.ContainsRune(p, 0) || path.IsAbs(p) ||
			filepath.IsAbs(osPart) || filepath.VolumeName(osPart) != "" {
			return "", fmt.Errorf("%w: part %q", ErrInvalidName, p)
		}
		elems = append(elems, osPart)
	}
	joined := filepath.Join(elems...)
	rel, err := filepath.Rel(filepath.Clean(root), joined)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%w: %q escapes or equals the root", ErrInvalidName, parts)
	}
	return joined, nil
}
