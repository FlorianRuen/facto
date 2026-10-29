package normalize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// translit maps one rune range to its ASCII lowercase transliteration.
type translit struct {
	lo, hi rune
	ascii  string
}

// translitTable is the hand-written transliteration table: the Latin-1
// Supplement and Latin Extended-A letters used in European languages, plus the
// capital sharp s. Ranges are sorted and disjoint; × (U+00D7) and ÷ (U+00F7)
// are deliberately absent, so they act as separators.
var translitTable = []translit{
	{0x00C0, 0x00C5, "a"}, // À Á Â Ã Ä Å
	{0x00C6, 0x00C6, "ae"},
	{0x00C7, 0x00C7, "c"},
	{0x00C8, 0x00CB, "e"},
	{0x00CC, 0x00CF, "i"},
	{0x00D0, 0x00D0, "d"}, // Ð
	{0x00D1, 0x00D1, "n"},
	{0x00D2, 0x00D6, "o"},
	{0x00D8, 0x00D8, "o"}, // Ø
	{0x00D9, 0x00DC, "u"},
	{0x00DD, 0x00DD, "y"},
	{0x00DE, 0x00DE, "th"}, // Þ
	{0x00DF, 0x00DF, "ss"}, // ß
	{0x00E0, 0x00E5, "a"},
	{0x00E6, 0x00E6, "ae"},
	{0x00E7, 0x00E7, "c"},
	{0x00E8, 0x00EB, "e"},
	{0x00EC, 0x00EF, "i"},
	{0x00F0, 0x00F0, "d"}, // ð
	{0x00F1, 0x00F1, "n"},
	{0x00F2, 0x00F6, "o"},
	{0x00F8, 0x00F8, "o"}, // ø
	{0x00F9, 0x00FC, "u"},
	{0x00FD, 0x00FD, "y"},
	{0x00FE, 0x00FE, "th"}, // þ
	{0x00FF, 0x00FF, "y"},
	{0x0100, 0x0105, "a"},  // Ā ā Ă ă Ą ą
	{0x0106, 0x010D, "c"},  // Ć ć Ĉ ĉ Ċ ċ Č č
	{0x010E, 0x0111, "d"},  // Ď ď Đ đ
	{0x0112, 0x011B, "e"},  // Ē ē Ĕ ĕ Ė ė Ę ę Ě ě
	{0x011C, 0x0123, "g"},  // Ĝ ĝ Ğ ğ Ġ ġ Ģ ģ
	{0x0124, 0x0127, "h"},  // Ĥ ĥ Ħ ħ
	{0x0128, 0x0131, "i"},  // Ĩ ĩ Ī ī Ĭ ĭ Į į İ ı
	{0x0132, 0x0133, "ij"}, // Ĳ ĳ
	{0x0134, 0x0135, "j"},  // Ĵ ĵ
	{0x0136, 0x0138, "k"},  // Ķ ķ ĸ
	{0x0139, 0x0142, "l"},  // Ĺ ĺ Ļ ļ Ľ ľ Ŀ ŀ Ł ł
	{0x0143, 0x0149, "n"},  // Ń ń Ņ ņ Ň ň ŉ
	{0x014A, 0x014B, "ng"}, // Ŋ ŋ
	{0x014C, 0x0151, "o"},  // Ō ō Ŏ ŏ Ő ő
	{0x0152, 0x0153, "oe"}, // Œ œ
	{0x0154, 0x0159, "r"},  // Ŕ ŕ Ŗ ŗ Ř ř
	{0x015A, 0x0161, "s"},  // Ś ś Ŝ ŝ Ş ş Š š
	{0x0162, 0x0167, "t"},  // Ţ ţ Ť ť Ŧ ŧ
	{0x0168, 0x0173, "u"},  // Ũ ũ Ū ū Ŭ ŭ Ů ů Ű ű Ų ų
	{0x0174, 0x0175, "w"},  // Ŵ ŵ
	{0x0176, 0x0178, "y"},  // Ŷ ŷ Ÿ
	{0x0179, 0x017E, "z"},  // Ź ź Ż ż Ž ž
	{0x017F, 0x017F, "s"},  // ſ
	{0x1E9E, 0x1E9E, "ss"}, // ẞ
}

// transliterate returns the ASCII form of a non-ASCII letter of the table.
func transliterate(r rune) (string, bool) {
	for _, t := range translitTable {
		if r < t.lo {
			return "", false
		}
		if r <= t.hi {
			return t.ascii, true
		}
	}
	return "", false
}

// Slug turns s into lowercase ASCII words joined by single hyphens: the result
// matches ^([a-z0-9]+(-[a-z0-9]+)*)?$. Letters of the Latin-1 and Latin
// Extended-A blocks are transliterated with a hand-written table (é→e, œ→oe,
// ß/ẞ→ss, ł→l, İ→i…), combining marks (decomposed accents) are dropped, and
// every run of any other character (space, punctuation, '_', '/', '.', NUL,
// controls, symbols, invalid UTF-8, non-Latin scripts) becomes one hyphen.
// Leading and trailing hyphens are trimmed, so Slug may return "". Slug is
// idempotent.
func Slug(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	sep := false // a separator is pending between two words
	word := func(w string) {
		if sep && b.Len() > 0 {
			b.WriteByte('-')
		}
		sep = false
		b.WriteString(w)
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case 'a' <= r && r <= 'z', '0' <= r && r <= '9':
			word(string(r))
		case 'A' <= r && r <= 'Z':
			word(string(r - 'A' + 'a'))
		case r == utf8.RuneError && size == 1:
			sep = true
		case unicode.Is(unicode.Mn, r):
			// Combining mark of a decomposed accent: dropped.
		default:
			if t, ok := transliterate(r); ok {
				word(t)
			} else {
				sep = true
			}
		}
	}
	return b.String()
}
