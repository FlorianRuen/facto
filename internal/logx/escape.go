package logx

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escape makes an untrusted string safe on one terminal line: every rune
// that is not printable (C0 and C1 controls, DEL, format characters such as
// bidi overrides, line and paragraph separators, non-ASCII spaces), every
// invalid byte, U+FFFD and the backslash itself are written as Go-style
// escapes, so the output never holds a byte a terminal interprets and an
// escape in the input cannot be confused with one Escape wrote. Escape does
// not mask secrets: callers run Clean first.
func Escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\\':
			b.WriteString(`\\`)
		case r == utf8.RuneError || !unicode.IsPrint(r):
			if r > 0xFFFF {
				fmt.Fprintf(&b, `\U%08x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}
