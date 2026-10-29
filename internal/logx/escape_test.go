package logx_test

import (
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

// TestEscape pins the one-line terminal escaping shared by the report and
// the CLI error output (SEC-J0-19): controls, C1, bidi and other format
// characters, line separators, invalid bytes and the backslash are written
// as Go-style escapes; printable text survives.
func TestEscape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"plain", "facture edf 2026.pdf", "facture edf 2026.pdf"},
		{"accents", "électricité.pdf", "électricité.pdf"},
		{"esc", "\x1b[2J", `\u001b[2J`},
		{"osc 52", "\x1b]52;c;Zm9v\x07", `\u001b]52;c;Zm9v\u0007`},
		{"cr lf", "a\rb\nc", `a\u000db\u000ac`},
		{"del", "a\x7fb", `a\u007fb`},
		{"c1 csi", "\u009b31m", `\u009b31m`},
		{"bidi override", "facture\u202egpj.pdf", `facture\u202egpj.pdf`},
		{"line separator", "a\u2028b", `a\u2028b`},
		{"invalid byte", "a\xffb", `a\xffb`},
		{"replacement char", "a\ufffdb", `a\ufffdb`},
		{"backslash", `C:\x`, `C:\\x`},
		{"astral non printable", "a\U000E0001b", `a\U000e0001b`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := logx.Escape(tc.in); got != tc.want {
				t.Errorf("Escape(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
