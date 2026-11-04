package connector_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/connector"
)

// TestPromptRequest_CleanLabelEdges covers escape sequences cut short by the
// end of the label, the 8-bit OSC introducer and terminator, and a rune that
// straddles the byte cap.
func TestPromptRequest_CleanLabelEdges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		label string
		want  string
	}{
		{name: "unterminated CSI drops the rest", label: "Code\x1b[31;", want: "Code"},
		{name: "unterminated OSC drops the rest", label: "Code\x1b]0;pwned", want: "Code"},
		{name: "8-bit OSC with 8-bit ST removed", label: "\u009d0;pwned\u009cCode", want: "Code"},
		{name: "DCS with ST removed whole", label: "\x1bPq#0;evil\x1b\\Code", want: "Code"},
		{name: "APC with ST removed whole", label: "\x1b_evil\x1b\\Code", want: "Code"},
		{name: "PM with ST removed whole", label: "\x1b^evil\x1b\\Code", want: "Code"},
		{name: "SOS with ST removed whole", label: "\x1bXevil\x1b\\Code", want: "Code"},
		{name: "8-bit DCS with 8-bit ST removed whole", label: "\u0090q#0;evil\u009cCode", want: "Code"},
		{name: "8-bit APC with ST removed whole", label: "\u009fevil\x1b\\Code", want: "Code"},
		{name: "8-bit PM with 8-bit ST removed whole", label: "\u009eevil\u009cCode", want: "Code"},
		{name: "8-bit SOS with 8-bit ST removed whole", label: "\u0098evil\u009cCode", want: "Code"},
		{name: "unterminated DCS drops the rest", label: "Code\x1bPevil", want: "Code"},
		{name: "lone ESC removed", label: "Co\x1bde", want: "Code"},
		{name: "ESC at end removed", label: "Code\x1b", want: "Code"},
		{
			name:  "rune straddling the cap is dropped whole",
			label: "a" + strings.Repeat("é", connector.MaxPromptLabelLen),
			want:  "a" + strings.Repeat("é", (connector.MaxPromptLabelLen-1)/2),
		},
		{
			name:  "space before the cap is trimmed",
			label: strings.Repeat("a", connector.MaxPromptLabelLen-1) + " b",
			want:  strings.Repeat("a", connector.MaxPromptLabelLen-1),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := connector.PromptRequest{Label: tc.label}.CleanLabel()
			if got != tc.want {
				t.Errorf("CleanLabel(%q) = %q, want %q", tc.label, got, tc.want)
			}
			if !utf8.ValidString(got) || len(got) > connector.MaxPromptLabelLen {
				t.Errorf("CleanLabel(%q) = %q: invalid UTF-8 or over the cap", tc.label, got)
			}
		})
	}
}
