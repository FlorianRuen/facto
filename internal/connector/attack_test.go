// Red-team attacks on the OTP / prompt label a supplier page controls (J1
// task T27): terminal escapes (CSI, OSC 52 clipboard write, OSC 8 links,
// DCS, title changes, 8-bit C1 introducers), bidi overrides and isolates,
// line and paragraph separators, backspace and carriage-return overwrite,
// invalid UTF-8 that could rebuild an escape once bytes are dropped, tag
// characters, and tokens or canaries hidden in the label. CleanLabel must
// give one printable terminal line of at most MaxPromptLabelLen bytes with
// none of them. Everything is synthetic.
package connector_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// labelSafe reports why s is not a safe single terminal line ("" if safe).
func labelSafe(s string) string {
	if len(s) > connector.MaxPromptLabelLen {
		return "over MaxPromptLabelLen"
	}
	if !utf8.ValidString(s) {
		return "invalid UTF-8"
	}
	for _, r := range s {
		switch {
		case r == '\x1b' || r == '\a' || r == '\b' || r == '\r' || r == '\n' || r == 0x7f:
			return "control character " + string(rune('0'+r%10))
		case unicode.IsControl(r):
			return "C0/C1 control"
		case unicode.Is(unicode.Cf, r):
			return "format character (bidi, zero width, tag)"
		case unicode.In(r, unicode.Zl, unicode.Zp):
			return "line or paragraph separator"
		case r >= 0xE000 && r <= 0xF8FF, r >= 0xF0000:
			return "private use"
		case !unicode.IsPrint(r):
			return "not printable"
		}
	}
	return ""
}

var hostileLabels = []string{
	"Code\x1b[2J\x1b[H facto: master password",
	"Code\x1b]52;c;ZmFjdG8tY2xpcGJvYXJk\a",
	"Code\x1b]52;c;ZmFjdG8tY2xpcGJvYXJk\x1b\\",
	"Code\x1b]8;;https://evil.test/\x1b\\click\x1b]8;;\x1b\\",
	"Code\x1b]0;facto - Bitwarden unlock\a",
	"Code\x1bP+q544e\x1b\\",
	"Code\x1b_hidden apc\x1b\\",
	"Code\x1b^hidden pm\x1b\\",
	"Code\x1bXhidden sos\x1b\\",
	"Code\u009b2J\u009b31m",
	"Code\u009d52;c;ZmFjdG8\u009c",
	"Code\u0090q\u009c",
	"Code\x1b[",
	"Code\x1b]52;c;never terminated",
	"Code\x1b\x1b[[31m",
	"Code\x1b\xff[2J",
	"Code\xc2\x9b2J",
	"Code\xc2[2J",
	"Code\x1b\x00[2J",
	"Code\x1bc reset",
	"Code\x1b7\x1b8 save restore",
	"Code \u202eedoc ruoy retne\u202c please",
	"Code \u2066\u2067\u2068\u2069\u061c\u200e\u200f",
	"Code \u202a\u202b\u202d",
	"Code\u2028facto: enter your master password\u2029",
	"Code\u0085next line",
	"Code\rfacto: enter your Bitwarden master password",
	"Code\nfacto: enter your Bitwarden master password",
	"Code\b\b\b\bfacto password",
	"Code\u200b\u200c\u200d\ufeff\u2060",
	"Code\U000e0041\U000e0042\U000e007f",
	"Code\ue000\U000f0000",
	"Code\x00\x01\x02\x7f",
	"Code\t\t\ttabs",
	"\x1b[8mhidden\x1b[28m",
	strings.Repeat("\x1b[31m", 200) + "Code",
	strings.Repeat("\u00e9", 200),
	strings.Repeat("a\u0301", 100),
}

// TestAttack_PromptLabelEscapesAndBidiNeutralised: every hostile label
// comes out as one safe line; no ESC, C1 or bidi control survives,
// whatever is around it.
func TestAttack_PromptLabelEscapesAndBidiNeutralised(t *testing.T) {
	t.Parallel()
	for _, l := range hostileLabels {
		got := connector.PromptRequest{Label: l}.CleanLabel()
		if why := labelSafe(got); why != "" {
			t.Errorf("CleanLabel(%q) = %q: %s", l, got, why)
		}
		for _, frag := range []string{"52;c;", "]8;;", "2J", "31m", "[H"} {
			if strings.Contains(l, "\x1b"+frag) || strings.Contains(l, "\x1b["+frag) {
				if strings.Contains(got, "\x1b") {
					t.Errorf("CleanLabel(%q) kept an escape", l)
				}
			}
		}
	}
}

// TestAttack_PromptLabelRandomHostileMix: random mixes of introducers,
// terminators, controls, format characters and invalid bytes never
// produce an unsafe line (property test, fixed seed).
func TestAttack_PromptLabelRandomHostileMix(t *testing.T) {
	t.Parallel()
	atoms := []string{
		"\x1b", "[", "]", "P", "X", "^", "_", "\\", "\a", ";", "52", "c", "2J", "m", "\x9b", "\xc2",
		"\u009b", "\u009d", "\u009c", "\u0090", "\u202e", "\u2066", "\u200f", "\u2028", "\r", "\n", "\b",
		"\x00", "\x7f", "\xff", "\xe2\x80", "\u00e9", "Code", " ", "\t", "\U000e0041", "\ufeff",
	}
	rng := lcg(27)
	for i := range 20000 {
		var b strings.Builder
		for range rng.intn(40) {
			b.WriteString(atoms[rng.intn(len(atoms))])
		}
		in := b.String()
		got := connector.PromptRequest{Label: in}.CleanLabel()
		if why := labelSafe(got); why != "" {
			t.Fatalf("case %d: CleanLabel(%q) = %q: %s", i, in, got, why)
		}
	}
}

// TestAttack_PromptLabelHidesTokens: a supplier label quoting a session
// token, a JWT, a URL query or a canary does not echo them to the
// terminal, even when the token straddles the length cap.
func TestAttack_PromptLabelHidesTokens(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	ck := testsecrets.Canary(t, testsecrets.Cookie)
	// The synthetic JWT is built at run time so that no JWT-shaped literal
	// sits in the source for secret scanners (SEC-J1-9). It is the same
	// value as before: {"alg":"HS256"}.{"sub":"synthetic"}.synthetic-sig.
	b64 := base64.RawURLEncoding.EncodeToString
	jwt := b64([]byte(`{"alg":"HS256"}`)) + "." + b64([]byte(`{"sub":"synthetic"}`)) + "." + b64([]byte("synthetic-sig"))
	for _, l := range []string{
		"Enter the code sent to you (ref " + tok + ")",
		"Code for https://login.supplier.example/otp?session=" + ck,
		"Code (session=" + ck + ")",
		"Code " + jwt,
		strings.Repeat("x", connector.MaxPromptLabelLen-10) + " " + tok,
		"Code\x1b]8;;https://evil.test/?t=" + tok + "\x1b\\link",
		"Code \u202e" + tok,
	} {
		got := connector.PromptRequest{Label: l}.CleanLabel()
		for _, s := range []string{tok, ck, jwt, tok[:24], ck[:24]} {
			if strings.Contains(got, s) {
				t.Errorf("CleanLabel kept a token: %q", got)
			}
		}
	}
}

// lcg is a deterministic 64-bit linear congruential sequence (Knuth MMIX
// constants): the property test must be reproducible, not unpredictable.
type lcg uint64

func (l *lcg) intn(n int) int {
	*l = *l*6364136223846793005 + 1442695040888963407
	return int(uint64(*l>>33) % uint64(n)) //nolint:gosec // n is a small positive slice length
}
