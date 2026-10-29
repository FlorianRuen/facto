package connector

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// SecretResolver resolves bw://, keyring://… references. *secret.Resolver
// satisfies it.
type SecretResolver interface {
	Resolve(ctx context.Context, ref string) (secret.Secret, error)
}

// Credentials holds secret REFERENCES (bw://…, keyring://…), never values.
// OTP resolves to a code, never a seed. An empty field is not configured.
type Credentials struct {
	Login, Password, OTP string
}

// Persistable is optionally implemented by the Session a connector's Login
// returns. The orchestrator type-asserts it after a successful login, stores
// the blob encrypted, and hands it back as Env.Saved on the next run.
// Sessions that do not implement it are never saved.
type Persistable interface {
	Persist(ctx context.Context) (secret.Secret, error)
}

// MaxPromptLabelLen caps CleanLabel's output, in bytes.
const MaxPromptLabelLen = 128

// PromptRequest is what a connector asks the user. Label may come from the
// supplier site and is untrusted: Prompter implementations display
// CleanLabel(), never Label.
type PromptRequest struct {
	Label string
}

// CleanLabel returns Label safe for one terminal line:
//   - ANSI escape sequences are removed whole: CSI (ESC '[' or the 8-bit
//     U+009B, up to the final byte 0x40–0x7E), OSC (ESC ']' or U+009D, up
//     to BEL or the string terminator ST, ESC '\' or U+009C), and DCS, SOS,
//     PM, APC (ESC 'P', 'X', '^', '_' or U+0090, U+0098, U+009E, U+009F, up
//     to ST); an unterminated sequence drops the rest of the label;
//   - \t, \r, \n become a space; every other rune that is not
//     unicode.IsPrint (C0, C1, DEL, bidi and other format characters,
//     line/paragraph separators) is removed; invalid UTF-8 bytes are removed;
//   - logx.Clean masks token-like content (URL queries, JWTs, base64 runs);
//   - leading and trailing spaces are trimmed;
//   - the result is cut to MaxPromptLabelLen bytes on a rune boundary.
//
// Clean runs before the cut so a token straddling the cap is still masked.
func (r PromptRequest) CleanLabel() string {
	s := strings.TrimSpace(logx.Clean(stripTerminal(r.Label)))
	if len(s) <= MaxPromptLabelLen {
		return s
	}
	cut := MaxPromptLabelLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut])
}

// Escape-sequence introducers and terminators.
const (
	esc     = '\x1b'
	bel     = '\x07'
	csi8    = '\u009b'
	osc8    = '\u009d'
	st8     = '\u009c'
	dcs8    = '\u0090'
	sos8    = '\u0098'
	pm8     = '\u009e'
	apc8    = '\u009f'
	csiLow  = 0x40 // CSI final byte range, inclusive
	csiHigh = 0x7e
)

// stripTerminal removes ANSI CSI, OSC, DCS, SOS, PM and APC sequences whole, turns \t, \r, \n
// into a space and drops every other non-printable rune and invalid byte.
func stripTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == esc && i+1 < len(s) && s[i+1] == '[':
			i = skipCSI(s, i+2)
			continue
		case r == esc && i+1 < len(s) && s[i+1] == ']':
			i = skipString(s, i+2, true)
			continue
		case r == esc && i+1 < len(s) && isStringIntro(s[i+1]):
			i = skipString(s, i+2, false)
			continue
		case r == csi8:
			i = skipCSI(s, i+size)
			continue
		case r == osc8:
			i = skipString(s, i+size, true)
			continue
		case r == dcs8 || r == sos8 || r == pm8 || r == apc8:
			i = skipString(s, i+size, false)
			continue
		case r == '\t' || r == '\r' || r == '\n':
			b.WriteByte(' ')
		case r == utf8.RuneError && size == 1:
			// invalid UTF-8 byte: dropped
		case unicode.IsPrint(r):
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// skipCSI returns the index just past the CSI final byte at or after i, or
// len(s) when the sequence is unterminated.
func skipCSI(s string, i int) int {
	for ; i < len(s); i++ {
		if c := s[i]; c >= csiLow && c <= csiHigh {
			return i + 1
		}
	}
	return len(s)
}

// isStringIntro reports whether ESC c opens a DCS, SOS, PM or APC string.
func isStringIntro(c byte) bool {
	return c == 'P' || c == 'X' || c == '^' || c == '_'
}

// skipString returns the index just past the string terminator (ST: ESC '\'
// or U+009C; also BEL when belEnds, as for OSC) at or after i, or len(s)
// when the sequence is unterminated.
func skipString(s string, i int, belEnds bool) int {
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == st8 || belEnds && r == bel:
			return i + size
		case r == esc && i+1 < len(s) && s[i+1] == '\\':
			return i + 2
		}
		i += size
	}
	return len(s)
}

// Prompter asks the interactive user for a value such as an OTP code; the
// answer is a secret.Secret. A non-interactive Prompter returns an error
// wrapping ErrNeedsLogin.
type Prompter interface {
	Prompt(ctx context.Context, req PromptRequest) (secret.Secret, error)
	Interactive() bool
}

// LaunchOptions configures one browser for one login.
type LaunchOptions struct {
	AllowedDomains []string // connector Info().AllowedDomains
	Visible        bool     // headful window; only when interactive
}

// BrowserPool hands out library-neutral browsers.
type BrowserPool interface {
	Launch(ctx context.Context, opts LaunchOptions) (Browser, error)
}

// Browser is the library-neutral page API. No method takes or returns a
// secret as a plain string.
type Browser interface {
	Navigate(ctx context.Context, url string) error
	WaitVisible(ctx context.Context, selector string) error
	TypeSecret(ctx context.Context, selector string, value secret.Secret) error
	Click(ctx context.Context, selector string) error
	CurrentURL(ctx context.Context) (string, error)
	Cookies(ctx context.Context, domains []string) ([]Cookie, error)
	Close() error
}

// Cookie is one browser cookie; its value is a secret.
type Cookie struct {
	Name     string
	Value    secret.Secret
	Domain   string
	Path     string
	Expires  time.Time // zero = session cookie
	Secure   bool
	HTTPOnly bool
}
