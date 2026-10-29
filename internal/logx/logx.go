// Package logx provides the redacting slog handler every facto logger goes
// through (CLAUDE.md rule 5). It cleans attribute keys and group names like
// messages, masks values by key (cookie, authorization,
// token, password, session…) at any group depth, masks token patterns (JWT,
// long base64, the query string and userinfo of URLs of any scheme, the raw
// URL quoted by net/url parse errors, the value after a sensitive key or a
// Bearer/Basic scheme in free text) in messages and string values, walks composite values (maps, structs,
// slices) to mask sensitive map keys of any key type, struct fields and byte
// values, renders url.URL without userinfo, query values or fragment, masks
// url.Userinfo, renders an http.Cookie as its name only, never prints a
// value implementing io.Reader or io.Writer (bodies, buffers, builders), and
// fails closed on every other type of net/http, net/url,
// net/http/cookiejar and crypto/... (requests, responses, clients, jars,
// TLS configurations, keys), whose String or Error is never called, even
// when promoted to a struct that embeds it. It renders errors and arbitrary
// values to cleaned, length-capped strings, and resolves slog.LogValuer
// first so types such as secret.Secret mask themselves. See docs/spec.md
// "Data in memory and in output".
//
// logx imports only the standard library so that every other package,
// internal/secret included, can use it without an import cycle.
package logx

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"unicode/utf8"
)

// Mask replaces every redacted value or token.
const Mask = "***"

// DefaultMaxErrorLen caps rendered errors when Options.MaxErrorLen is 0.
const DefaultMaxErrorLen = 512

// TruncatedSuffix ends an error string that was cut.
const TruncatedSuffix = "…[truncated]"

// defaultKeys are the sensitive key fragments. A fragment of more than
// shortFragment bytes matches when the lowercased key contains it; a shorter
// one must equal a whole word of the key (see words), so "auth" masks
// "X-Auth" and "basicAuth" but not "author", and "code", "pin" and "key"
// mask "otp_code", "PinCode" and "X-Key" but not "barcode", "pincode" or
// "keyboard". The rule is lexical: "country_code" and "status_code" are
// masked too, an accepted loss of log detail.
var defaultKeys = []string{
	"cookie", "authorization", "token", "password", "passwd", "passphrase",
	"secret", "session", "apikey", "api_key", "api-key", "credential",
	"pwd", "pass", "auth", "otp", "totp", "bearer", "jwt", "csrf", "xsrf", "sid",
	"sessid", "mdp", "motdepasse", "mot_de_passe", "code", "pin", "key",
}

// shortFragment is the length up to which a fragment matches whole words
// only.
const shortFragment = 4

// Options configures a Handler.
type Options struct {
	// Keys adds sensitive key fragments to the defaults (same matching).
	Keys []string
	// MaxErrorLen caps the byte length of a rendered error before
	// TruncatedSuffix is appended. 0 means DefaultMaxErrorLen.
	MaxErrorLen int
}

// Handler wraps an inner slog.Handler and redacts every record before
// passing it on. It is immutable and safe for concurrent use.
type Handler struct {
	inner  slog.Handler
	frag   fragments // sensitive key fragments, defaults plus Options.Keys
	maxErr int
	// masked is set once a sensitive WithGroup name was opened: every
	// attribute logged inside it is masked.
	masked bool
}

// NewHandler returns a Handler redacting records before inner sees them.
func NewHandler(inner slog.Handler, opts Options) *Handler {
	h := &Handler{
		inner:  inner,
		maxErr: opts.MaxErrorLen,
		frag:   splitFragments(slices.Concat(defaultKeys, opts.Keys)),
	}
	if h.maxErr <= 0 {
		h.maxErr = DefaultMaxErrorLen
	}
	return h
}

// Enabled delegates to the inner handler.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

// Handle redacts the message and every attribute of r, then calls the inner
// handler with the redacted copy.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, Clean(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.redact(a, h.masked))
		return true
	})
	if err := h.inner.Handle(ctx, out); err != nil {
		return fmt.Errorf("logx: inner handler: %w", err)
	}
	return nil
}

// WithAttrs redacts attrs and returns a handler carrying them.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = h.redact(a, h.masked)
	}
	c := *h
	c.inner = h.inner.WithAttrs(red)
	return &c
}

// WithGroup returns a handler nesting later attributes under name, cleaned
// like every attribute key (see cleanKey). A sensitive name masks every
// attribute logged inside the group.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.inner = h.inner.WithGroup(cleanKey(name))
	c.masked = h.masked || h.sensitive(name)
	return &c
}

// cleanKey makes an attribute key or group name safe to write: a buggy
// caller may use a secret as the key (log.Info("m", tok, true)). Token
// patterns are masked by Clean and control characters are removed so a key
// cannot forge log lines. Sensitivity is still decided on the original key.
func cleanKey(k string) string {
	if k == "" {
		return k
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, Clean(k))
}

// sensitive reports whether key, lowercased, contains a long sensitive
// fragment or has a short one as a whole word.
func (h *Handler) sensitive(key string) bool {
	return h.frag.match(key)
}

// isWord reports whether s is made of ASCII letters and digits only.
func isWord(s string) bool {
	for i := range len(s) {
		if !isAlnum(s[i]) {
			return false
		}
	}
	return true
}

// words splits key into lowercased words on non-alphanumeric bytes and on
// lower→Upper camelCase boundaries: "X-Auth_header" → x, auth, header;
// "basicAuth" → basic, auth; "PHPSESSID" → phpsessid.
func words(key string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(key); i++ {
		boundary := i == len(key) || !isAlnum(key[i])
		camel := !boundary && i > 0 && 'A' <= key[i] && key[i] <= 'Z' && 'a' <= key[i-1] && key[i-1] <= 'z'
		if (boundary || camel) && start >= 0 {
			out = append(out, strings.ToLower(key[start:i]))
			start = -1
		}
		if !boundary && start < 0 {
			start = i
		}
	}
	return out
}

// redact returns a copy of a that is safe to hand to the inner handler: its
// key and every nested group name go through cleanKey, its values through
// Clean or Mask. masked forces every leaf value to Mask.
func (h *Handler) redact(a slog.Attr, masked bool) slog.Attr {
	if a.Equal(slog.Attr{}) {
		return a // slog ignores empty attrs: keep it empty
	}
	v := a.Value.Resolve()
	key := cleanKey(a.Key)
	if v.Kind() == slog.KindGroup {
		// An inline group (empty key) is not itself a key to match.
		if a.Key != "" && (masked || h.sensitive(a.Key)) {
			return slog.String(key, Mask)
		}
		group := v.Group()
		red := make([]slog.Attr, len(group))
		for i, ga := range group {
			red[i] = h.redact(ga, masked)
		}
		return slog.Attr{Key: key, Value: slog.GroupValue(red...)}
	}
	if masked || h.sensitive(a.Key) {
		return slog.String(key, Mask)
	}
	switch v.Kind() {
	case slog.KindString:
		return slog.String(key, h.capStr(Clean(v.String()), false))
	case slog.KindAny:
		return slog.String(key, h.render(v.Any()))
	case slog.KindBool, slog.KindDuration, slog.KindFloat64, slog.KindInt64,
		slog.KindTime, slog.KindUint64:
		return slog.Attr{Key: key, Value: v} // no secret shape
	case slog.KindGroup, slog.KindLogValuer:
		// Unreachable: groups are handled above and Resolve never returns
		// a LogValuer. Mask rather than trust it.
		return slog.String(key, Mask)
	}
	return slog.String(key, Mask) // a future Kind: fail closed
}

// controlFree replaces control characters (U+0000–U+001F, U+007F) by a
// space, so an error cannot forge log lines.
func controlFree(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// capStr cuts s to maxErr bytes on a rune boundary and appends
// TruncatedSuffix when it was longer, or when force reports that content was
// already dropped. Callers clean s first so a token straddling the cap is
// still recognised.
func (h *Handler) capStr(s string, force bool) string {
	if len(s) <= h.maxErr {
		if force {
			return s + TruncatedSuffix
		}
		return s
	}
	cut := h.maxErr
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + TruncatedSuffix
}
