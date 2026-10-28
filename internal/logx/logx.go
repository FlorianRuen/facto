// Package logx provides the redacting slog handler every facto logger goes
// through (CLAUDE.md rule 5). It masks values by key (cookie, authorization,
// token, password, session…) at any group depth, masks token patterns (JWT,
// long base64, URL query strings and userinfo) in messages and string values,
// renders errors and arbitrary values to cleaned, length-capped strings, and
// resolves slog.LogValuer first so types such as secrets.Secret mask
// themselves. See docs/spec.md "Data in memory and in output".
//
// logx imports only the standard library so that every other package,
// internal/secrets included, can use it without an import cycle.
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

// defaultKeys are the sensitive key fragments, matched against the
// lowercased attribute key with strings.Contains.
var defaultKeys = []string{
	"cookie", "authorization", "token", "password", "passwd", "passphrase",
	"secret", "session", "apikey", "api_key", "api-key", "credential",
}

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
	keys   []string // lowercased sensitive fragments
	maxErr int
	// masked is set once a sensitive WithGroup name was opened: every
	// attribute logged inside it is masked.
	masked bool
}

// NewHandler returns a Handler redacting records before inner sees them.
func NewHandler(inner slog.Handler, opts Options) *Handler {
	keys := slices.Clone(defaultKeys)
	for _, k := range opts.Keys {
		// An empty fragment would match every key.
		if k = strings.ToLower(k); k != "" {
			keys = append(keys, k)
		}
	}
	maxErr := opts.MaxErrorLen
	if maxErr <= 0 {
		maxErr = DefaultMaxErrorLen
	}
	return &Handler{inner: inner, keys: keys, maxErr: maxErr}
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

// WithGroup returns a handler nesting later attributes under name. A
// sensitive name masks every attribute logged inside the group.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.inner = h.inner.WithGroup(name)
	c.masked = h.masked || h.sensitive(name)
	return &c
}

// sensitive reports whether key, lowercased, contains a sensitive fragment.
func (h *Handler) sensitive(key string) bool {
	k := strings.ToLower(key)
	for _, f := range h.keys {
		if strings.Contains(k, f) {
			return true
		}
	}
	return false
}

// redact returns a copy of a that is safe to hand to the inner handler.
// masked forces every leaf value to Mask.
func (h *Handler) redact(a slog.Attr, masked bool) slog.Attr {
	if a.Equal(slog.Attr{}) {
		return a // slog ignores empty attrs: keep it empty
	}
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		// An inline group (empty key) is not itself a key to match.
		if a.Key != "" && (masked || h.sensitive(a.Key)) {
			return slog.String(a.Key, Mask)
		}
		group := v.Group()
		red := make([]slog.Attr, len(group))
		for i, ga := range group {
			red[i] = h.redact(ga, masked)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(red...)}
	}
	if masked || h.sensitive(a.Key) {
		return slog.String(a.Key, Mask)
	}
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, Clean(v.String()))
	case slog.KindAny:
		return slog.String(a.Key, h.render(v.Any()))
	case slog.KindBool, slog.KindDuration, slog.KindFloat64, slog.KindInt64,
		slog.KindTime, slog.KindUint64:
		return slog.Attr{Key: a.Key, Value: v} // no secret shape
	case slog.KindGroup, slog.KindLogValuer:
		// Unreachable: groups are handled above and Resolve never returns
		// a LogValuer. Mask rather than trust it.
		return slog.String(a.Key, Mask)
	}
	return slog.String(a.Key, Mask) // a future Kind: fail closed
}

// render turns an arbitrary value into a cleaned string, so the inner
// handler never dumps a raw struct, map or slice. Errors are also stripped
// of control characters and capped.
func (h *Handler) render(x any) string {
	switch t := x.(type) {
	case error:
		return h.cleanError(t.Error())
	case fmt.Stringer:
		return Clean(t.String())
	default:
		return Clean(fmt.Sprintf("%+v", x))
	}
}

// cleanError applies Clean, replaces control characters by a space and cuts
// the result to maxErr bytes on a rune boundary. Cleaning happens before
// cutting so a token straddling the cap is still recognised.
func (h *Handler) cleanError(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, Clean(s))
	if len(s) <= h.maxErr {
		return s
	}
	cut := h.maxErr
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + TruncatedSuffix
}
