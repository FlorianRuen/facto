// Tests for package logx (J0 task T9): the redacting slog handler every
// facto logger goes through (CLAUDE.md rule 5). Spec: docs/spec.md "Data in
// memory and in output" and "Threat model" (leak in logs, reports, errors).
//
// Import rule: logx imports only the standard library. It must NOT import
// internal/secret (secret.Secret implements slog.LogValuer and is masked
// because the handler resolves LogValuers before anything else), so
// secrets' tests may use logx without an import cycle. These tests use a
// local LogValuer type instead of secret.Secret.
//
// Expected API (implementer: follow exactly):
//
//	// Mask replaces every redacted value or token.
//	const Mask = "***"
//
//	// DefaultMaxErrorLen caps rendered errors when Options.MaxErrorLen is 0.
//	const DefaultMaxErrorLen = 512
//
//	// TruncatedSuffix ends an error string that was cut.
//	const TruncatedSuffix = "…[truncated]"
//
//	type Options struct {
//	    // Keys adds sensitive key fragments to the defaults (same matching).
//	    Keys []string
//	    // MaxErrorLen caps the byte length of a rendered error before
//	    // TruncatedSuffix is appended. 0 means DefaultMaxErrorLen.
//	    MaxErrorLen int
//	}
//
//	// Handler wraps an inner slog.Handler (Text or JSON in practice) and
//	// redacts every record before passing it on. Safe for concurrent use;
//	// passes testing/slogtest.
//	type Handler struct{ /* unexported */ }
//	func NewHandler(inner slog.Handler, opts Options) *Handler
//	func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool // delegates to inner
//	func (h *Handler) Handle(ctx context.Context, r slog.Record) error
//	func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler     // attrs redacted too
//	func (h *Handler) WithGroup(name string) slog.Handler
//
// Redaction rules, applied to the message, to record attrs and to WithAttrs
// attrs, at any group depth:
//
//  1. LogValuers are resolved first (slog.Value.Resolve), so a type whose
//     LogValue masks it is never rendered through String/Error/fmt.
//  2. Sensitive keys: an attr whose key, lowercased, contains one of
//     "cookie", "authorization", "token", "password", "passwd", "passphrase",
//     "secret", "session", "apikey", "api_key", "api-key", "credential" (or a
//     lowercased Options.Keys entry) gets the string value Mask, whatever its
//     kind (a group under a sensitive key becomes the single string Mask).
//     A WithGroup name that is sensitive masks every attr logged inside it.
//  3. Errors (a KindAny value implementing error): rendered with Error(),
//     cleaned by rule 5, control characters (U+0000–U+001F, U+007F) replaced
//     by a space, then cut to MaxErrorLen bytes on a rune boundary with
//     TruncatedSuffix appended when cut. The inner handler gets a string.
//  4. Other KindAny values are rendered to a string (fmt.Stringer → String(),
//     otherwise fmt.Sprintf("%+v")) and cleaned by rule 5; the inner
//     handler never receives a raw struct, map or slice to dump.
//  5. Token patterns, applied to the message and every string value, in
//     this order (JWT first, so its parts are not masked piecemeal):
//     - JWT: "eyJ" followed by [A-Za-z0-9_-]*, ".", [A-Za-z0-9_-]*, ".",
//     [A-Za-z0-9_-]*  → Mask.
//     - Long base64: a maximal run of [A-Za-z0-9+/=_-] that contains at least
//     16 consecutive [A-Za-z0-9] characters which are neither all
//     lowercase hex [0-9a-f] (digests, numeric ids) nor all [a-z] (words)
//     → the whole run becomes Mask. File names, slugs, UUIDs, paths and
//     hex digests survive; testsecrets canaries ("FACTO-CANARY-<kind>-"
//     + ≥16 uppercase base32 chars) are masked.
//     - URLs (http:// or https://): userinfo is removed and everything from
//     the first "?" or "#" to the end of the URL becomes "?***".
//
// Keys, levels, times and non-sensitive scalar values (ints, bools,
// durations, plain strings) pass through unchanged.
package logx_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"testing/slogtest"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// jsonLogger returns a logger writing JSON lines through the redacting
// handler, and a function decoding the last line.
func jsonLogger(t *testing.T, opts logx.Options) (*slog.Logger, *bytes.Buffer, func() map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	l := slog.New(logx.NewHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}), opts))
	last := func() map[string]any {
		t.Helper()
		lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
			t.Fatalf("decode log line %q: %v", lines[len(lines)-1], err)
		}
		return m
	}
	return l, &buf, last
}

// lookup follows a dotted path ("http.header.cookie") in a decoded record.
func lookup(t *testing.T, m map[string]any, path string) any {
	t.Helper()
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("lookup %q: %q is not a group in %v", path, k, m)
		}
		cur, ok = mm[k]
		if !ok {
			t.Fatalf("lookup %q: key %q missing in %v", path, k, m)
		}
	}
	return cur
}

func TestHandler_MasksSensitiveKeys(t *testing.T) {
	t.Parallel()
	const v = "plain-value-42"
	sensitive := []string{
		"password", "Password", "PASSWORD", "user_password", "passwd", "passphrase",
		"cookie", "Cookie", "set-cookie", "Set-Cookie", "cookies",
		"authorization", "Authorization", "Proxy-Authorization",
		"token", "access_token", "refreshToken", "X-Auth-Token", "id_token",
		"session", "Session", "sessionid", "session_key",
		"secret", "client_secret", "apikey", "api_key", "X-Api-Key", "credentials",
	}
	for _, key := range sensitive {
		t.Run("masks "+key, func(t *testing.T) {
			t.Parallel()
			l, buf, last := jsonLogger(t, logx.Options{})
			l.Info("m", key, v)
			if got := last()[key]; got != logx.Mask {
				t.Errorf("%s = %v, want %q", key, got, logx.Mask)
			}
			if strings.Contains(buf.String(), v) {
				t.Errorf("output leaks the value: %s", buf)
			}
		})
	}

	kept := []string{"user", "provider", "status", "url", "host", "path", "count", "file", "content-type", "author", "kind"}
	for _, key := range kept {
		t.Run("keeps "+key, func(t *testing.T) {
			t.Parallel()
			l, _, last := jsonLogger(t, logx.Options{})
			l.Info("m", key, v)
			if got := last()[key]; got != v {
				t.Errorf("%s = %v, want %q kept", key, got, v)
			}
		})
	}
}

func TestHandler_MasksNonStringKinds(t *testing.T) {
	t.Parallel()
	l, _, last := jsonLogger(t, logx.Options{})
	l.Info("m",
		slog.Int("session_count", 3),
		slog.Bool("token", true),
		slog.Any("cookie", []string{"a=1", "b=2"}),
		slog.Any("password", errors.New("boom")),
		slog.Group("authorization", slog.String("scheme", "Bearer"), slog.String("value", "abc")),
	)
	m := last()
	for _, k := range []string{"session_count", "token", "cookie", "password", "authorization"} {
		if got := m[k]; got != logx.Mask {
			t.Errorf("%s = %#v, want %q (string)", k, got, logx.Mask)
		}
	}
}

func TestHandler_MasksNestedGroups(t *testing.T) {
	t.Parallel()
	const v = "nested-value-7"
	tests := []struct {
		name string
		log  func(l *slog.Logger)
		path string // dotted path of the masked value
		want any
	}{
		{
			name: "group attr",
			log:  func(l *slog.Logger) { l.Info("m", slog.Group("http", slog.String("Cookie", v))) },
			path: "http.Cookie", want: logx.Mask,
		},
		{
			name: "deep group",
			log: func(l *slog.Logger) {
				l.Info("m", slog.Group("http", slog.Group("request", slog.Group("header", slog.String("Authorization", v)))))
			},
			path: "http.request.header.Authorization", want: logx.Mask,
		},
		{
			name: "sibling kept",
			log: func(l *slog.Logger) {
				l.Info("m", slog.Group("http", slog.String("Cookie", v), slog.String("method", "GET")))
			},
			path: "http.method", want: "GET",
		},
		{
			name: "WithGroup then attr",
			log:  func(l *slog.Logger) { l.WithGroup("http").Info("m", "token", v) },
			path: "http.token", want: logx.Mask,
		},
		{
			name: "WithAttrs",
			log:  func(l *slog.Logger) { l.With("authorization", v).Info("m") },
			path: "authorization", want: logx.Mask,
		},
		{
			name: "WithGroup then WithAttrs",
			log:  func(l *slog.Logger) { l.WithGroup("a").With(slog.Group("b", "password", v)).Info("m") },
			path: "a.b.password", want: logx.Mask,
		},
		{
			name: "sensitive WithGroup masks everything inside",
			log:  func(l *slog.Logger) { l.WithGroup("session").Info("m", "id", v, "user", "u1") },
			path: "session.id", want: logx.Mask,
		},
		{
			name: "sensitive WithGroup masks WithAttrs inside",
			log:  func(l *slog.Logger) { l.WithGroup("Cookies").With("sid", v).Info("m") },
			path: "Cookies.sid", want: logx.Mask,
		},
		{
			name: "sensitive group key masks whole group",
			log:  func(l *slog.Logger) { l.Info("m", slog.Group("session", slog.String("id", v))) },
			path: "session", want: logx.Mask,
		},
		{
			name: "inline group (empty key)",
			log:  func(l *slog.Logger) { l.Info("m", slog.Group("", slog.String("password", v))) },
			path: "password", want: logx.Mask,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, buf, last := jsonLogger(t, logx.Options{})
			tc.log(l)
			if got := lookup(t, last(), tc.path); got != tc.want {
				t.Errorf("%s = %#v, want %#v", tc.path, got, tc.want)
			}
			if strings.Contains(buf.String(), v) {
				t.Errorf("output leaks the value: %s", buf)
			}
		})
	}
}

func TestHandler_ExtraKeys(t *testing.T) {
	t.Parallel()
	l, _, last := jsonLogger(t, logx.Options{Keys: []string{"IBAN"}})
	l.Info("m", "iban", "FR00-synthetic", "account_iban", "FR00-synthetic", "password", "x", "user", "u1")
	m := last()
	for k, want := range map[string]any{"iban": logx.Mask, "account_iban": logx.Mask, "password": logx.Mask, "user": "u1"} {
		if got := m[k]; got != want {
			t.Errorf("%s = %#v, want %#v", k, got, want)
		}
	}
}

// Synthetic tokens built from synthetic content.
var (
	jwtHeader  = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	jwtPayload = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"synthetic-user","iat":1700000000}`))
	jwtSig     = base64.RawURLEncoding.EncodeToString([]byte("synthetic-signature-bytes"))
	jwt        = jwtHeader + "." + jwtPayload + "." + jwtSig
	// Unsigned JWT with tiny parts: only the JWT rule catches it.
	jwtShortPayload = base64.RawURLEncoding.EncodeToString([]byte(`{"x":1}`))
	jwtShort        = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + jwtShortPayload + "."
	b64Std          = base64.StdEncoding.EncodeToString([]byte("synthetic opaque session bytes 0123"))
	b64URL          = base64.RawURLEncoding.EncodeToString([]byte("\xfb\xff synthetic url-safe token bytes \xfe"))
)

func TestHandler_MasksTokenPatterns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		in        string
		forbidden []string // must not appear
		kept      []string // must appear
		removed   bool     // forbidden parts are dropped, not replaced by Mask
	}{
		{name: "jwt alone", in: jwt, forbidden: []string{jwtHeader, jwtPayload, jwtSig}},
		{name: "jwt in sentence", in: "got id " + jwt + " from sso", forbidden: []string{jwtPayload, jwtSig}, kept: []string{"got id ", " from sso"}},
		{name: "short unsigned jwt", in: "t=" + jwtShort, forbidden: []string{jwtShortPayload}},
		{name: "bearer jwt", in: "Bearer " + jwt, forbidden: []string{jwtPayload}, kept: []string{"Bearer "}},
		{name: "std base64", in: "blob " + b64Std + " end", forbidden: []string{b64Std, b64Std[:20]}, kept: []string{"blob ", " end"}},
		{name: "url-safe base64", in: "sid=" + b64URL, forbidden: []string{b64URL[4:24]}},
		{name: "uppercase base32 run", in: "code ABCDEFGHJKMNPQRSTUVWXYZ234 ok", forbidden: []string{"ABCDEFGHJKMNPQRSTUVWXYZ234"}, kept: []string{"code ", " ok"}},
		{
			name:      "url query and fragment",
			in:        "GET https://api.fournisseur.test/invoices/2026?ticket=q1w2e3&page=2#frag done",
			forbidden: []string{"ticket", "q1w2e3", "page=2", "frag"},
			kept:      []string{"https://api.fournisseur.test/invoices/2026?***", " done"},
		},
		{
			name:      "url userinfo",
			in:        "dial https://someone:" + "zz-userinfo-pw" + "@api.fournisseur.test/x",
			forbidden: []string{"someone", "zz-userinfo-pw", "@"},
			kept:      []string{"dial https://api.fournisseur.test/x"},
			removed:   true,
		},
		// Benign values survive untouched.
		{name: "file name", in: "2026-03-15_bouygues-telecom_facture-internet_84-12EUR.pdf", kept: []string{"2026-03-15_bouygues-telecom_facture-internet_84-12EUR.pdf"}},
		{name: "sha256 hex", in: "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", kept: []string{"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}},
		{name: "uuid", in: "item 3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90", kept: []string{"3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90"}},
		{name: "api path", in: "/api/v1/invoices/2026/download", kept: []string{"/api/v1/invoices/2026/download"}},
		{name: "url without query", in: "https://api.fournisseur.test/invoices/list", kept: []string{"https://api.fournisseur.test/invoices/list"}},
		{name: "long numeric id", in: "invoice 12345678901234567890", kept: []string{"12345678901234567890"}},
		{name: "long word", in: "internationalization", kept: []string{"internationalization"}},
		{name: "sentence", in: "connector bouyguestelecom: needs login", kept: []string{"connector bouyguestelecom: needs login"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, buf, last := jsonLogger(t, logx.Options{})
			l.Info(tc.in, "note", tc.in, slog.Group("g", "detail", tc.in))
			m := last()
			for _, got := range []string{m["msg"].(string), m["note"].(string), lookup(t, m, "g.detail").(string)} {
				for _, f := range tc.forbidden {
					if strings.Contains(got, f) {
						t.Errorf("%q not masked in %q", f, got)
					}
				}
				for _, k := range tc.kept {
					if !strings.Contains(got, k) {
						t.Errorf("%q lost in %q", k, got)
					}
				}
				if len(tc.forbidden) > 0 && !tc.removed && !strings.Contains(got, logx.Mask) {
					t.Errorf("%q has no %q marker", got, logx.Mask)
				}
			}
			if len(tc.forbidden) == 0 && strings.Contains(buf.String(), logx.Mask) {
				t.Errorf("benign value was masked: %s", buf)
			}
		})
	}
}

// leakyError prints its value through String and Error but masks it
// through LogValue, like secret.Secret must.
type leakyError struct{ v string }

func (l leakyError) String() string     { return l.v }
func (l leakyError) Error() string      { return l.v }
func (leakyError) LogValue() slog.Value { return slog.StringValue(logx.Mask) }

// account resolves to a group with a sensitive member.
type account struct{ user, pw string }

func (a account) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user", a.user), slog.String("password", a.pw))
}

// tokenHolder resolves to a string carrying a token pattern.
type tokenHolder struct{ tok string }

func (h tokenHolder) LogValue() slog.Value { return slog.StringValue("bearer " + h.tok) }

func TestHandler_HonorsLogValuer(t *testing.T) {
	t.Parallel()
	const v = "leaky-value-99"
	tests := []struct {
		name string
		log  func(l *slog.Logger)
		path string
		want any
	}{
		{name: "masking LogValuer", log: func(l *slog.Logger) { l.Info("m", "cred", leakyError{v}) }, path: "cred", want: logx.Mask},
		{name: "masking LogValuer in group", log: func(l *slog.Logger) { l.Info("m", slog.Group("g", "cred", leakyError{v})) }, path: "g.cred", want: logx.Mask},
		{name: "masking LogValuer in WithAttrs", log: func(l *slog.Logger) { l.With("cred", leakyError{v}).Info("m") }, path: "cred", want: logx.Mask},
		{name: "masking LogValuer as error key", log: func(l *slog.Logger) { l.Info("m", "err", leakyError{v}) }, path: "err", want: logx.Mask},
		{name: "resolved group gets key masking", log: func(l *slog.Logger) { l.Info("m", "acct", account{user: "u1", pw: v}) }, path: "acct.password", want: logx.Mask},
		{name: "resolved group keeps other keys", log: func(l *slog.Logger) { l.Info("m", "acct", account{user: "u1", pw: v}) }, path: "acct.user", want: "u1"},
		{name: "resolved string gets pattern masking", log: func(l *slog.Logger) { l.Info("m", "h", tokenHolder{jwt}) }, path: "h", want: "bearer " + logx.Mask},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, buf, last := jsonLogger(t, logx.Options{})
			tc.log(l)
			if got := lookup(t, last(), tc.path); got != tc.want {
				t.Errorf("%s = %#v, want %#v", tc.path, got, tc.want)
			}
			for _, leak := range []string{v, jwtPayload} {
				if strings.Contains(buf.String(), leak) {
					t.Errorf("output leaks %q: %s", leak, buf)
				}
			}
		})
	}
}

func TestHandler_RendersAnyAsCleanString(t *testing.T) {
	t.Parallel()
	type creds struct {
		User  string
		Value string
	}
	u, err := url.Parse("https://api.fournisseur.test/download?sig=zz-synthetic-sig")
	if err != nil {
		t.Fatal(err)
	}
	l, buf, last := jsonLogger(t, logx.Options{})
	l.Info("m", "obj", creds{User: "u1", Value: jwt}, "u", u, "list", []string{"a", b64Std})
	m := last()
	for _, k := range []string{"obj", "u", "list"} {
		if _, ok := m[k].(string); !ok {
			t.Errorf("%s = %#v (%T), want a string", k, m[k], m[k])
		}
	}
	if s, _ := m["obj"].(string); !strings.Contains(s, "u1") {
		t.Errorf("obj = %q, want the non-sensitive field kept", s)
	}
	for _, leak := range []string{jwtPayload, "zz-synthetic-sig", b64Std} {
		if strings.Contains(buf.String(), leak) {
			t.Errorf("output leaks %q: %s", leak, buf)
		}
	}
}

func TestHandler_TruncatesErrors(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("é", 2000) // 4000 bytes, multi-byte runes
	tests := []struct {
		name      string
		maxLen    int
		err       error
		wantLimit int // max bytes before the suffix
		wantCut   bool
		forbidden []string
		kept      []string
	}{
		{name: "default cap", err: errors.New(long), wantLimit: logx.DefaultMaxErrorLen, wantCut: true},
		{name: "custom cap", maxLen: 64, err: errors.New(long), wantLimit: 64, wantCut: true},
		{name: "short error kept", err: errors.New("connector: needs login"), wantLimit: logx.DefaultMaxErrorLen, kept: []string{"connector: needs login"}},
		{
			name:      "control characters cleaned",
			err:       errors.New("line1\nINFO forged=entry\r\x1b[31mred\ttab\x00nul"),
			wantLimit: logx.DefaultMaxErrorLen,
			forbidden: []string{"\n", "\r", "\x1b", "\x00", "\t"},
			kept:      []string{"line1", "forged=entry", "red", "tab", "nul"},
		},
		{
			name:      "url query stripped from wrapped error",
			err:       fmt.Errorf("list invoices: %w", &url.Error{Op: "Get", URL: "https://api.fournisseur.test/inv?code=zz-synthetic-code", Err: io.ErrUnexpectedEOF}),
			wantLimit: logx.DefaultMaxErrorLen,
			forbidden: []string{"zz-synthetic-code", "code="},
			kept:      []string{"list invoices", "api.fournisseur.test/inv", "unexpected EOF"},
		},
		{
			name:      "token in error",
			err:       fmt.Errorf("decode: unexpected %s", jwt),
			wantLimit: logx.DefaultMaxErrorLen,
			forbidden: []string{jwtPayload},
			kept:      []string{"decode: unexpected"},
		},
		{
			// Cleaning happens before cutting: cutting first would leave a
			// token prefix too short for the base64 rule.
			name:      "token straddling the cap masked before cutting",
			maxLen:    64,
			err:       fmt.Errorf("%s%s", strings.Repeat("x ", 25), b64Std),
			wantLimit: 64,
			forbidden: []string{b64Std[:12]},
			kept:      []string{"x x x"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, _, last := jsonLogger(t, logx.Options{MaxErrorLen: tc.maxLen})
			l.Error("failed", "err", tc.err)
			got, ok := last()["err"].(string)
			if !ok {
				t.Fatalf("err = %#v, want a string", last()["err"])
			}
			if !utf8.ValidString(got) {
				t.Errorf("err is not valid UTF-8: %q", got)
			}
			body, cut := strings.CutSuffix(got, logx.TruncatedSuffix)
			if cut != tc.wantCut {
				t.Errorf("truncated = %v, want %v (len %d)", cut, tc.wantCut, len(got))
			}
			if len(body) > tc.wantLimit {
				t.Errorf("err body is %d bytes, want <= %d", len(body), tc.wantLimit)
			}
			if tc.wantCut && len(body) < tc.wantLimit-utf8.UTFMax {
				t.Errorf("err body is %d bytes, want close to the cap %d", len(body), tc.wantLimit)
			}
			for _, f := range tc.forbidden {
				if strings.Contains(got, f) {
					t.Errorf("err %q contains %q", got, f)
				}
			}
			for _, k := range tc.kept {
				if !strings.Contains(got, k) {
					t.Errorf("err %q lost %q", got, k)
				}
			}
		})
	}
}

func TestHandler_PassesScalarsThrough(t *testing.T) {
	t.Parallel()
	l, _, last := jsonLogger(t, logx.Options{})
	l.Warn("collect done", "count", 3, "ok", true, "provider", "edf", slog.Float64("ratio", 0.5))
	m := last()
	want := map[string]any{"msg": "collect done", "level": "WARN", "count": float64(3), "ok": true, "provider": "edf", "ratio": 0.5}
	for k, w := range want {
		if m[k] != w {
			t.Errorf("%s = %#v, want %#v", k, m[k], w)
		}
	}
}

func TestHandler_EnabledDelegatesToInner(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	h := logx.NewHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}), logx.Options{})
	ctx := context.Background()
	if h.Enabled(ctx, slog.LevelInfo) {
		t.Error("Enabled(Info) = true with an inner Warn handler")
	}
	if !h.Enabled(ctx, slog.LevelError) {
		t.Error("Enabled(Error) = false with an inner Warn handler")
	}
	slog.New(h).Info("dropped")
	if buf.Len() != 0 {
		t.Errorf("Info written through a Warn handler: %s", buf.String())
	}
}

func TestHandler_WithDoesNotMutateParent(t *testing.T) {
	t.Parallel()
	l, buf, last := jsonLogger(t, logx.Options{})
	_ = l.With("a", 1).WithGroup("g")
	l.Info("m", "b", 2)
	m := last()
	if _, ok := m["a"]; ok {
		t.Errorf("parent logger gained attr from With: %s", buf)
	}
	if _, ok := m["g"]; ok {
		t.Errorf("parent logger gained group from WithGroup: %s", buf)
	}
}

func TestHandler_SlogConformance(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	newHandler := func(*testing.T) slog.Handler {
		buf.Reset()
		return logx.NewHandler(slog.NewJSONHandler(&buf, nil), logx.Options{})
	}
	result := func(t *testing.T) map[string]any {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatalf("decode %q: %v", buf.String(), err)
		}
		return m
	}
	slogtest.Run(t, newHandler, result)
}

// TestHandler_CanaryNeverWritten logs canaries through every path, with both
// JSON and text inner handlers, into files under ArtifactDir that make
// leakcheck greps.
func TestHandler_CanaryNeverWritten(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	token := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	canaries := []string{pw, cookie, token, sess}

	logAll := func(l *slog.Logger) {
		l.Info("login", "password", pw, "user", "synthetic-user")
		l.Info("request", slog.Group("http", slog.Group("header", slog.String("Cookie", "sid="+cookie), slog.String("Accept", "application/json"))))
		l.WithGroup("session").Info("restored", "id", sess)
		l.With("authorization", "Bearer "+token).Info("call")
		l.Info("free text leak " + token)
		l.Info("free value", "note", "cookie was "+cookie)
		l.Error("fetch failed", "err", fmt.Errorf("get https://api.fournisseur.test/x?sid=%s: %w", sess, io.EOF))
		l.Error("fetch failed", "err", errors.New("server said "+pw))
		l.Info("valuer", "cred", leakyError{pw}, "acct", account{user: "u1", pw: pw})
		l.Info("struct", "obj", struct{ Token string }{token})
	}

	dir := testsecrets.ArtifactDir(t)
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	for name, inner := range map[string]func(io.Writer) slog.Handler{
		"log.json": func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
		"log.txt":  func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
	} {
		var buf bytes.Buffer
		logAll(slog.New(logx.NewHandler(inner(&buf), logx.Options{})))
		if err := r.WriteAtomic(t.Context(), name, buf.Bytes()); err != nil {
			t.Fatalf("WriteAtomic %s: %v", name, err)
		}
		for _, c := range canaries {
			if strings.Contains(buf.String(), c) {
				t.Errorf("%s leaks a canary (output not printed)", name)
			}
		}
		if !strings.Contains(buf.String(), "synthetic-user") || !strings.Contains(buf.String(), "application/json") {
			t.Errorf("%s lost non-sensitive values:\n%s", name, buf.String())
		}
	}
}
