// Tests for review findings on package logx (J0 task T9 follow-up): key
// masking must reach inside composite slog.Any values, bytes must never be
// dumped, the default sensitive keys are extended without false positives,
// and every rendered string is capped.
//
// Expected behaviour (implementer: follow exactly; complements the contract
// at the top of logx_test.go, which still holds):
//
//  6. Composite KindAny values are WALKED, not printed with %+v. The walk
//     applies, at every depth, the same order as top-level attrs:
//     slog.LogValuer resolved first (a resolved group gets key masking),
//     then error / fmt.Stringer (rendered, cleaned, capped), then by kind:
//     - maps whose key kind is string (http.Header, url.Values,
//     map[string]string, map[string]any, named string keys): an entry whose
//     key is sensitive (rule 2 matching) renders as Mask; other entries
//     render their value recursively; keys themselves are Cleaned.
//     - structs (and pointers to structs): each field name, exported or
//     not, is checked like a key; sensitive → Mask; otherwise the field
//     value is rendered recursively. A field the walker cannot inspect
//     safely (unexported LogValuer/Stringer/error, func, chan, unsafe
//     pointer) renders as "<TypeName>" (fail closed), never via %+v.
//     - slices/arrays: elements rendered recursively.
//     - []byte, [N]byte and named byte slices (json.RawMessage) render as
//     Mask, at top level and nested: contents and decimal byte lists never
//     appear. This check comes BEFORE the Stringer check: with go1.27
//     json.RawMessage is jsontext.Value, whose String() returns the raw
//     JSON body (net.IP is masked as a consequence; log netip.Addr instead).
//     - cycles (a pointer already being walked) and depth beyond a small
//     bound render as "<cycle>" / "<TypeName>"; the walk always terminates.
//     The whole rendered value is one string (rule 4), cleaned and capped.
//     The exact textual layout of a walked composite is free (e.g.
//     "map[Accept:[text/html] Cookie:***]"); tests only assert what must and
//     must not appear.
//  7. Extra default sensitive keys: "pwd", "auth", "otp", "totp", "bearer",
//     "jwt", "csrf", "xsrf", "sid", "sessid", "mdp", "motdepasse",
//     "mot_de_passe". Short fragments (<= 4 letters) match a whole word of
//     the key (words split on non-alphanumerics and lower→Upper camelCase
//     boundaries), so "auth" masks "X-Auth" and "basicAuth" but not
//     "author", and "sid" masks "sid" but not "inside". Longer fragments keep
//     the strings.Contains rule.
//  8. Plain string values (KindString) and rendered Stringers/composites
//     are capped at MaxErrorLen bytes on a rune boundary with
//     TruncatedSuffix, like errors.
package logx_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// Short synthetic secrets with no token shape: only key masking can hide
// them, so a pattern-based pass cannot make these tests pass by accident.
const (
	shortPW     = "hunter2"
	shortSID    = "abc123"
	decimalPW   = "104 117 110 116 101 114 50"
	decimalPWJS = "104,117,110,116,101,114,50"
)

// basicValue is a synthetic HTTP Basic credential: 12 base64 characters,
// under the long-base64 token rule.
var basicValue = base64.StdEncoding.EncodeToString([]byte("user:pass"))

// hdrKey is a named string map key type.
type hdrKey string

// stringer renders a fixed value through String.
type stringer struct{ s string }

func (s stringer) String() string { return s.s }

// node can form a pointer cycle.
type node struct {
	Name string
	Next *node
}

func TestHandler_MasksSensitiveKeysInsideComposites(t *testing.T) {
	t.Parallel()
	type loginForm struct {
		User     string
		Password string
	}
	type withBytes struct {
		name string
		key  []byte
	}
	type withValuer struct {
		Label string
		Note  leakyError
	}
	type withHiddenValuer struct {
		note leakyError
	}
	type tokenRow struct{ Token string }

	tests := []struct {
		name      string
		value     any
		forbidden []string
		kept      []string
	}{
		{
			name: "http.Header",
			value: http.Header{
				"Cookie":        {"sid=" + shortSID},
				"Authorization": {"Basic " + basicValue},
				"Accept":        {"text/html"},
			},
			forbidden: []string{shortSID, basicValue},
			kept:      []string{"Accept", "text/html", "Cookie", logx.Mask},
		},
		{
			name: "http.Header set-cookie and csrf",
			value: http.Header{
				"Set-Cookie":   {"PHPSESSID=" + shortSID + "; Path=/"},
				"X-Csrf-Token": {shortPW},
				"Content-Type": {"application/pdf"},
			},
			forbidden: []string{shortSID, shortPW},
			kept:      []string{"application/pdf"},
		},
		{
			name:      "url.Values",
			value:     url.Values{"password": {shortPW}, "page": {"2"}},
			forbidden: []string{shortPW},
			kept:      []string{"page"},
		},
		{
			name:      "map[string]string",
			value:     map[string]string{"password": shortPW, "user": "u1"},
			forbidden: []string{shortPW},
			kept:      []string{"user", "u1"},
		},
		{
			name:      "nested map[string]any",
			value:     map[string]any{"form": map[string]any{"pwd": shortPW, "lang": "fr-FR"}},
			forbidden: []string{shortPW},
			kept:      []string{"form", "lang", "fr-FR"},
		},
		{
			name:      "named string key type",
			value:     map[hdrKey][]string{"Cookie": {"sid=" + shortSID}, "Accept": {"text/html"}},
			forbidden: []string{shortSID},
			kept:      []string{"text/html"},
		},
		{
			name:      "map key with token shape cleaned",
			value:     map[string]int{b64Std: 1},
			forbidden: []string{b64Std},
		},
		{
			name:      "map value with JWT cleaned",
			value:     map[string]string{"note": jwt},
			forbidden: []string{jwtPayload},
			kept:      []string{"note"},
		},
		{
			name:      "map value resolving to a group",
			value:     map[string]any{"acct": account{user: "u1", pw: shortPW}},
			forbidden: []string{shortPW},
			kept:      []string{"u1"},
		},
		{
			name:      "struct with sensitive exported field",
			value:     loginForm{User: "u1", Password: shortPW},
			forbidden: []string{shortPW},
			kept:      []string{"u1"},
		},
		{
			name:      "pointer to struct",
			value:     &loginForm{User: "u1", Password: shortPW},
			forbidden: []string{shortPW},
			kept:      []string{"u1"},
		},
		{
			name:      "struct with unexported []byte field",
			value:     withBytes{name: "u1", key: []byte(shortPW)},
			forbidden: []string{shortPW, decimalPW, decimalPWJS},
		},
		{
			name:      "LogValuer nested in exported field",
			value:     withValuer{Label: "u1", Note: leakyError{shortPW}},
			forbidden: []string{shortPW},
			kept:      []string{"u1"},
		},
		{
			name:      "LogValuer nested in unexported field",
			value:     withHiddenValuer{note: leakyError{shortPW}},
			forbidden: []string{shortPW},
		},
		{
			name:      "slice of structs",
			value:     []tokenRow{{Token: shortPW}},
			forbidden: []string{shortPW},
		},
		{
			name:      "slice of maps",
			value:     []any{map[string]string{"cookie": "sid=" + shortSID}},
			forbidden: []string{shortSID},
		},
		{
			name:      "map of byte slices",
			value:     map[string][]byte{"note": []byte(shortPW)},
			forbidden: []string{shortPW, decimalPW, decimalPWJS},
			kept:      []string{"note"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, buf, _ := jsonLogger(t, logx.Options{})
			l.Info("m", "v", tc.value)
			out := buf.String()
			for _, f := range tc.forbidden {
				if strings.Contains(out, f) {
					t.Errorf("output leaks %q: %s", f, out)
				}
			}
			for _, k := range tc.kept {
				if !strings.Contains(out, k) {
					t.Errorf("output lost %q: %s", k, out)
				}
			}
		})
	}
}

func TestHandler_MasksByteValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value any
	}{
		{name: "[]byte", value: []byte(shortPW)},
		{name: "[N]byte", value: [7]byte{'h', 'u', 'n', 't', 'e', 'r', '2'}},
		{name: "json.RawMessage", value: json.RawMessage(`{"pwd":"` + shortPW + `"}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, buf, last := jsonLogger(t, logx.Options{})
			l.Info("m", "body", tc.value)
			if got := last()["body"]; got != logx.Mask {
				t.Errorf("body = %#v, want %q", got, logx.Mask)
			}
			for _, f := range []string{shortPW, decimalPW, decimalPWJS} {
				if strings.Contains(buf.String(), f) {
					t.Errorf("output leaks %q: %s", f, buf)
				}
			}
		})
	}
}

func TestHandler_WalkTerminatesOnCycles(t *testing.T) {
	t.Parallel()
	n := &node{Name: "n1"}
	n.Next = n
	// A map reaching itself through a pointer. (A map holding itself
	// directly, m["self"] = m, makes today's fmt-based rendering overflow the
	// stack and abort the whole test binary, so it is not exercised here; the
	// walker's cycle detection must cover maps as well as pointers.)
	type box struct{ M map[string]any }
	m := map[string]any{"user": "u1"}
	m["box"] = &box{M: m}
	l, _, last := jsonLogger(t, logx.Options{})
	l.Info("m", "list", n, "map", m)
	got := last()
	for _, k := range []string{"list", "map"} {
		s, ok := got[k].(string)
		if !ok {
			t.Fatalf("%s = %#v, want a string", k, got[k])
		}
		if len(s) > logx.DefaultMaxErrorLen+len(logx.TruncatedSuffix) {
			t.Errorf("%s is %d bytes, want capped", k, len(s))
		}
	}
	if s, _ := got["list"].(string); !strings.Contains(s, "n1") {
		t.Errorf("list = %q, want the node name kept", s)
	}
	if s, _ := got["map"].(string); !strings.Contains(s, "u1") {
		t.Errorf("map = %q, want the user kept", s)
	}
}

func TestHandler_MasksExtendedSensitiveKeys(t *testing.T) {
	t.Parallel()
	const v = "plain-value-42"
	sensitive := []string{
		"pwd", "PWD", "user_pwd", "userPwd",
		"auth", "Auth", "X-Auth", "basicAuth", "auth_header",
		"otp", "OTP", "otp_code", "emailOtp",
		"totp", "totpCode",
		"bearer", "Bearer", "bearer_value",
		"jwt", "id_jwt", "jwtValue",
		"csrf", "_csrf", "X-CSRF", "csrf_header",
		"xsrf", "XSRF", "x-xsrf",
		"sid", "SID", "user_sid",
		"PHPSESSID", "sessid",
		"mdp", "MDP", "user_mdp",
		"motdepasse", "MotDePasse", "mot_de_passe", "MOT_DE_PASSE",
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

	// False positives the short fragments must avoid.
	kept := []string{
		"author", "Author", "authored_by", "coauthor", "authority",
		"footprint", "hotplug",
		"inside", "side", "considered", "residence", "sidebar", "subsidiary_name",
		"description", "options",
	}
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

func TestHandler_ExtendedKeysApplyEverywhere(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		log  func(l *slog.Logger)
	}{
		{name: "WithGroup name", log: func(l *slog.Logger) { l.WithGroup("auth").Info("m", "value", shortPW) }},
		{name: "group attr key", log: func(l *slog.Logger) { l.Info("m", slog.Group("otp", slog.String("code", shortPW))) }},
		{name: "map key", log: func(l *slog.Logger) { l.Info("m", "form", map[string]string{"mot_de_passe": shortPW}) }},
		{name: "struct field", log: func(l *slog.Logger) {
			l.Info("m", "form", struct{ Mdp string }{shortPW})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, buf, _ := jsonLogger(t, logx.Options{})
			tc.log(l)
			if strings.Contains(buf.String(), shortPW) {
				t.Errorf("output leaks the value: %s", buf)
			}
		})
	}
}

func TestHandler_CapsStringsAndStringers(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("é", 2000) // 4000 bytes, multi-byte runes
	tests := []struct {
		name   string
		maxLen int
		value  any
		limit  int
	}{
		{name: "string default cap", value: long, limit: logx.DefaultMaxErrorLen},
		{name: "string custom cap", maxLen: 64, value: long, limit: 64},
		{name: "Stringer default cap", value: stringer{long}, limit: logx.DefaultMaxErrorLen},
		{name: "Stringer custom cap", maxLen: 64, value: stringer{long}, limit: 64},
		{name: "map custom cap", maxLen: 64, value: map[string]string{"note": long}, limit: 64},
		{name: "struct custom cap", maxLen: 64, value: struct{ Note string }{long}, limit: 64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, _, last := jsonLogger(t, logx.Options{MaxErrorLen: tc.maxLen})
			l.Info("m", "v", tc.value)
			got, ok := last()["v"].(string)
			if !ok {
				t.Fatalf("v = %#v, want a string", last()["v"])
			}
			if !utf8.ValidString(got) {
				t.Errorf("v is not valid UTF-8")
			}
			body, cut := strings.CutSuffix(got, logx.TruncatedSuffix)
			if !cut {
				t.Errorf("v (%d bytes) not truncated, want TruncatedSuffix", len(got))
			}
			if len(body) > tc.limit {
				t.Errorf("v body is %d bytes, want <= %d", len(body), tc.limit)
			}
		})
	}

	t.Run("short string untouched", func(t *testing.T) {
		t.Parallel()
		l, _, last := jsonLogger(t, logx.Options{MaxErrorLen: 64})
		l.Info("m", "provider", "edf")
		if got := last()["provider"]; got != "edf" {
			t.Errorf("provider = %#v, want %q", got, "edf")
		}
	})
}

// TestHandler_CompositeCanaryNeverWritten logs canaries inside composite
// values with JSON and text inner handlers and keeps the output under
// ArtifactDir for make leakcheck.
func TestHandler_CompositeCanaryNeverWritten(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	token := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	canaries := []string{pw, cookie, token, sess}

	type form struct {
		User string
		Pwd  string
		otp  string
		raw  []byte
		Note leakyError
	}
	logAll := func(l *slog.Logger) {
		l.Info("request", "headers", http.Header{
			"Cookie":        {"sid=" + cookie},
			"Authorization": {"Bearer " + token},
			"Accept":        {"application/json"},
		})
		l.Info("form", "values", url.Values{"mot_de_passe": {pw}, "user": {"synthetic-user"}})
		l.Info("map", "m", map[string]any{"session": sess, "nested": map[string]string{"sid": sess}})
		l.Info("struct", "f", form{User: "synthetic-user", Pwd: pw, otp: token, raw: []byte(pw), Note: leakyError{pw}})
		l.Info("bytes", "body", []byte(cookie))
		l.Info("stringer", "s", stringer{"cookie was " + cookie})
	}

	dir := testsecrets.ArtifactDir(t)
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	for name, inner := range map[string]func(io.Writer) slog.Handler{
		"composite.json": func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
		"composite.txt":  func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
	} {
		var buf bytes.Buffer
		logAll(slog.New(logx.NewHandler(inner(&buf), logx.Options{})))
		if err := r.WriteAtomic(t.Context(), name, buf.Bytes()); err != nil {
			t.Fatalf("WriteAtomic %s: %v", name, err)
		}
		out := buf.String()
		for _, c := range canaries {
			if strings.Contains(out, c) {
				t.Errorf("%s leaks a canary (output not printed)", name)
			}
			// A byte dump would hide the canary from a plain grep.
			if strings.Contains(out, decimalBytes(c)) {
				t.Errorf("%s dumps canary bytes (output not printed)", name)
			}
		}
		if !strings.Contains(out, "synthetic-user") || !strings.Contains(out, "application/json") {
			t.Errorf("%s lost non-sensitive values:\n%s", name, out)
		}
	}
}

// decimalBytes renders s the way %v prints a []byte, without brackets.
func decimalBytes(s string) string {
	parts := make([]string, len(s))
	for i := range len(s) {
		parts[i] = fmt.Sprint(s[i])
	}
	return strings.Join(parts, " ")
}
