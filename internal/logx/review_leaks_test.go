// Tests for blocking review findings on package logx (J0 follow-up, after
// the composite walk of composite_test.go). Four leak classes:
//
// Expected behaviour (implementer: follow exactly; rules 1–8 of
// logx_test.go and composite_test.go still hold):
//
//  9. Map keys of any static type. A map whose key type is an interface
//     (map[any]any, map[any]string…), or any other non-string key type, is
//     masked by key like a string-keyed map: the key is rendered (string or
//     named string dynamic value → its text; other values → their walked /
//     String() form) and an entry whose rendered key is sensitive (rule 2 /
//     rule 7 matching) renders its value as Mask. This holds at any depth,
//     including inside an `any` struct field.
//  10. URLs. url.URL and *url.URL (any scheme, not only http/https), top
//     level or nested, render without the userinfo password, without any
//     query value and without the fragment; the host stays visible for
//     http(s) URLs. A url.Userinfo or *url.Userinfo renders as Mask (an
//     optional leading "&" is tolerated), with or without a password.
//  11. Readers and writers. Any value whose type, or pointer-to-type,
//     implements io.Reader or io.Writer renders as Mask or "<TypeName>"
//     (an optional leading "&" tolerated), never through String() and never
//     field by field. This check comes before the Stringer check
//     (*bytes.Buffer and *strings.Builder have a String() that returns the
//     content). As a consequence the body of an *http.Request or
//     *http.Response, a bare buffer, builder or reader, and an io.Reader
//     struct field never reach the output.
//  12. "pass" is a sensitive short fragment (<= 4 letters, whole-word rule
//     7): it masks "pass", "Pass", "user_pass", "userPass", "X-Pass",
//     "db-pass", as a key, map key, url.Values key or struct field. It does
//     not mask words that merely contain it: "passenger", "compass",
//     "passport", "bypass_cache", "passage", "surpass", "trespass",
//     "passive_mode".
package logx_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// bodyMarker is synthetic request/buffer content with no token shape: only
// the reader/writer rule can hide it.
const bodyMarker = "body-marker-q7"

// queryMarker is a non-sensitive query value: rule 10 hides every query
// value, not only the ones under a sensitive key.
const queryMarker = "pg4242"

// tapReader implements io.Reader on its pointer type only.
type tapReader struct{ Data string }

func (*tapReader) Read([]byte) (int, error) { return 0, io.EOF }

// tapWriter implements io.Writer on its value type.
type tapWriter struct{ Sink string }

func (tapWriter) Write(p []byte) (int, error) { return len(p), nil }

// ifaceHolder carries an arbitrary value in an exported `any` field.
type ifaceHolder struct{ Data any }

// logBoth logs key=value through the redacting handler over a JSON and a
// text inner handler and returns the JSON attribute value and both raw
// outputs joined.
func logBoth(t *testing.T, key string, value any) (jsonVal any, raw string) {
	t.Helper()
	var jb, tb bytes.Buffer
	slog.New(logx.NewHandler(slog.NewJSONHandler(&jb, nil), logx.Options{})).Info("m", key, value)
	slog.New(logx.NewHandler(slog.NewTextHandler(&tb, nil), logx.Options{})).Info("m", key, value)
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(jb.Bytes()), &m); err != nil {
		t.Fatalf("decode %q: %v", jb.String(), err)
	}
	return m[key], jb.String() + tb.String()
}

type leakCase struct {
	name      string
	value     any
	forbidden []string
	kept      []string
}

func runLeakCases(t *testing.T, tests []leakCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, raw := logBoth(t, "v", tc.value)
			for _, f := range tc.forbidden {
				if strings.Contains(raw, f) {
					t.Errorf("output leaks %q:\n%s", f, raw)
				}
			}
			s, _ := got.(string)
			for _, k := range tc.kept {
				if !strings.Contains(s, k) {
					t.Errorf("v = %q, want it to keep %q", s, k)
				}
			}
		})
	}
}

func TestHandler_MasksSensitiveInterfaceMapKeys(t *testing.T) {
	t.Parallel()
	runLeakCases(t, []leakCase{
		{
			name:      "map[any]any password",
			value:     map[any]any{"password": shortPW, "user": "synthetic-user"},
			forbidden: []string{shortPW},
			kept:      []string{"synthetic-user", logx.Mask},
		},
		{
			name:      "map[any]string authorization",
			value:     map[any]string{"authorization": "Basic " + basicValue, "accept": "text/html"},
			forbidden: []string{basicValue},
			kept:      []string{"text/html"},
		},
		{
			name:      "map[any]any cookie inside an any struct field",
			value:     ifaceHolder{Data: map[any]any{"cookie": "sid=" + shortSID}},
			forbidden: []string{shortSID},
		},
		{
			name:      "named string key in an interface",
			value:     map[any]any{hdrKey("Set-Cookie"): "PHPSESSID=" + shortSID},
			forbidden: []string{shortSID},
		},
		{
			name:      "mixed key kinds",
			value:     map[any]any{1: "one", "token": shortPW, true: "yes"},
			forbidden: []string{shortPW},
			kept:      []string{"one", "yes"},
		},
		{
			name:      "nested under a string-keyed map",
			value:     map[string]any{"outer": map[any]any{"otp": shortPW}},
			forbidden: []string{shortPW},
		},
		{
			name:      "Stringer key rendered sensitive",
			value:     map[stringer]string{{"X-Auth"}: shortPW},
			forbidden: []string{shortPW},
		},
		{
			name:      "slice of interface-keyed maps",
			value:     []map[any]any{{"secret": shortPW}},
			forbidden: []string{shortPW},
		},
	})
}

func TestHandler_RedactsURLs(t *testing.T) {
	t.Parallel()
	httpURL, err := url.Parse("https://synthetic-user:" + shortPW + "@example.com/x?token=" + shortSID + "&page=" + queryMarker + "#frag-" + queryMarker)
	if err != nil {
		t.Fatal(err)
	}
	ftpURL, err := url.Parse("ftp://synthetic-user:" + shortPW + "@files.example.com/x?k=" + queryMarker)
	if err != nil {
		t.Fatal(err)
	}
	urlForbidden := []string{shortPW, shortSID, queryMarker}
	runLeakCases(t, []leakCase{
		{name: "url.URL value", value: *httpURL, forbidden: urlForbidden, kept: []string{"example.com"}},
		{name: "*url.URL", value: httpURL, forbidden: urlForbidden, kept: []string{"example.com"}},
		{name: "*url.URL non-http scheme", value: ftpURL, forbidden: []string{shortPW, queryMarker}},
		{name: "url.URL value non-http scheme", value: *ftpURL, forbidden: []string{shortPW, queryMarker}},
		{name: "url.URL struct field", value: struct{ Endpoint url.URL }{*httpURL}, forbidden: urlForbidden, kept: []string{"example.com"}},
		{name: "*url.URL struct field", value: struct{ Endpoint *url.URL }{httpURL}, forbidden: urlForbidden},
		{name: "unexported url.URL field", value: struct{ endpoint url.URL }{*httpURL}, forbidden: urlForbidden},
		{name: "slice of *url.URL", value: []*url.URL{httpURL, ftpURL}, forbidden: urlForbidden},
		{name: "map of url.URL", value: map[string]url.URL{"login": *httpURL}, forbidden: urlForbidden},
	})
}

func TestHandler_MasksUserinfo(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value any
	}{
		{name: "*url.Userinfo with password", value: url.UserPassword("synthetic-user", shortPW)},
		{name: "*url.Userinfo without password", value: url.User("synthetic-user")},
		{name: "url.Userinfo value", value: *url.UserPassword("synthetic-user", shortPW)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, raw := logBoth(t, "v", tc.value)
			if s, _ := got.(string); strings.TrimPrefix(s, "&") != logx.Mask {
				t.Errorf("v = %#v, want %q", got, logx.Mask)
			}
			if strings.Contains(raw, shortPW) || strings.Contains(raw, "synthetic-user") {
				t.Errorf("output leaks userinfo:\n%s", raw)
			}
		})
	}
}

// opaqueOrMask reports whether s (an optional leading "&" removed) is Mask or
// a "<TypeName>" placeholder containing typeName (the name itself may be
// partly masked by Clean, e.g. "<io.***>").
func opaqueOrMask(s, typeName string) bool {
	s = strings.TrimPrefix(s, "&")
	if s == logx.Mask {
		return true
	}
	return strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") && strings.Contains(s, typeName)
}

func TestHandler_ReadersAndWritersAreOpaque(t *testing.T) {
	t.Parallel()
	var sb strings.Builder
	sb.WriteString(bodyMarker)
	tests := []struct {
		name     string
		value    any
		typeName string
	}{
		{name: "*bytes.Buffer", value: bytes.NewBufferString(bodyMarker), typeName: "bytes.Buffer"},
		{name: "*strings.Builder", value: &sb, typeName: "strings.Builder"},
		{name: "*strings.Reader", value: strings.NewReader(bodyMarker), typeName: "strings.Reader"},
		{name: "*bytes.Reader", value: bytes.NewReader([]byte(bodyMarker)), typeName: "bytes.Reader"},
		{name: "io.NopCloser", value: io.NopCloser(strings.NewReader(bodyMarker)), typeName: "io."},
		{name: "pointer type implements io.Reader", value: tapReader{Data: bodyMarker}, typeName: "tapReader"},
		{name: "value type implements io.Writer", value: tapWriter{Sink: bodyMarker}, typeName: "tapWriter"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, raw := logBoth(t, "v", tc.value)
			if strings.Contains(raw, bodyMarker) {
				t.Errorf("output leaks the content:\n%s", raw)
			}
			if s, _ := got.(string); !opaqueOrMask(s, tc.typeName) {
				t.Errorf("v = %q, want %q or <…%s…>", s, logx.Mask, tc.typeName)
			}
		})
	}
}

func TestHandler_NeverLogsBodies(t *testing.T) {
	t.Parallel()
	form := "user=synthetic-user&note=" + bodyMarker
	newReq := func(body io.Reader) *http.Request {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/login", body)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	var sb strings.Builder
	sb.WriteString(bodyMarker)
	runLeakCases(t, []leakCase{
		{name: "*http.Request strings.Reader body", value: newReq(strings.NewReader(form)), forbidden: []string{bodyMarker}},
		{name: "*http.Request NopCloser bytes.Buffer body", value: newReq(io.NopCloser(bytes.NewBufferString(form))), forbidden: []string{bodyMarker}},
		{name: "*http.Request bytes.Reader body", value: newReq(bytes.NewReader([]byte(form))), forbidden: []string{bodyMarker}},
		{name: "*http.Response body", value: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(form))}, forbidden: []string{bodyMarker}},
		{name: "io.Reader struct field", value: struct{ Body io.Reader }{strings.NewReader(bodyMarker)}, forbidden: []string{bodyMarker}},
		{name: "unexported reader field", value: struct{ body io.Reader }{strings.NewReader(bodyMarker)}, forbidden: []string{bodyMarker}},
		{name: "bytes.Buffer value field", value: struct{ Buf bytes.Buffer }{*bytes.NewBufferString(bodyMarker)}, forbidden: []string{bodyMarker}},
		{name: "*strings.Builder in a map", value: map[string]any{"draft": &sb}, forbidden: []string{bodyMarker}},
		{name: "reader in an any field", value: ifaceHolder{Data: strings.NewReader(bodyMarker)}, forbidden: []string{bodyMarker}},
	})
}

func TestHandler_MasksPassKey(t *testing.T) {
	t.Parallel()
	const v = "plain-value-42"
	for _, key := range []string{"pass", "Pass", "PASS", "user_pass", "userPass", "X-Pass", "db-pass", "pass_hash"} {
		t.Run("masks "+key, func(t *testing.T) {
			t.Parallel()
			got, raw := logBoth(t, key, v)
			if got != logx.Mask {
				t.Errorf("%s = %v, want %q", key, got, logx.Mask)
			}
			if strings.Contains(raw, v) {
				t.Errorf("output leaks the value:\n%s", raw)
			}
		})
	}
	for _, key := range []string{"passenger", "Passenger", "compass", "passport", "bypass_cache", "passage", "surpass", "trespass", "passive_mode"} {
		t.Run("keeps "+key, func(t *testing.T) {
			t.Parallel()
			got, _ := logBoth(t, key, v)
			if got != v {
				t.Errorf("%s = %v, want %q kept", key, got, v)
			}
		})
	}

	type cfg struct{ Login, Pass string }
	runLeakCases(t, []leakCase{
		{name: "struct field Pass", value: cfg{Login: "synthetic-user", Pass: shortPW}, forbidden: []string{shortPW}, kept: []string{"synthetic-user"}},
		{name: "url.Values pass", value: url.Values{"pass": {shortPW}, "login": {"synthetic-user"}}, forbidden: []string{shortPW}, kept: []string{"synthetic-user"}},
		{name: "map key user_pass", value: map[string]string{"user_pass": shortPW}, forbidden: []string{shortPW}},
		{name: "interface map key pass", value: map[any]any{"pass": shortPW}, forbidden: []string{shortPW}},
		{name: "struct field Passenger kept", value: struct{ Passenger string }{"synthetic-rider"}, kept: []string{"synthetic-rider"}},
	})

	t.Run("WithGroup pass", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		slog.New(logx.NewHandler(slog.NewJSONHandler(&buf, nil), logx.Options{})).WithGroup("pass").Info("m", "value", shortPW)
		if strings.Contains(buf.String(), shortPW) {
			t.Errorf("output leaks the value:\n%s", buf.String())
		}
	})
}

// TestHandler_ReviewCanaryNeverWritten logs canaries through every shape
// above (interface map keys, URLs, userinfo, request bodies, buffers,
// builders, readers, "pass" keys) with JSON and text inner handlers and keeps
// the output under ArtifactDir for make leakcheck.
func TestHandler_ReviewCanaryNeverWritten(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	token := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	canaries := []string{pw, cookie, token, sess}

	u := &url.URL{
		Scheme:   "ftp",
		User:     url.UserPassword("synthetic-user", pw),
		Host:     "files.example.com",
		Path:     "/x",
		RawQuery: url.Values{"token": {token}}.Encode(),
	}
	logAll := func(t *testing.T, l *slog.Logger) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/login", strings.NewReader("password="+pw+"&cookie="+cookie))
		if err != nil {
			t.Fatal(err)
		}
		var sb strings.Builder
		sb.WriteString(sess)
		l.Info("map", "m", map[any]any{"password": pw, "cookie": cookie})
		l.Info("iface", "h", ifaceHolder{Data: map[any]any{"session": sess}})
		l.Info("url", "u", u, "uv", *u, "ui", url.UserPassword("synthetic-user", pw))
		l.Info("req", "req", req)
		l.Info("buffers", "buf", bytes.NewBufferString(token), "sb", &sb, "rd", strings.NewReader(cookie))
		l.Info("pass", "pass", pw, "cfg", struct{ Login, Pass string }{"synthetic-user", pw}, "form", url.Values{"pass": {pw}})
	}

	dir := testsecrets.ArtifactDir(t)
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	for name, inner := range map[string]func(io.Writer) slog.Handler{
		"review.json": func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
		"review.txt":  func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
	} {
		var buf bytes.Buffer
		logAll(t, slog.New(logx.NewHandler(inner(&buf), logx.Options{})))
		if err := r.WriteAtomic(t.Context(), name, buf.Bytes()); err != nil {
			t.Fatalf("WriteAtomic %s: %v", name, err)
		}
		out := buf.String()
		for _, c := range canaries {
			if strings.Contains(out, c) {
				t.Errorf("%s leaks a canary (output not printed)", name)
			}
			if strings.Contains(out, decimalBytes(c)) {
				t.Errorf("%s dumps canary bytes (output not printed)", name)
			}
			if strings.Contains(out, url.QueryEscape(c)) || strings.Contains(out, fmt.Sprintf("%x", c)) {
				t.Errorf("%s leaks an encoded canary (output not printed)", name)
			}
		}
		if !strings.Contains(out, "synthetic-user") {
			t.Errorf("%s lost non-sensitive values:\n%s", name, out)
		}
	}
}
