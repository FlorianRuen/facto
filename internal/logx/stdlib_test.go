// Tests for the third review round on package logx: the walker must fail
// closed on sensitive standard-library types instead of reacting to leak
// shapes one by one, must not call String()/Error() promoted from an
// embedded URL, userinfo, cookie or reader, and Clean must redact URLs of
// any scheme.
//
// Expected behaviour (implementer: follow exactly; rules 1–12 of
// logx_test.go, composite_test.go and review_leaks_test.go still hold):
//
//  13. Fail closed for sensitive stdlib packages. In the walker, at any
//     depth (top level, behind pointers, inside interfaces, slices,
//     arrays, map values, struct fields exported or not, embedded fields),
//     a value whose type (after removing pointers) is DEFINED in net/http,
//     net/url, net/http/cookiejar, or crypto or any crypto/... package
//     (reflect.Type.PkgPath) renders as "<TypeName>" (e.g. "<*cookiejar.Jar>",
//     "<*tls.Config>", "<*http.Request>"; an optional leading "&" is
//     tolerated) and is neither walked nor rendered through
//     String/Error/LogValue. This check runs before the Stringer/error
//     check. The only exceptions, rendered as follows:
//     - url.URL / *url.URL: rule 10 (scheme, host, path; "?***" when a
//     query or fragment was present; no userinfo).
//     - url.Userinfo / *url.Userinfo: Mask.
//     - http.Header and url.Values: maps, sensitive keys masked (rule 6).
//     - http.Cookie / *http.Cookie: "<Name>=***" (the cookie name, cleaned,
//     then "=" and Mask); Value, Raw, Unparsed, Domain, Path… never appear.
//     *http.Request and *http.Response therefore render as "<*http.Request>"
//     and "<*http.Response>": nothing they carry (URL query, Form, Header,
//     Body, TLS state) reaches the output.
//     Errors defined in these packages (e.g. *url.Error) may render either
//     as "<TypeName>" or as their cleaned Error() text; tests only require
//     that no secret appears.
//  14. Promoted methods. When a struct gets String() or Error() by
//     promotion from an embedded field whose type is *url.Userinfo,
//     url.URL, *url.URL, *http.Cookie (or anything rule 13 covers), or an
//     io.Reader / io.Writer, that promoted method is never called. For the
//     rule-13 types the struct is walked field by field
//     and the embedded field gets its own rendering (Mask, redacted URL,
//     "Name=***", "<TypeName>"), so its sibling fields stay visible; the
//     embedded field's name ("Userinfo", "URL", "Cookie", "Reader"…) is
//     matched like any field name (rule 2: "Cookie" masks it whole). A
//     LogValue method is still honoured first (none of these embedded
//     types has one, so it is the struct's own). A String/Error the struct
//     declares itself may be honoured or the struct walked: tests only
//     require that nothing leaks. A struct embedding a reader/writer may
//     be walked (the embedded field then renders "<TypeName>") or stay
//     opaque as a whole (rule 11; io.NopCloser must keep rendering
//     "<io.…>"): tests only require that the content never appears.
//  15. Clean redacts URLs of any scheme matching [a-zA-Z][a-zA-Z0-9+.-]*://
//     (ftp, sftp, smb, git+ssh, redis, custom.v2…, any case) exactly like
//     http(s) URLs today: the whole userinfo is removed, and everything from
//     the first "?" or "#" is replaced by "?***". It applies to messages,
//     string values and rendered errors (errors.New, fmt.Errorf, *url.Error).
//     Text without "://" is left unchanged.
package logx_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// Short synthetic markers with no token shape: lowercase hex and plain
// words survive Clean, so only the structural rules can hide them.
const (
	pwMarker    = "pwmarker7"
	hexCookie   = "0123456789abcdef0123456789abcdef"
	sniMarker   = "sni-marker-q5"
	labelMarker = "label-q3"
	ftpURLRaw   = "ftp://alice:" + pwMarker + "@h.example/p?q=" + queryMarker
)

// cookie returns a synthetic cookie with secure attributes (gosec G124).
func cookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// isOpaque reports whether s, an optional leading "&" removed, is a
// "<TypeName>" placeholder naming typeName.
func isOpaque(s, typeName string) bool {
	s = strings.TrimPrefix(s, "&")
	return strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") && strings.Contains(s, typeName)
}

// stdCase is one value logged under the non-sensitive key "got".
type stdCase struct {
	name      string
	value     any
	forbidden []string
	kept      []string // substrings the rendered value must contain
	opaque    string   // if set, the whole rendered value must be <…opaque…>
	exact     string   // if set, the rendered value must equal it
}

func runStdCases(t *testing.T, tests []stdCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, raw := logBoth(t, "got", tc.value)
			for _, f := range tc.forbidden {
				if strings.Contains(raw, f) {
					t.Errorf("output leaks %q:\n%s", f, raw)
				}
			}
			s, ok := got.(string)
			if !ok {
				t.Fatalf("got = %#v, want a string", got)
			}
			for _, k := range tc.kept {
				if !strings.Contains(s, k) {
					t.Errorf("got = %q, want it to contain %q", s, k)
				}
			}
			if tc.opaque != "" && !isOpaque(s, tc.opaque) {
				t.Errorf("got = %q, want an opaque <…%s…> placeholder", s, tc.opaque)
			}
			if tc.exact != "" && s != tc.exact {
				t.Errorf("got = %q, want %q", s, tc.exact)
			}
		})
	}
}

func TestHandler_RendersCookiesAsNameOnly(t *testing.T) {
	t.Parallel()
	c := http.Cookie{
		Name: "pref", Value: hexCookie, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Path: "/" + hexCookie, Domain: "h.example",
		Raw: "pref=" + hexCookie, Unparsed: []string{"x=" + hexCookie},
	}
	sess := *cookie("PHPSESSID", hexCookie)
	no := []string{hexCookie}
	runStdCases(t, []stdCase{
		{name: "[]*http.Cookie", value: []*http.Cookie{&sess}, forbidden: no, kept: []string{"PHPSESSID=" + logx.Mask}},
		{name: "[]*http.Cookie non-session name", value: []*http.Cookie{&c}, forbidden: no, kept: []string{"pref=" + logx.Mask}},
		{name: "*http.Cookie", value: &c, forbidden: no, kept: []string{"pref=" + logx.Mask}},
		{name: "http.Cookie by value", value: c, forbidden: no, exact: "pref=" + logx.Mask},
		{name: "[]http.Cookie", value: []http.Cookie{c, sess}, forbidden: no, kept: []string{"pref=" + logx.Mask, "PHPSESSID=" + logx.Mask}},
		{name: "map value []*http.Cookie", value: map[string]any{"jar": []*http.Cookie{cookie("sid", hexCookie)}}, forbidden: no, kept: []string{"jar"}},
		{name: "struct field", value: struct{ Got []*http.Cookie }{[]*http.Cookie{&c}}, forbidden: no, kept: []string{"pref=" + logx.Mask}},
		// A sensitive field name (rule 2) still masks the whole value.
		{name: "sensitive struct field", value: struct{ Cookies []*http.Cookie }{[]*http.Cookie{&c}}, forbidden: no, kept: []string{logx.Mask}},
		{name: "unexported struct field", value: struct{ cookie http.Cookie }{c}, forbidden: no},
		{name: "any field", value: ifaceHolder{Data: &c}, forbidden: no, kept: []string{"pref=" + logx.Mask}},
		{name: "embedded by value", value: struct{ http.Cookie }{c}, forbidden: no, kept: []string{logx.Mask}},
		{name: "array", value: [1]*http.Cookie{&c}, forbidden: no, kept: []string{"pref=" + logx.Mask}},
	})
}

func TestHandler_SensitiveStdlibTypesFailClosed(t *testing.T) {
	t.Parallel()
	page := mustURL(t, "https://h.example/p?q="+queryMarker)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(page, []*http.Cookie{cookie("pref", hexCookie)})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, page.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = url.Values{"note": {bodyMarker}}
	req.Header.Set("X-Note", bodyMarker)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-Note": {bodyMarker}},
		Request:    req,
		Body:       io.NopCloser(strings.NewReader(bodyMarker)),
	}

	// A fixed synthetic P-256 scalar (0x01..0x20), well below the order.
	scalar := make([]byte, 32)
	for i := range scalar {
		scalar[i] = byte(i + 1)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	keyDec := new(big.Int).SetBytes(scalar).String()
	keyHex := fmt.Sprintf("%x", scalar)
	keyNo := []string{keyDec, keyHex}

	tlsCfg := &tls.Config{ServerName: sniMarker, MinVersion: tls.VersionTLS13}
	httpNo := []string{hexCookie, bodyMarker, queryMarker, sniMarker}

	runStdCases(t, []stdCase{
		{name: "*cookiejar.Jar", value: jar, forbidden: httpNo, opaque: "cookiejar.Jar"},
		{name: "jar in a struct field", value: struct{ Jar http.CookieJar }{jar}, forbidden: httpNo, kept: []string{"cookiejar.Jar>"}},
		{name: "jar in an unexported field", value: struct{ jar *cookiejar.Jar }{jar}, forbidden: httpNo, kept: []string{"cookiejar.Jar>"}},
		{name: "*http.Client with jar", value: &http.Client{Jar: jar}, forbidden: httpNo, opaque: "http.Client"},
		{name: "*http.Request", value: req, forbidden: httpNo, opaque: "http.Request"},
		{name: "*http.Response", value: resp, forbidden: httpNo, opaque: "http.Response"},
		{name: "*http.Request in a slice", value: []any{req}, forbidden: httpNo, kept: []string{"http.Request>"}},
		{name: "*http.Transport", value: &http.Transport{TLSClientConfig: tlsCfg}, forbidden: httpNo, opaque: "http.Transport"},
		{name: "*tls.Config", value: tlsCfg, forbidden: httpNo, opaque: "tls.Config"},
		{name: "*tls.Config in a map value", value: map[string]any{"tls": tlsCfg}, forbidden: httpNo, kept: []string{"tls", "tls.Config>"}},
		{name: "tls.Certificate", value: tls.Certificate{PrivateKey: key}, forbidden: keyNo, opaque: "tls.Certificate"},
		{name: "*ecdsa.PrivateKey", value: key, forbidden: keyNo, opaque: "ecdsa.PrivateKey"},
		{name: "ecdsa key behind any field", value: ifaceHolder{Data: key}, forbidden: keyNo, kept: []string{"ecdsa.PrivateKey>"}},
		{name: "*ecdsa.PublicKey", value: &key.PublicKey, opaque: "ecdsa.PublicKey"},
		{name: "*url.Error", value: &url.Error{Op: "Get", URL: ftpURLRaw, Err: errors.New("eof")}, forbidden: []string{pwMarker, queryMarker, "alice"}},

		// The explicitly handled types keep their rendering.
		{name: "http.Header still a masked map", value: struct{ H http.Header }{http.Header{"Accept": {"text/html"}, "Cookie": {"pref=" + hexCookie}}}, forbidden: []string{hexCookie}, kept: []string{"Accept", "text/html", "Cookie"}},
		{name: "url.Values still a masked map", value: []any{url.Values{"page": {"2"}, "password": {pwMarker}}}, forbidden: []string{pwMarker}, kept: []string{"page", "2"}},
		{name: "*url.URL still redacted", value: []any{mustURL(t, ftpURLRaw)}, forbidden: []string{pwMarker, queryMarker, "alice"}, kept: []string{"h.example/p?" + logx.Mask}},
		{name: "*url.Userinfo still masked", value: map[string]any{"u": url.UserPassword("alice", pwMarker)}, forbidden: []string{pwMarker, "alice"}, kept: []string{logx.Mask}},
	})
}

// Named types whose String/Error/Read come only from an embedded field.
type (
	embUserinfo struct{ *url.Userinfo }
	embURLPtr   struct{ *url.URL }
	embURLVal   struct {
		Label string
		url.URL
	}
	embCookie struct {
		Label string
		*http.Cookie
	}
	embReader struct {
		Label string
		io.Reader
	}
	embBuffer struct {
		Label string
		*bytes.Buffer
	}
	embTwice struct{ embUserinfo }
)

// ownStringer embeds a userinfo but declares its own String: that one is
// still honoured.
type ownStringer struct{ *url.Userinfo }

func (ownStringer) String() string { return "own-render" }

// ownValuer embeds a cookie but declares its own LogValue.
type ownValuer struct{ *http.Cookie }

func (ownValuer) LogValue() slog.Value { return slog.StringValue("own-value") }

func TestHandler_EmbeddedStdlibFieldsAreWalked(t *testing.T) {
	t.Parallel()
	ui := url.UserPassword("alice", pwMarker)
	ftp := mustURL(t, ftpURLRaw)
	c := cookie("pref", hexCookie)
	uiNo := []string{pwMarker, "alice"}
	urlNo := []string{pwMarker, queryMarker, "alice"}
	runStdCases(t, []stdCase{
		{name: "struct{*url.Userinfo}", value: embUserinfo{ui}, forbidden: uiNo, kept: []string{logx.Mask}},
		{name: "&struct{*url.Userinfo}", value: &embUserinfo{ui}, forbidden: uiNo, kept: []string{logx.Mask}},
		{name: "two levels of embedding", value: embTwice{embUserinfo{ui}}, forbidden: uiNo, kept: []string{logx.Mask}},
		{name: "anonymous struct{*url.Userinfo}", value: struct{ *url.Userinfo }{ui}, forbidden: uiNo, kept: []string{logx.Mask}},
		{name: "struct{*url.URL} ftp", value: embURLPtr{ftp}, forbidden: urlNo, kept: []string{"ftp://h.example/p?" + logx.Mask}},
		{name: "&struct{url.URL} ftp", value: &embURLVal{Label: labelMarker, URL: *ftp}, forbidden: urlNo, kept: []string{labelMarker, "h.example/p?" + logx.Mask}},
		{name: "struct{*http.Cookie}", value: embCookie{Label: labelMarker, Cookie: c}, forbidden: []string{hexCookie}, kept: []string{labelMarker, logx.Mask}},
		{name: "struct{*http.Cookie} in a slice", value: []any{embCookie{Label: labelMarker, Cookie: c}}, forbidden: []string{hexCookie}, kept: []string{labelMarker, logx.Mask}},
		// Rule 11 may keep a struct that embeds a reader/writer opaque as a
		// whole (io.NopCloser must stay "<io.…>"): only no-leak is required.
		{name: "struct{io.Reader}", value: embReader{Label: labelMarker, Reader: strings.NewReader(bodyMarker)}, forbidden: []string{bodyMarker}},
		{name: "struct{*bytes.Buffer}", value: embBuffer{Label: labelMarker, Buffer: bytes.NewBufferString(bodyMarker)}, forbidden: []string{bodyMarker}},

		// A LogValue declared by the struct itself still wins; for a
		// declared String either outcome is fine as long as nothing leaks.
		{name: "own String", value: ownStringer{ui}, forbidden: uiNo},
		{name: "own LogValue", value: ownValuer{c}, forbidden: []string{hexCookie}, exact: "own-value"},
	})
}

func TestClean_RedactsURLsOfAnyScheme(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "ftp userinfo and query", in: "dial " + ftpURLRaw, want: "dial ftp://h.example/p?" + logx.Mask},
		{name: "sftp with port", in: "sftp://alice:" + pwMarker + "@h.example:22/srv", want: "sftp://h.example:22/srv"},
		{name: "smb domain user", in: "smb://WORKGROUP;alice:" + pwMarker + "@fs.example/share", want: "smb://fs.example/share"},
		{name: "git+ssh", in: "git+ssh://git:" + pwMarker + "@git.example/repo.git?ref=" + queryMarker, want: "git+ssh://git.example/repo.git?" + logx.Mask},
		{name: "uppercase scheme fragment", in: "FTP://alice:" + pwMarker + "@H.example/p#" + queryMarker, want: "FTP://H.example/p?" + logx.Mask},
		{name: "custom scheme with dot and dash", in: "x-app.v2://h.example/cb?code=" + queryMarker, want: "x-app.v2://h.example/cb?" + logx.Mask},
		{name: "password only userinfo", in: "redis://:" + pwMarker + "@cache.example:6379/0", want: "redis://cache.example:6379/0"},
		{name: "quoted in a url.Error text", in: (&url.Error{Op: "Get", URL: ftpURLRaw, Err: errors.New("eof")}).Error(), want: `Get "ftp://h.example/p?` + logx.Mask + `": eof`},
		{name: "two urls", in: "from sftp://a:" + pwMarker + "@x.example/a to ftp://b:" + pwMarker + "@y.example/b?k=" + queryMarker, want: "from sftp://x.example/a to ftp://y.example/b?" + logx.Mask},
		{name: "http still redacted", in: "https://alice:" + pwMarker + "@h.example/p?q=" + queryMarker, want: "https://h.example/p?" + logx.Mask},

		// Text without "://" is left alone.
		{name: "mailto", in: "mailto:alice@example.test", want: "mailto:alice@example.test"},
		{name: "urn", in: "urn:isbn:0451450523", want: "urn:isbn:0451450523"},
		{name: "scheme-less host and query", in: "see example.test/p?page=2 for details", want: "see example.test/p?page=2 for details"},
		{name: "windows path", in: `C:\Users\facto\out`, want: `C:\Users\facto\out`},
		{name: "times and ratios", in: "ratio 3:1 at 12:30", want: "ratio 3:1 at 12:30"},
		{name: "protocol-relative", in: "//cdn.example/x?y=1", want: "//cdn.example/x?y=1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := logx.Clean(tc.in); got != tc.want {
				t.Errorf("Clean(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestHandler_RedactsAnySchemeInMessagesAndErrors(t *testing.T) {
	t.Parallel()
	ue := &url.Error{Op: "Get", URL: ftpURLRaw, Err: errors.New("eof")}
	no := []string{pwMarker, queryMarker, "alice"}
	tests := []struct {
		name string
		log  func(l *slog.Logger)
		kept string
	}{
		{name: "message", log: func(l *slog.Logger) { l.Info("dial " + ftpURLRaw) }, kept: "ftp://h.example/p?" + logx.Mask},
		{name: "string attr", log: func(l *slog.Logger) { l.Info("m", "target", ftpURLRaw) }, kept: "ftp://h.example/p?" + logx.Mask},
		{name: "errors.New", log: func(l *slog.Logger) { l.Info("m", "err", errors.New("dial "+ftpURLRaw)) }, kept: "dial ftp://h.example/p?" + logx.Mask},
		{name: "wrapped *url.Error", log: func(l *slog.Logger) { l.Info("m", "err", fmt.Errorf("list invoices: %w", ue)) }, kept: "list invoices"},
		{name: "*url.Error", log: func(l *slog.Logger) { l.Info("m", "err", ue) }},
		{name: "sftp in a group", log: func(l *slog.Logger) {
			l.Info("m", slog.Group("g", "dst", "sftp://alice:"+pwMarker+"@h.example/srv?x="+queryMarker))
		}, kept: "sftp://h.example/srv?" + logx.Mask},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for name, mk := range map[string]func(io.Writer) slog.Handler{
				"json": func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
				"text": func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
			} {
				var buf bytes.Buffer
				tc.log(slog.New(logx.NewHandler(mk(&buf), logx.Options{})))
				out := buf.String()
				for _, f := range no {
					if strings.Contains(out, f) {
						t.Errorf("%s output leaks %q:\n%s", name, f, out)
					}
				}
				if tc.kept != "" && !strings.Contains(out, tc.kept) {
					t.Errorf("%s output lost %q:\n%s", name, tc.kept, out)
				}
			}
		})
	}
}

// TestHandler_StdlibCanaryNeverWritten logs canaries through every shape of
// this file (cookies, jars, requests, embedded userinfo/URL/cookie, URLs of
// non-http schemes in strings and errors) and keeps the output under
// ArtifactDir for make leakcheck.
func TestHandler_StdlibCanaryNeverWritten(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	cookieVal := testsecrets.Canary(t, testsecrets.Cookie)
	token := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	canaries := []string{pw, cookieVal, token, sess}

	ftp := &url.URL{
		Scheme: "ftp", User: url.UserPassword("synthetic-user", pw),
		Host: "files.example.com", Path: "/x", RawQuery: url.Values{"k": {token}}.Encode(),
	}
	page := mustURL(t, "https://files.example.com/p")
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(page, []*http.Cookie{cookie("pref", sess)})
	c := &http.Cookie{
		Name: "pref", Value: cookieVal, Raw: "pref=" + cookieVal,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}

	logAll := func(t *testing.T, l *slog.Logger) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://files.example.com/p?k="+token, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie("pref", sess))
		l.Info("cookies", "got", []*http.Cookie{c}, "val", *c, "vals", []http.Cookie{*c}, "m", map[string]any{"jar": []*http.Cookie{c}})
		l.Info("jar", "got", jar, "client", &http.Client{Jar: jar})
		l.Info("req", "got", req)
		l.Info("embedded", "ui", embUserinfo{url.UserPassword("synthetic-user", pw)}, "u", embURLPtr{ftp}, "c", embCookie{Label: "synthetic-user", Cookie: c})
		l.Info("dial "+ftp.String(), "target", ftp.String(), "err", errors.New("dial "+ftp.String()),
			"uerr", &url.Error{Op: "Get", URL: ftp.String(), Err: errors.New("eof")})
	}

	dir := testsecrets.ArtifactDir(t)
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	for name, inner := range map[string]func(io.Writer) slog.Handler{
		"stdlib.json": func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
		"stdlib.txt":  func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
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
			if strings.Contains(out, url.QueryEscape(c)) || strings.Contains(out, fmt.Sprintf("%x", c)) {
				t.Errorf("%s leaks an encoded canary (output not printed)", name)
			}
		}
		if !strings.Contains(out, "files.example.com") || !strings.Contains(out, "synthetic-user") {
			t.Errorf("%s lost non-sensitive values:\n%s", name, out)
		}
	}
}
