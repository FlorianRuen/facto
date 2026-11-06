package har_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/har"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// entry builds a request/response pair carrying every kind of secret the
// redaction must remove.
func secretEntry(t *testing.T) (har.Entry, []string) {
	t.Helper()
	pw := testsecrets.Canary(t, testsecrets.Password)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	tok := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	e := har.Entry{
		StartedDateTime: "2026-01-01T00:00:00Z",
		Request: har.Request{
			Method:      "POST",
			URL:         "https://www.example.test/login?access_token=" + tok + "&page=2",
			HTTPVersion: "HTTP/1.1",
			Headers: []har.NV{
				{Name: "Authorization", Value: "Bearer " + tok},
				{Name: "Cookie", Value: "sid=" + cookie},
				{Name: "X-CSRF-Token", Value: tok},
				{Name: "Accept", Value: "text/html"},
				{Name: "Proxy-Authorization", Value: "Basic " + tok},
				{Name: "X-Api-Key", Value: tok},
			},
			Cookies:     []har.Cookie{{Name: "sid", Value: cookie}},
			QueryString: []har.NV{{Name: "access_token", Value: tok}, {Name: "page", Value: "2"}},
			PostData: &har.PostData{
				MimeType: "application/x-www-form-urlencoded",
				Text:     "username=someone&password=" + pw + "&csrf_token=" + tok,
				Params: []har.NV{
					{Name: "username", Value: "someone"},
					{Name: "password", Value: pw},
					{Name: "csrf_token", Value: tok},
				},
			},
		},
		Response: har.Response{
			Status: 200, StatusText: "OK", HTTPVersion: "HTTP/1.1",
			Headers: []har.NV{
				{Name: "Set-Cookie", Value: "sid=" + sess + "; Path=/; Secure"},
				{Name: "Content-Type", Value: "application/json"},
				{Name: "WWW-Authenticate", Value: "Bearer realm=" + tok},
			},
			Cookies: []har.Cookie{{Name: "sid", Value: sess}},
			Content: har.Content{MimeType: "application/json", Text: `{"access_token":"` + tok + `","id_token":"` + tok + `","name":"x","password":"` + pw + `"}`},
		},
	}
	return e, []string{pw, cookie, tok, sess}
}

func TestRedact_RemovesPasswordsCookiesAndAuthorization(t *testing.T) {
	t.Parallel()
	e, secrets := secretEntry(t)
	got := har.RedactEntry(e)
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("redacted entry still holds a secret canary: %s", b)
		}
	}
	for _, h := range got.Request.Headers {
		switch strings.ToLower(h.Name) {
		case "authorization", "cookie", "proxy-authorization", "x-csrf-token", "x-api-key":
			if h.Value != har.Redacted {
				t.Errorf("header %s = %q, want %q", h.Name, h.Value, har.Redacted)
			}
		case "accept":
			if h.Value != "text/html" {
				t.Errorf("harmless header Accept changed to %q", h.Value)
			}
		}
	}
	if len(got.Request.Cookies) != 1 || got.Request.Cookies[0].Name != "sid" || got.Request.Cookies[0].Value != har.Redacted {
		t.Errorf("request cookies = %+v, want name kept, value redacted", got.Request.Cookies)
	}
	if got.Response.Cookies[0].Value != har.Redacted {
		t.Errorf("response cookie value kept")
	}
	// Non-secret structure stays usable for a connector author.
	if !strings.Contains(got.Request.URL, "page=2") {
		t.Errorf("URL lost its harmless query: %s", got.Request.URL)
	}
	// The login identifier is half of a credential: removed from requests.
	if strings.Contains(got.Request.PostData.Text, "someone") {
		t.Errorf("request form kept the login identifier: %s", got.Request.PostData.Text)
	}
	if !strings.Contains(got.Request.PostData.Text, "username=") {
		t.Errorf("request form lost the field name: %s", got.Request.PostData.Text)
	}
	if !strings.Contains(got.Response.Content.Text, `"name":"x"`) {
		t.Errorf("JSON body lost a non-secret field: %s", got.Response.Content.Text)
	}
}

func TestRedact_SecretFieldNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{"password", true},
		{"Password", true},
		{"passwd", true},
		{"pwd", true},
		{"new_password", true},
		{"user[password]", true},
		{"motdepasse", true},
		{"mot_de_passe", true},
		{"csrf_token", true},
		{"_csrf", true},
		{"authenticity_token", true},
		{"__RequestVerificationToken", true},
		{"access_token", true},
		{"refresh_token", true},
		{"id_token", true},
		{"code_verifier", true},
		{"client_secret", true},
		{"otp", true},
		{"totp", true},
		{"session", true},
		{"sessionid", true},
		{"jsessionid", true},
		{"api_key", true},
		{"apikey", true},
		{"SAMLResponse", true},
		{"pin", true},
		{"username", false},
		{"page", false},
		{"from", false},
		{"to", false},
		{"invoice_id", false},
		{"contract", false},
		{"lang", false},
		{"pinned", false},
		{"spinner", false},
	}
	for _, tt := range tests {
		if got := har.SecretField(tt.name); got != tt.want {
			t.Errorf("SecretField(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestRedact_JSONBodiesNested(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	in := `{"user":{"login":"a","credentials":{"password":"` + pw + `"}},"list":[{"token":"` + pw + `","id":1}]}`
	out := har.RedactBody("application/json; charset=utf-8", in)
	if strings.Contains(out, pw) {
		t.Fatalf("nested JSON secret kept: %s", out)
	}
	if !strings.Contains(out, `"login":"a"`) || !strings.Contains(out, `"id":1`) {
		t.Fatalf("non-secret JSON fields lost: %s", out)
	}
}

func TestRedact_JWTAndBearerAnywhere(t *testing.T) {
	t.Parallel()
	// Synthetic JWT, split for secret scanners (SEC-J1-9); value unchanged.
	jwt := "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "c2lnbmF0dXJlLXZhbHVlLWZha2U"
	in := `<html><script>var t = "` + jwt + `"; fetch(u, {headers: {Authorization: "Bearer abcdefghijklmnop0123456789"}})</script></html>`
	out := har.RedactBody("text/html", in)
	if strings.Contains(out, jwt) || strings.Contains(out, "abcdefghijklmnop0123456789") {
		t.Fatalf("JWT or bearer token kept: %s", out)
	}
}

func TestRedact_HTMLPasswordInputValue(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	tok := testsecrets.Canary(t, testsecrets.Token)
	in := `<form><input type="password" name="pw" value="` + pw + `"><input type="hidden" name="csrf_token" value="` + tok + `"><input name="q" value="ok"></form>`
	out := har.RedactBody("text/html", in)
	if strings.Contains(out, pw) || strings.Contains(out, tok) {
		t.Fatalf("form secret kept: %s", out)
	}
	if !strings.Contains(out, `value="ok"`) {
		t.Fatalf("harmless input value lost: %s", out)
	}
}

func TestRedact_BinaryBodyDropped(t *testing.T) {
	t.Parallel()
	c := har.RedactContent(har.Content{MimeType: "application/pdf", Encoding: "base64", Text: "JVBERi0xLjcK", Size: 9})
	if c.Text != "" || c.Comment == "" || c.Size != 9 {
		t.Fatalf("binary body = %+v, want dropped with a comment and size kept", c)
	}
}

func TestDecode_RejectsGarbageAndHugeInput(t *testing.T) {
	t.Parallel()
	if _, err := har.Decode(strings.NewReader("not json")); !errors.Is(err, har.ErrInvalid) {
		t.Fatalf("Decode garbage err = %v, want ErrInvalid", err)
	}
	if _, err := har.Decode(strings.NewReader(`{"log":{"version":"1.2","entries":[]}} {}`)); !errors.Is(err, har.ErrInvalid) {
		t.Fatalf("Decode trailing data err = %v, want ErrInvalid", err)
	}
	big := strings.NewReader(`{"log":{"comment":"` + strings.Repeat("a", har.MaxFileBytes) + `"}}`)
	if _, err := har.Decode(big); !errors.Is(err, har.ErrTooLarge) {
		t.Fatalf("Decode huge err = %v, want ErrTooLarge", err)
	}
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	t.Parallel()
	e, _ := secretEntry(t)
	f := har.New("facto test", "dev")
	f.Log.Entries = append(f.Log.Entries, har.RedactEntry(e))
	var buf bytes.Buffer
	if err := har.Encode(&buf, f); err != nil {
		t.Fatal(err)
	}
	g, err := har.Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if g.Log.Version != "1.2" || len(g.Log.Entries) != 1 || g.Log.Creator.Name != "facto test" {
		t.Fatalf("round trip = %+v", g.Log)
	}
}

func TestCheck_FindsLeftoverSecrets(t *testing.T) {
	t.Parallel()
	e, _ := secretEntry(t)
	f := har.New("t", "dev")
	f.Log.Entries = []har.Entry{e}
	if got := har.Check(f); len(got) == 0 {
		t.Fatal("Check on an unredacted entry found nothing")
	}
	f.Log.Entries = []har.Entry{har.RedactEntry(e)}
	if got := har.Check(f); len(got) != 0 {
		t.Fatalf("Check on a redacted entry = %q, want none", got)
	}
}

func TestRedact_Idempotent(t *testing.T) {
	t.Parallel()
	e, _ := secretEntry(t)
	once := har.RedactEntry(e)
	twice := har.RedactEntry(once)
	a, _ := json.Marshal(once)
	b, _ := json.Marshal(twice)
	if !bytes.Equal(a, b) {
		t.Fatalf("RedactEntry is not idempotent:\n%s\n%s", a, b)
	}
	// Harmless JSON keeps its exact formatting (fixtures stay reviewable).
	in := "{\n  \"b\": 1,\n  \"a\": \"x\"\n}"
	if got := har.RedactBody("application/json", in); got != in {
		t.Fatalf("harmless JSON reformatted: %q", got)
	}
}

func TestRedact_LoginIdentifiersInRequestsOnly(t *testing.T) {
	t.Parallel()
	for _, n := range []string{"username", "login", "email", "user[email]", "j_username", "identifiant"} {
		if !har.LoginField(n) {
			t.Errorf("LoginField(%q) = false", n)
		}
	}
	e := har.Entry{
		Request: har.Request{Method: "POST", URL: "https://a.test/api", PostData: &har.PostData{
			MimeType: "application/json", Text: `{"email":"someone@example.org","remember":true}`,
		}},
		Response: har.Response{Content: har.Content{MimeType: "application/json", Text: `{"email":"someone@example.org"}`}},
	}
	got := har.RedactEntry(e)
	if strings.Contains(got.Request.PostData.Text, "someone") || !strings.Contains(got.Request.PostData.Text, `"remember":true`) {
		t.Errorf("request JSON = %s, want login removed, other fields kept", got.Request.PostData.Text)
	}
	if !strings.Contains(got.Response.Content.Text, "someone@example.org") {
		t.Errorf("response JSON lost a non-credential field (sanitize.sh handles PII): %s", got.Response.Content.Text)
	}
}

// TestTaint_ScrubsSecretValuesEverywhere: a value seen in a secret position
// (cookie, Authorization, secret or login form field, secret JSON field)
// is removed from every other string of the file, bodies of other entries
// included: a login page that inlines the password, an SPA that inlines
// its bearer token.
func TestTaint_ScrubsSecretValuesEverywhere(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	tok := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	login := "someone.private@example.org"
	entries := []har.Entry{
		{
			Request: har.Request{Method: "GET", URL: "https://a.test/login"},
			Response: har.Response{Content: har.Content{
				MimeType: "text/html",
				Text:     `<script>u.value="` + login + `"; p.value="` + pw + `"; var t = "` + tok + `"; x="` + sess + `"</script>`,
			}},
		},
		{
			Request: har.Request{Method: "POST", URL: "https://a.test/login", PostData: &har.PostData{
				MimeType: "application/x-www-form-urlencoded", Text: "username=" + url(login) + "&password=" + pw,
			}},
			Response: har.Response{Headers: []har.NV{{Name: "Set-Cookie", Value: "sid=" + sess + "; Path=/"}}},
		},
		{
			Request:  har.Request{Method: "GET", URL: "https://a.test/api", Headers: []har.NV{{Name: "Authorization", Value: "Bearer " + tok}}},
			Response: har.Response{Content: har.Content{MimeType: "application/json", Text: `{"echo":"` + tok + `"}`}},
		},
	}
	f := har.New("t", "dev")
	taint := har.NewTaint()
	for _, e := range entries {
		taint.Collect(e)
		f.Log.Entries = append(f.Log.Entries, har.RedactEntry(e))
	}
	taint.Scrub(f)
	var buf bytes.Buffer
	if err := har.Encode(&buf, f); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{pw, tok, sess, login} {
		if bytes.Contains(buf.Bytes(), []byte(s)) {
			t.Fatalf("tainted value %q survived the scrub:\n%s", s, buf.Bytes())
		}
	}
	if !strings.Contains(buf.String(), "<script>") {
		t.Fatalf("scrub destroyed the page structure:\n%s", buf.Bytes())
	}
}

// TestTaint_IgnoresShortAndCommonValues: values too short or too common to
// be secrets ("1", "true", "en") are never tainted: they would wipe the
// whole file.
func TestTaint_IgnoresShortAndCommonValues(t *testing.T) {
	t.Parallel()
	taint := har.NewTaint()
	taint.Collect(har.Entry{Request: har.Request{Method: "POST", URL: "https://a.test/", PostData: &har.PostData{
		MimeType: "application/x-www-form-urlencoded", Text: "remember_token=true&pin=1234&session=en",
	}}})
	f := har.New("t", "dev")
	f.Log.Entries = []har.Entry{{
		Request:  har.Request{Method: "GET", URL: "https://a.test/?lang=en&n=1234"},
		Response: har.Response{Content: har.Content{MimeType: "text/plain", Text: "true en 1234"}},
	}}
	taint.Scrub(f)
	if got := f.Log.Entries[0].Response.Content.Text; got != "true en 1234" {
		t.Fatalf("short values scrubbed: %q", got)
	}
}

// TestSecretHeader_PseudoHeadersKept: HTTP/2 pseudo-headers are not
// secrets (":authority" is the host).
func TestSecretHeader_PseudoHeadersKept(t *testing.T) {
	t.Parallel()
	for _, h := range []string{":authority", ":path", ":method", ":scheme"} {
		if har.SecretHeader(h) {
			t.Errorf("SecretHeader(%q) = true", h)
		}
	}
}

func url(s string) string { return strings.NewReplacer("@", "%40").Replace(s) }

// TestCheck_CleanMinimalEntryPasses: an entry without secrets (nil lists
// included) is not a finding.
func TestCheck_CleanMinimalEntryPasses(t *testing.T) {
	t.Parallel()
	f := har.New("t", "dev")
	f.Log.Entries = []har.Entry{{
		Request:  har.Request{Method: "GET", URL: "https://a.test/x?page=1"},
		Response: har.Response{Status: 200, Content: har.Content{MimeType: "application/json", Text: `{"a":1}`}},
	}}
	if got := har.Check(f); len(got) != 0 {
		t.Fatalf("Check = %q, want none", got)
	}
}

// TestRedact_InlineScriptSecretKeys (J2): a page that inlines a token in a
// script object ({token: "…"}, "access_token": "…", csrfToken = '…') has it
// removed even when no request ever carried it in a header.
func TestRedact_InlineScriptSecretKeys(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	for _, in := range []string{
		`<script>window.__FP = {token: "` + tok + `", list: "/api"};</script>`,
		`<script>var cfg = {"access_token":"` + tok + `"}</script>`,
		`<script>window.csrfToken = '` + tok + `';</script>`,
		`<meta name="csrf-token" content="` + tok + `">`,
	} {
		out := har.RedactBody("text/html", in)
		if strings.Contains(out, tok) {
			t.Errorf("inline secret kept: %s", out)
		}
	}
	keep := `<script>var cfg = {list: "/api/invoices", page: "1"};</script>`
	if got := har.RedactBody("text/html", keep); got != keep {
		t.Errorf("harmless inline config changed: %s", got)
	}
}

// TestTaint_InlineSecretScrubbedElsewhere: a token first seen inline on a
// page is scrubbed from the other entries too.
func TestTaint_InlineSecretScrubbedElsewhere(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	entries := []har.Entry{
		{
			Request:  har.Request{Method: "GET", URL: "https://a.test/"},
			Response: har.Response{Content: har.Content{MimeType: "text/html", Text: `<script>x = {token: "` + tok + `"}</script>`}},
		},
		{
			Request:  har.Request{Method: "GET", URL: "https://a.test/api?echo=x"},
			Response: har.Response{Content: har.Content{MimeType: "text/plain", Text: "seen " + tok}},
		},
	}
	f := har.New("t", "dev")
	taint := har.NewTaint()
	for _, e := range entries {
		taint.Collect(e)
		f.Log.Entries = append(f.Log.Entries, har.RedactEntry(e))
	}
	taint.Scrub(f)
	var b bytes.Buffer
	if err := har.Encode(&b, f); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Bytes(), []byte(tok)) {
		t.Fatalf("inline token survived elsewhere:\n%s", b.Bytes())
	}
}

// TestScrub_ThenCheckClean (J2, Wecasa "redaction check failed"): a file
// whose tainted values were scrubbed out of URLs, headers and bodies passes
// har.Check: the scrub leaves nothing a second redaction would change.
func TestScrub_ThenCheckClean(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	entries := []har.Entry{
		{Request: har.Request{
			Method: "GET", URL: "https://a.test/api",
			Headers: []har.NV{{Name: "Authorization", Value: "Bearer " + tok}, {Name: "Cookie", Value: "sid=" + sess}},
		}},
		{
			Request: har.Request{
				Method: "GET", URL: "https://a.test/sessions/" + tok + "/invoice?ref=" + sess + "&page=1",
				Headers:     []har.NV{{Name: "Referer", Value: "https://a.test/x?ref=" + sess}, {Name: ":path", Value: "/sessions/" + tok + "/invoice?ref=" + sess}},
				QueryString: []har.NV{{Name: "ref", Value: sess}, {Name: "page", Value: "1"}},
			},
			Response: har.Response{
				RedirectURL: "/next?ref=" + sess,
				Headers:     []har.NV{{Name: "Location", Value: "/next?ref=" + sess}},
				Content:     har.Content{MimeType: "application/json", Text: `{"ref":"` + sess + `","url":"/sessions/` + tok + `"}`},
			},
		},
	}
	f := har.New("t", "dev")
	taint := har.NewTaint()
	for _, e := range entries {
		taint.Collect(e)
		f.Log.Entries = append(f.Log.Entries, har.RedactEntry(e))
	}
	taint.Scrub(f)
	if got := har.Check(f); len(got) != 0 {
		for i, e := range f.Log.Entries {
			a, _ := json.Marshal(e)
			b, _ := json.Marshal(har.RedactEntry(e))
			if !bytes.Equal(a, b) {
				t.Errorf("entry %d changes on a second redaction:\n%s\n%s", i, a, b)
			}
		}
		t.Fatalf("Check after scrub = %q", got)
	}
}

// TestCheck_FindingNamesPlaceNotValue: a finding says which part of which
// entry is unredacted, never the value.
func TestCheck_FindingNamesPlaceNotValue(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	f := har.New("t", "dev")
	f.Log.Entries = []har.Entry{{Request: har.Request{
		Method: "GET", URL: "https://a.test/?access_token=" + tok,
		Headers: []har.NV{{Name: "X-Auth-Token", Value: tok}},
	}}}
	got := har.Check(f)
	if len(got) != 1 || !strings.Contains(got[0], "request url") || !strings.Contains(got[0], "request header X-Auth-Token") {
		t.Fatalf("Check = %q", got)
	}
	if strings.Contains(got[0], tok) {
		t.Fatalf("finding quotes the value: %q", got[0])
	}
}

// TestStabilize_FixedPointAndOnlyRemoves (J2): Stabilize redacts until a
// second redaction changes nothing, so Check is clean, and it never brings
// a value back: every round only removes.
func TestStabilize_FixedPointAndOnlyRemoves(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	f := har.New("t", "dev")
	// A scrubbed value left as a raw "[redacted]" in a query: RedactURL
	// re-encodes it on the next round; the header was never redacted.
	f.Log.Entries = []har.Entry{{Request: har.Request{
		Method: "GET", URL: "https://a.test/x?ref=[redacted]&page=1",
		Headers: []har.NV{{Name: "X-Session", Value: tok}},
	}}}
	if !har.Stabilize(f, 3) {
		t.Fatal("Stabilize did not reach a fixed point in 3 rounds")
	}
	if got := har.Check(f); len(got) != 0 {
		t.Fatalf("Check after Stabilize = %q", got)
	}
	var b bytes.Buffer
	if err := har.Encode(&b, f); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Bytes(), []byte(tok)) {
		t.Fatal("secret header survived Stabilize")
	}
	if !strings.Contains(f.Log.Entries[0].Request.URL, "page=1") {
		t.Fatalf("harmless query lost: %s", f.Log.Entries[0].Request.URL)
	}
}
