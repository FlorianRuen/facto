package har_test

import (
	"encoding/json"
	neturl "net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/har"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// SEC-J2-2: request bodies are redacted field by field only in formats
// har can parse (urlencoded, JSON, multipart/form-data); any other request
// body is dropped (fail closed), and Check flags it. A password or a login
// must never survive, whatever the login page's encoding.

const mpBoundary = "----WebKitFormBoundaryAbC123"

func multipartBody(parts ...[2]string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--" + mpBoundary + "\r\n")
		b.WriteString(`Content-Disposition: form-data; name="` + p[0] + `"` + "\r\n\r\n")
		b.WriteString(p[1] + "\r\n")
	}
	b.WriteString("--" + mpBoundary + "--\r\n")
	return b.String()
}

// recordPipeline runs what record.Run does: Collect, RedactEntry, Scrub,
// Stabilize; it returns the encoded file and the Check findings of the raw
// entry.
func recordPipeline(t *testing.T, e har.Entry) (string, []string) {
	t.Helper()
	raw := har.New("facto", "test")
	raw.Log.Entries = []har.Entry{e}
	findings := har.Check(raw)
	taint := har.NewTaint()
	taint.Collect(e)
	f := har.New("facto", "test")
	f.Log.Entries = []har.Entry{har.RedactEntry(e)}
	taint.Scrub(f)
	if !har.Stabilize(f, 3) {
		t.Fatalf("Stabilize did not reach a fixed point")
	}
	if c := har.Check(f); len(c) != 0 {
		t.Fatalf("Check after redaction = %v, want none", c)
	}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(out), findings
}

func postEntry(mime, body string) har.Entry {
	return har.Entry{
		StartedDateTime: "2026-01-01T00:00:00Z",
		Request: har.Request{
			Method: "POST", URL: "https://login.supplier.example/session", HTTPVersion: "HTTP/1.1",
			PostData: &har.PostData{MimeType: mime, Text: body},
		},
		Response: har.Response{Status: 200, Content: har.Content{MimeType: "text/html", Text: "<p>ok</p>"}},
	}
}

func TestRedact_RequestBodiesAnyEncoding(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	login := "someone.e2e@login.example"
	cases := map[string]struct {
		mime, body string
		keep       []string // harmless values that must stay
	}{
		"multipart": {
			mime: "multipart/form-data; boundary=" + mpBoundary,
			body: multipartBody([2]string{"user[email]", login}, [2]string{"user[password]", pw}, [2]string{"commit", "Sign in"}),
			keep: []string{"commit", "Sign in", `name="user[password]"`},
		},
		"multipart short password": {
			mime: "multipart/form-data; boundary=" + mpBoundary,
			body: multipartBody([2]string{"username", login}, [2]string{"pass", pw[:4] + "x"}),
		},
		"multipart file part": {
			mime: "multipart/form-data; boundary=" + mpBoundary,
			body: "--" + mpBoundary + "\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"id.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF " + pw + "\r\n--" + mpBoundary + "--\r\n",
		},
		"multipart no boundary": {
			mime: "multipart/form-data",
			body: multipartBody([2]string{"username", login}, [2]string{"password", pw}),
		},
		"multipart truncated": {
			mime: "multipart/form-data; boundary=" + mpBoundary,
			body: "--" + mpBoundary + "\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + pw,
		},
		// Crafted bodies a server parses into a password part (review of
		// SEC-J2-2): the splitter must fail closed, never mis-name a part.
		"multipart two dispositions": {
			mime: "multipart/form-data; boundary=" + mpBoundary,
			body: "--" + mpBoundary + "\r\nContent-Disposition: form-data; name=\"password\"\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n" + pw + "\r\n--" + mpBoundary + "--\r\n",
		},
		"multipart padded boundary": {
			mime: "multipart/form-data; boundary=" + mpBoundary,
			body: "--" + mpBoundary + "\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhello\r\n--" + mpBoundary + " \r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + pw + "\r\n--" + mpBoundary + "--\r\n",
		},
		"multipart lf delimiter": {
			mime: "multipart/form-data; boundary=" + mpBoundary,
			body: "--" + mpBoundary + "\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhello\n--" + mpBoundary + "\nContent-Disposition: form-data; name=\"password\"\n\n" + pw + "\r\n--" + mpBoundary + "--\r\n",
		},
		"text/plain": {
			mime: "text/plain;charset=UTF-8",
			body: "username=" + login + "&password=" + pw,
		},
		"graphql inline": {
			mime: "application/json",
			body: `{"query":"mutation { login(email: \"` + login + `\", password: \"` + pw + `\") { token } }"}`,
			keep: []string{"mutation", "login("},
		},
		"graphql variables": {
			mime: "application/json",
			body: `{"query":"mutation Login($e: String!, $p: String!) { login(email: $e, password: $p) { ok } }","variables":{"email":"` + login + `","password":"` + pw + `"}}`,
			keep: []string{"$p"},
		},
		"invalid json": {
			mime: "application/json",
			body: `{"password":"` + pw + `", "email":"` + login + `"`,
		},
		"xml": {
			mime: "application/xml",
			body: "<login><user>" + login + "</user><password>" + pw + "</password></login>",
		},
		"octet-stream": {
			mime: "application/octet-stream",
			body: "\x00\x01" + login + "\x00" + pw,
		},
		"no mime": {
			mime: "",
			body: "u=" + login + ";p=" + pw,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := postEntry(tc.mime, tc.body)
			out, findings := recordPipeline(t, e)
			for _, secret := range []string{pw, login, url(login)} {
				if strings.Contains(out, secret) {
					t.Errorf("recorded file still holds a credential (%d bytes)", len(secret))
				}
			}
			if len(findings) == 0 {
				t.Errorf("Check on the raw entry found nothing: an unredacted %s body passes the gate", name)
			}
			for _, k := range tc.keep {
				if !strings.Contains(out, jsonText(k)) {
					t.Errorf("harmless %q lost from the recorded body", k)
				}
			}
		})
	}
}

// jsonText is s as it appears inside a JSON-encoded string.
func jsonText(s string) string {
	b, _ := json.Marshal(s)
	return strings.Trim(string(b), `"`)
}

// TestRedact_DroppedRequestBodySaysSo: a body that cannot be redacted
// field by field is dropped with a comment (the connector author knows a
// body existed, of what type).
func TestRedact_DroppedRequestBodySaysSo(t *testing.T) {
	t.Parallel()
	r := har.RedactEntry(postEntry("text/plain", "anything at all"))
	pd := r.Request.PostData
	if pd == nil || pd.Text != "" || pd.MimeType != "text/plain" || !strings.Contains(pd.Comment, "not recorded") {
		t.Fatalf("dropped body = %+v, want empty text, kept MIME type and a comment", pd)
	}
	again := har.RedactEntry(r)
	if a := again.Request.PostData; a.Text != pd.Text || a.MimeType != pd.MimeType || a.Comment != pd.Comment {
		t.Errorf("redacting a dropped body again changed it: %+v", again.Request.PostData)
	}
}

// TestRedact_MultipartIdempotent: redacting a redacted multipart body
// changes nothing (Check stays clean, Stabilize converges in one round).
func TestRedact_MultipartIdempotent(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	e := postEntry("multipart/form-data; boundary="+mpBoundary,
		multipartBody([2]string{"login", "someone"}, [2]string{"password", pw}, [2]string{"remember", "1"}))
	once := har.RedactEntry(e)
	twice := har.RedactEntry(once)
	if once.Request.PostData.Text != twice.Request.PostData.Text {
		t.Fatalf("multipart redaction not idempotent:\n%q\n%q", once.Request.PostData.Text, twice.Request.PostData.Text)
	}
	if !strings.Contains(once.Request.PostData.Text, "remember") || strings.Contains(once.Request.PostData.Text, pw) {
		t.Fatalf("multipart redaction = %q", once.Request.PostData.Text)
	}
}

// TestTaint_MultipartAndGraphQLValuesScrubbedElsewhere: a password sent in
// a multipart part or a GraphQL argument and echoed in a response is
// scrubbed there too.
func TestTaint_MultipartAndGraphQLValuesScrubbedElsewhere(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	for name, e := range map[string]har.Entry{
		"multipart": postEntry("multipart/form-data; boundary="+mpBoundary, multipartBody([2]string{"password", pw})),
		"graphql":   postEntry("application/json", `{"query":"mutation { login(password: \"`+pw+`\") { ok } }"}`),
		"textplain": postEntry("text/plain", "password="+pw),
		"crafted multipart": postEntry("multipart/form-data; boundary="+mpBoundary,
			"--"+mpBoundary+"\r\nContent-Disposition: form-data; name=\"password\"\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n"+pw+"\r\n--"+mpBoundary+"--\r\n"),
	} {
		e.Response.Content.Text = "<p>debug: " + pw + "</p>"
		out, _ := recordPipeline(t, e)
		if strings.Contains(out, pw) {
			t.Errorf("%s: password echoed in a response survived the scrub", name)
		}
	}
}

// SEC-J2-6: the declared content type is not trusted, and encodings nest.
// Every case goes through the record pipeline; no secret may survive and
// Check on the raw entry must flag it.
func TestRedact_RequestBodyNestedEncodings(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	login := "someone.e2e@login.example"
	aura := `{"actions":[{"id":"1;a","params":{"username":"` + login + `","password":"` + pw + `","startUrl":""}}]}`
	cases := map[string]struct {
		mime, body string
		secrets    []string
		keep       []string
	}{
		"json under urlencoded type (jQuery)": {
			"application/x-www-form-urlencoded; charset=UTF-8",
			`{"username":"` + login + `","password":"` + pw + `"}`,
			[]string{pw, login},
			nil,
		},
		"json inside a json string": {
			"application/json",
			`{"body":"{\"username\":\"` + login + `\",\"password\":\"` + pw + `\"}"}`,
			[]string{pw, login},
			[]string{"body"},
		},
		"json inside a urlencoded value": {
			"application/x-www-form-urlencoded",
			"message=" + neturl.QueryEscape(aura) + "&aura.context=x",
			[]string{pw, login},
			[]string{"aura.context=x"},
		},
		"graphql block string": {
			"application/json",
			`{"query":"mutation { login(password: \"\"\"` + pw + `\"\"\") { ok } }"}`,
			[]string{pw},
			[]string{"mutation"},
		},
		"graphql bare number": {
			"application/json",
			`{"query":"mutation { login(pin: 98127364) { ok } }"}`,
			[]string{"98127364"},
			[]string{"mutation"},
		},
		"urlencoded inside a multipart part": {
			"multipart/form-data; boundary=" + mpBoundary,
			multipartBody([2]string{"blob", "user=" + login + "&password=" + pw}),
			[]string{pw, login},
			[]string{`name=\"blob\"`},
		},
		"graphql operations part": {
			"multipart/form-data; boundary=" + mpBoundary,
			multipartBody([2]string{"operations", `{"query":"mutation($e:String!){x(email:$e)}","variables":{"email":"` + login + `"}}`}),
			[]string{login},
			[]string{"operations"},
		},
		"no mime json":       {"", `{"password":"` + pw + `"}`, []string{pw}, nil},
		"no mime urlencoded": {"", "password=" + pw + "&page=2", []string{pw}, []string{"page=2"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, findings := recordPipeline(t, postEntry(tc.mime, tc.body))
			for _, s := range tc.secrets {
				if strings.Contains(out, s) || strings.Contains(out, neturl.QueryEscape(s)) {
					t.Errorf("recorded file still holds a credential (%d bytes)", len(s))
				}
			}
			if len(findings) == 0 {
				t.Errorf("Check on the raw entry found nothing")
			}
			for _, k := range tc.keep {
				if !strings.Contains(out, k) && !strings.Contains(out, jsonText(k)) {
					t.Errorf("harmless %q lost", k)
				}
			}
		})
	}
}
