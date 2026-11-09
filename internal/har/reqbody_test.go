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
			// Values are all redacted (SEC-J2-10); names stay.
			keep: []string{`name="commit"`, `name="user[password]"`},
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
			[]string{"aura.context="},
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
		"no mime urlencoded": {"", "password=" + pw + "&page=2", []string{pw}, []string{"page="}},
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

// SEC-J2-10: credentials under neutral names. A request body keeps its
// structure and loses every value, whatever its name.
func TestRedact_RequestBodyEveryValueRedacted(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	login := "someone.e2e@login.example"
	openAM := `{"authId":"x","stage":"DataStore1","callbacks":[` +
		`{"type":"NameCallback","output":[{"name":"prompt","value":"User Name:"}],"input":[{"name":"IDToken1","value":"` + login + `"}]},` +
		`{"type":"PasswordCallback","output":[{"name":"prompt","value":"Password:"}],"input":[{"name":"IDToken2","value":"` + pw + `"}]}]}`
	cases := map[string]struct {
		mime, body string
		keep       []string
	}{
		"openam callbacks":    {"application/json", openAM, []string{"callbacks", "input"}},
		"name value pairs":    {"application/json", `{"fields":[{"name":"password","value":"` + pw + `"}]}`, []string{"fields"}},
		"jsonrpc positional":  {"application/json", `{"jsonrpc":"2.0","method":"auth.login","params":["` + login + `","` + pw + `"],"id":1}`, []string{"jsonrpc", "params"}},
		"graphql renamed var": {"application/json", `{"query":"mutation($u:String!,$p:String!){login(email:$u,password:$p){ok}}","variables":{"u":"` + login + `","p":"` + pw + `"}}`, []string{"mutation($u:String!", "variables"}},
		"array pairs":         {"application/json", `[["password","` + pw + `"]]`, nil},
		"unknown names":       {"application/json", `{"loginEmail":"` + login + `","psw":"` + pw + `","passcode":"` + pw + `"}`, []string{"loginEmail", "psw", "passcode"}},
		"numbers":             {"application/json", `{"code":98127364,"pin":4821}`, []string{"code"}},
		"duplicate keys":      {"application/json", `{"password":"` + pw + `","password":"[redacted]"}`, nil},
		"bracket names":       {"application/x-www-form-urlencoded", "creds%5B1%5D=" + neturl.QueryEscape(pw) + "&creds%5B0%5D=" + neturl.QueryEscape(login), []string{"creds%5B1%5D="}},
		"graphql escaped":     {"application/json", `{"query":"mutation { login(password: \"a\\\"` + pw + `\") }"}`, []string{"mutation"}},
		"graphql template":    {"application/json", `{"q":"login(password: ` + "`" + pw + "`" + `)"}`, []string{`"q"`}},
		"deep nesting":        {"application/json", nestJSON(`{"user":"`+login+`","secret":"`+pw+`"}`, 9), nil},
		"multipart any part":  {"multipart/form-data; boundary=" + mpBoundary, multipartBody([2]string{"blob", pw}, [2]string{"who", login}), []string{`name="blob"`}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, findings := recordPipeline(t, postEntry(tc.mime, tc.body))
			for _, s := range []string{pw, login, neturl.QueryEscape(pw), neturl.QueryEscape(login), "98127364", "4821"} {
				if strings.Contains(out, s) {
					t.Errorf("recorded file still holds a value (%d bytes)", len(s))
				}
			}
			if len(findings) == 0 {
				t.Errorf("Check on the raw entry found nothing")
			}
			for _, k := range tc.keep {
				if !strings.Contains(out, k) && !strings.Contains(out, jsonText(k)) {
					t.Errorf("structure %q lost", k)
				}
			}
		})
	}
}

// nestJSON wraps s as a JSON string value n times: {"d":"{\"d\":…}"}.
func nestJSON(s string, n int) string {
	for range n {
		b, _ := json.Marshal(s)
		s = `{"d":` + string(b) + `}`
	}
	return s
}

// TestRedact_OpenAMValueTaintedFileWide: the OpenAM credential, echoed in
// a response, is scrubbed there too (name/value pair taint).
func TestRedact_OpenAMValueTaintedFileWide(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	e := postEntry("application/json", `{"callbacks":[{"input":[{"name":"IDToken2","value":"`+pw+`"}]}]}`)
	e.Response.Content.Text = "<p>debug " + pw + "</p>"
	if out, _ := recordPipeline(t, e); strings.Contains(out, pw) {
		t.Fatal("OpenAM credential echoed in a response survived the scrub")
	}
}

// TestRedact_ParamsEveryValueRedacted (SEC-J2-11): postData.params is not
// a second, weaker path: every value is redacted, and a name that is not a
// field name (a JSON body posted as urlencoded) is too.
func TestRedact_ParamsEveryValueRedacted(t *testing.T) {
	t.Parallel()
	e := postEntry("application/x-www-form-urlencoded", "")
	e.Request.PostData.Params = []har.NV{
		{Name: "pin", Value: "4821"},
		{Name: "comment", Value: "soleil"},
		{Name: `{"username":"x","secret":"soleil"}`, Value: ""},
		{Name: "empty", Value: ""},
	}
	r := har.RedactEntry(e)
	for _, p := range r.Request.PostData.Params {
		if strings.Contains(p.Name+p.Value, "soleil") || strings.Contains(p.Value, "4821") {
			t.Errorf("param kept a value: %+v", p)
		}
	}
	if got := r.Request.PostData.Params; got[0].Name != "pin" || got[3].Value != "" {
		t.Errorf("params = %+v, want names kept and empty values empty", got)
	}
	raw := har.New("facto", "t")
	raw.Log.Entries = []har.Entry{e}
	if len(har.Check(raw)) == 0 {
		t.Error("Check found nothing in unredacted params")
	}
}

// SEC-J2-13: data placed where a name is expected (a raw base64
// "login:secret" body, a login as a JSON key, a multipart filename or
// extra header) is redacted like a value. SEC-J2-14: a string is kept as
// GraphQL only when it is a real document once its literals are gone.
func TestRedact_RequestBodyNamesCarryNoData(t *testing.T) {
	t.Parallel()
	// A synthetic random-looking value (not a real credential).
	sample := "Zq7Canary91xPw"
	login := "alice.audit@example.org"
	b64 := "YWxpY2UuYXVkaXRAZXhhbXBsZS5vcmc6WnE3Q2FuYXJ5OTF4UHc="
	cases := []struct{ name, mime, body, secret string }{
		{"raw b64 text/plain", "text/plain;charset=UTF-8", b64, strings.TrimRight(b64, "=")},
		{"raw b64 urlencoded", "application/x-www-form-urlencoded", b64, strings.TrimRight(b64, "=")},
		{"raw b64 no type", "", b64, strings.TrimRight(b64, "=")},
		{"urlencoded name", "application/x-www-form-urlencoded", "u=1&" + sample + "=", sample},
		{"json key login", "application/json", `{"accounts":{"` + login + `":{"remember":true}}}`, login},
		{"json key secret", "application/json", `{"` + sample + `":true}`, sample},
		{"multipart filename", "multipart/form-data; boundary=XyZ", "--XyZ\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"" + login + ".pdf\"\r\n\r\nabc\r\n--XyZ--\r\n", login},
		{"multipart header", "multipart/form-data; boundary=XyZ", "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\nX-Pw: " + sample + "\r\n\r\nabc\r\n--XyZ--\r\n", sample},
		{"query not a document", "application/json", `{"query":"` + sample + `"}`, sample},
		{"query login", "application/json", `{"query":"` + login + `"}`, login},
		{"js literal object", "application/json", `{"data":"{u:alice,p:` + sample + `}"}`, sample},
		{"query prefix text", "application/json", `{"msg":"query ` + sample + `"}`, sample},
		{"graphql enum arg", "application/json", `{"query":"mutation { login(user: alice, pin: ABCD` + sample + `) { ok } }"}`, sample},
		{"graphql comment", "application/json", `{"query":"mutation { login(pin: $p) { ok } } # ` + sample + `"}`, sample},
		{"graphql alias", "application/json", `{"query":"mutation { ` + sample + `: login(pin: 1) { ok } }"}`, sample},
		{"graphql dot number", "application/json", `{"query":"mutation { login(pin: .1234) { ok } }"}`, "1234"},
		{"graphql plus number", "application/json", `{"query":"mutation { login(pin: +1234) { ok } }"}`, "1234"},
		{"graphql hex number", "application/json", `{"query":"mutation { login(pin: 0x1234beef) { ok } }"}`, "1234beef"},
		{"big number", "application/json", `{"pin":12345678901234567890123}`, "12345678901234567890123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, findings := recordPipeline(t, postEntry(tc.mime, tc.body))
			if strings.Contains(out, tc.secret) {
				t.Errorf("recorded file still holds the data (%d bytes)", len(tc.secret))
			}
			if len(findings) == 0 {
				t.Errorf("Check on the raw entry found nothing")
			}
		})
	}
}

// TestRedact_FieldNamesAndDocumentsKept: the structure a connector author
// needs survives: ordinary field names, JSON-LD keys, OpenAM IDToken
// names, empty form fields, multipart part names, and a real GraphQL
// document with its variables.
func TestRedact_FieldNamesAndDocumentsKept(t *testing.T) {
	t.Parallel()
	cases := []struct{ mime, body string }{
		{"application/x-www-form-urlencoded", "user%5Bemail%5D=x&user%5Bpassword%5D=y&commit=Sign+in&remember_me="},
		{"application/json", `{"@type":"Login","IDToken2":"x","address2Line":"y","utf8":"z","callbacks":[]}`},
		{"application/json", `{"query":"mutation Login($e: String!, $p: String!) { login(email: $e, password: $p, remember: true, kind: CUSTOMER) { token user { id } } }","variables":{"e":"x","p":"y"}}`},
		{"multipart/form-data; boundary=XyZ", "--XyZ\r\nContent-Disposition: form-data; name=\"user[email]\"\r\n\r\nx\r\n--XyZ--\r\n"},
	}
	want := [][]string{
		{"user%5Bemail%5D=", "commit=", "remember_me="},
		{"@type", "IDToken2", "address2Line", "utf8", "callbacks"},
		{"mutation Login($e: String!, $p: String!)", "login(email: $e", "remember: true", "token user { id }"},
		{`name=\"user[email]\"`},
	}
	for i, tc := range cases {
		out, _ := recordPipeline(t, postEntry(tc.mime, tc.body))
		for _, k := range want[i] {
			if !strings.Contains(out, k) && !strings.Contains(out, jsonText(k)) {
				t.Errorf("case %d: structure %q lost", i, k)
			}
		}
	}
}

// SEC-J2-15: data-shaped names the first rule missed: short base64 of a
// "user:secret" pair, lowercase hex tokens (Joomla CSRF field names),
// UUID keys, a lone token posted with an empty value.
func TestRedact_RequestBodyDataShapedNames(t *testing.T) {
	t.Parallel()
	hexTok := "9f86d081884c7d659a2feaa0c55ad015"
	uuid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	cases := []struct{ name, mime, body, data string }{
		{"short b64 mixed", "text/plain", "bWFydGluOkJvbmpvdXI=", "bWFydGluOkJvbmpvdXI"},
		{"short b64 lower", "", "Ym9iOnNvbGVpbA==", "Ym9iOnNvbGVpbA"},
		{"lone token no padding", "application/x-www-form-urlencoded", "bobsoleil", "bobsoleil"},
		{"lone token empty value", "application/x-www-form-urlencoded", "bobsoleil=", "bobsoleil"},
		{"hex csrf field name", "application/x-www-form-urlencoded", "username=x&" + hexTok + "=1", hexTok},
		{"hex json key", "application/json", `{"` + hexTok + `":true}`, hexTok},
		{"uuid json key", "application/json", `{"` + uuid + `":{"a":1}}`, uuid},
		{"long unbroken key", "application/json", `{"abcdefghijklmnopqrstuvwxyzabcdefghij":1}`, "abcdefghijklmnopqrstuvwxyzabcdefghij"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, findings := recordPipeline(t, postEntry(tc.mime, tc.body))
			if strings.Contains(out, tc.data) {
				t.Errorf("recorded file still holds the data-shaped name (%d bytes)", len(tc.data))
			}
			if len(findings) == 0 {
				t.Errorf("Check on the raw entry found nothing")
			}
		})
	}
	// Ordinary names stay, a lone ordinary field among others too.
	out, _ := recordPipeline(t, postEntry("application/x-www-form-urlencoded", "remember_me=&user_id=7&csrf_token=abc"))
	for _, k := range []string{"remember_me=", "user_id=", "csrf_token="} {
		if !strings.Contains(out, k) {
			t.Errorf("field name %q lost", k)
		}
	}
}

// SEC-J2-16: enum argument values are redacted on their own (not only
// when the random-looking-name check rejects the document), and the
// document is kept.
func TestRedact_GraphQLEnumArgumentsRedacted(t *testing.T) {
	t.Parallel()
	body := `{"query":"mutation { login(user: alice, pin: SOLEIL, kind: CUSTOMER, remember: true) { ok } }"}`
	out, _ := recordPipeline(t, postEntry("application/json", body))
	for _, v := range []string{"alice", "SOLEIL", "CUSTOMER"} {
		if strings.Contains(out, v) {
			t.Errorf("enum argument %q kept", v)
		}
	}
	for _, k := range []string{"mutation { login(user: [redacted], pin: [redacted], kind: [redacted], remember: true) { ok } }"} {
		if !strings.Contains(out, k) {
			t.Errorf("document %q not kept with its enum values redacted:\n%s", k, out)
		}
	}
}

// SEC-J2-17: random tokens used as names, letter-led so the
// identifier-shape rule alone does not reject them, are redacted; field
// names made of words are kept.
func TestDataLikeNames(t *testing.T) {
	t.Parallel()
	data := []string{
		"f47ac10b-58cc-4372-a567-0e02b2c3d479", // UUID, letter-led
		"abcdefab-cdef-4abc-abcd-abcdefabcdef", // UUID with one digit run
		"F47AC10B58CC4372A5670E02B2C3D479",     // upper-case hex
		"deadbeefcafe1234",                     // 16-char hex, letter-led
		"kXpQzRmWtYvLsNbHjGfDcA",               // base64url, no digit
		"h1n3uv7qkt0b9gd2sl5rjm8e4a",           // PHP session id shape
		"Zq7Canary91xPw",                       // mixed case, digits
		"abcdefghijklmnopqrstuvwxyzabcdefghij", // long lowercase run
	}
	for _, s := range data {
		if !har.DataLikeName(s) {
			t.Errorf("DataLikeName(%q) = false, want true", s)
		}
	}
	fields := []string{
		"username", "user[email]", "remember_me", "csrf_token", "IDToken2", "address2Line",
		"utf8", "customerNotificationPreferences", "x-csrf-token", "authenticity_token",
		"startUrl", "g-recaptcha-response", "aura.context", "deliveryAddressLine1", "@type",
		"__VIEWSTATEGENERATOR", "ctl00_MainContent_txtUser",
	}
	for _, s := range fields {
		if har.DataLikeName(s) {
			t.Errorf("DataLikeName(%q) = true, want false (a field name)", s)
		}
	}
}

// TestRedact_LetterLedTokenNames: the same shapes as JSON keys and form
// names go through the record pipeline redacted.
func TestRedact_LetterLedTokenNames(t *testing.T) {
	t.Parallel()
	for _, tok := range []string{"f47ac10b-58cc-4372-a567-0e02b2c3d479", "F47AC10B58CC4372A5670E02B2C3D479", "deadbeefcafe1234", "kXpQzRmWtYvLsNbHjGfDcA", "h1n3uv7qkt0b9gd2sl5rjm8e4a"} {
		for _, body := range [][2]string{
			{"application/json", `{"` + tok + `":true}`},
			{"application/x-www-form-urlencoded", "username=x&" + tok + "=1"},
		} {
			out, _ := recordPipeline(t, postEntry(body[0], body[1]))
			if strings.Contains(out, tok) {
				t.Errorf("token name %q kept in a %s body", tok, body[0])
			}
		}
	}
}
