// Package har is the HAR 1.2 subset facto writes and reads (`facto record`,
// scripts/harslim, scripts/fixtures), and the redaction every recorded
// entry goes through before it is kept in memory or written anywhere.
//
// Redaction (RedactEntry) is the single place that decides what a recording
// may hold. It removes, whatever the site:
//   - the value of every Cookie, Set-Cookie, Authorization,
//     Proxy-Authorization and WWW-Authenticate header, and of every header
//     whose name says it carries a token, key, secret, CSRF value or session;
//   - every cookie value (request and response cookie lists);
//   - the value of every query, form or JSON field whose name is a secret
//     field (SecretField: passwords, OTPs, tokens, CSRF, session ids, keys);
//   - JWTs, "Bearer <token>" strings and <input type=password> values
//     anywhere in a text body;
//   - every binary body (PDFs included): only its MIME type and size stay.
//
// It never removes personal data (names, addresses, contract numbers):
// scripts/fixtures/sanitize.sh does that, and scripts/fixtures/scan.sh
// checks it.
package har

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Redacted replaces every removed value.
const Redacted = "[redacted]"

// MaxFileBytes caps a HAR file read by Decode.
const MaxFileBytes = 64 << 20

// MaxBodyBytes caps one text body kept in a recording; longer bodies are
// cut (Content.Comment says so).
const MaxBodyBytes = 2 << 20

var (
	// ErrInvalid reports a file that is not one HAR JSON document.
	ErrInvalid = errors.New("har: not a valid HAR file")
	// ErrTooLarge reports a file over MaxFileBytes.
	ErrTooLarge = errors.New("har: file too large")
)

// File is a HAR document.
type File struct {
	Log Log `json:"log"`
}

// Log is the HAR log.
type Log struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Pages   []Page  `json:"pages,omitempty"`
	Entries []Entry `json:"entries"`
	Comment string  `json:"comment,omitempty"`
}

// Creator names the tool that wrote the file.
type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Page is one HAR page.
type Page struct {
	StartedDateTime string `json:"startedDateTime"`
	ID              string `json:"id"`
	Title           string `json:"title"`
}

// Entry is one request and its response.
type Entry struct {
	Pageref         string   `json:"pageref,omitempty"`
	StartedDateTime string   `json:"startedDateTime"`
	Time            float64  `json:"time"`
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
	Cache           struct{} `json:"cache"`
	Timings         Timings  `json:"timings"`
	ResourceType    string   `json:"_resourceType,omitempty"`
	Comment         string   `json:"comment,omitempty"`
}

// Timings are the HAR timings; facto records none (-1).
type Timings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// NV is a name/value pair (headers, query string, form params).
type NV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Cookie is a HAR cookie.
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}

// Request is a HAR request.
type Request struct {
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	HTTPVersion string    `json:"httpVersion"`
	Headers     []NV      `json:"headers"`
	Cookies     []Cookie  `json:"cookies"`
	QueryString []NV      `json:"queryString"`
	PostData    *PostData `json:"postData,omitempty"`
	HeadersSize int       `json:"headersSize"`
	BodySize    int       `json:"bodySize"`
}

// PostData is a request body.
type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Params   []NV   `json:"params,omitempty"`
}

// Response is a HAR response.
type Response struct {
	Status      int      `json:"status"`
	StatusText  string   `json:"statusText"`
	HTTPVersion string   `json:"httpVersion"`
	Headers     []NV     `json:"headers"`
	Cookies     []Cookie `json:"cookies"`
	Content     Content  `json:"content"`
	RedirectURL string   `json:"redirectURL"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
}

// Content is a response body.
type Content struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// New returns an empty HAR 1.2 file.
func New(creator, version string) *File {
	return &File{Log: Log{Version: "1.2", Creator: Creator{Name: creator, Version: version}, Entries: []Entry{}}}
}

// Encode writes f as indented JSON.
func Encode(w io.Writer, f *File) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return fmt.Errorf("har: encode: %w", err)
	}
	return nil
}

// Decode reads exactly one HAR JSON document of at most MaxFileBytes.
func Decode(r io.Reader) (*File, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("har: read: %w", err)
	}
	if len(data) > MaxFileBytes {
		return nil, ErrTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var f File
	if err := dec.Decode(&f); err != nil {
		// The decoder error may quote input bytes: never returned.
		return nil, ErrInvalid
	}
	if dec.More() {
		return nil, ErrInvalid
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	return &f, nil
}

// secretHeaders have their value removed whatever it holds.
var secretHeaders = []string{
	"authorization", "proxy-authorization", "cookie", "set-cookie", "set-cookie2",
	"www-authenticate", "proxy-authenticate", "x-amz-security-token",
}

// secretHeaderWords mark a header carrying a secret by its name.
var secretHeaderWords = []string{"token", "secret", "csrf", "xsrf", "session", "auth", "key", "password", "signature"}

// SecretHeader reports whether the value of header name is removed.
func SecretHeader(name string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, ":") {
		// HTTP/2 pseudo-headers (:authority, :path, :method, :scheme);
		// :path goes through redactText like any other value.
		return false
	}
	if slices.Contains(secretHeaders, n) {
		return true
	}
	for _, w := range secretHeaderWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// secretFieldWords mark a field as secret when they appear anywhere in its
// normalized name (lowercase, separators removed).
var secretFieldWords = []string{
	"password", "passwd", "passphrase", "motdepasse", "secret", "token", "csrf", "xsrf",
	"session", "apikey", "accesskey", "privatekey", "otp", "codeverifier", "samlresponse",
	"samlrequest", "assertion", "credential", "authcode", "nonce", "signature",
}

// secretFieldExact are secret only as the whole normalized name: as
// substrings they would match harmless names ("spinner", "pinned").
var secretFieldExact = []string{"pwd", "pw", "pass", "pin", "mdp", "code", "sid", "jwt", "auth", "key", "ticket", "otc"}

// SecretField reports whether a query, form or JSON field named name holds
// a secret. Bracketed form names ("user[password]") are matched on each part.
func SecretField(name string) bool {
	for part := range strings.FieldsFuncSeq(name, func(r rune) bool { return r == '[' || r == ']' || r == '.' }) {
		n := normalizeField(part)
		if n == "" {
			continue
		}
		if slices.Contains(secretFieldExact, n) {
			return true
		}
		for _, w := range secretFieldWords {
			if strings.Contains(n, w) {
				return true
			}
		}
	}
	return false
}

func normalizeField(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RedactEntry returns a copy of e with every secret removed (package doc).
func RedactEntry(e Entry) Entry {
	out := e
	out.Request = redactRequest(e.Request)
	out.Response = redactResponse(e.Response)
	return out
}

func redactRequest(r Request) Request {
	out := r
	out.URL = RedactURL(r.URL)
	out.Headers = redactHeaders(r.Headers)
	out.Cookies = redactCookies(r.Cookies)
	out.QueryString = redactNV(r.QueryString)
	if r.PostData != nil {
		pd := *r.PostData
		pd.Params = redactNVWith(pd.Params, requestField)
		pd.Text = redactBodyWith(pd.MimeType, pd.Text, requestField)
		out.PostData = &pd
	}
	return out
}

// loginFields are the login identifiers a request body may carry: half of
// a credential, removed from request bodies only (response bodies keep
// them for sanitize.sh, which turns them into synthetic values).
var loginFields = []string{
	"username", "user", "login", "loginid", "userid", "email", "mail", "emailaddress",
	"identifiant", "identifier", "jusername", "uid", "principal",
}

// LoginField reports whether a request field named name carries a login
// identifier.
func LoginField(name string) bool {
	for part := range strings.FieldsFuncSeq(name, func(r rune) bool { return r == '[' || r == ']' || r == '.' }) {
		if slices.Contains(loginFields, normalizeField(part)) {
			return true
		}
	}
	return false
}

// requestField is the field rule of request bodies.
func requestField(name string) bool { return SecretField(name) || LoginField(name) }

func redactResponse(r Response) Response {
	out := r
	out.Headers = redactHeaders(r.Headers)
	out.Cookies = redactCookies(r.Cookies)
	out.RedirectURL = RedactURL(r.RedirectURL)
	out.Content = RedactContent(r.Content)
	return out
}

func redactHeaders(hs []NV) []NV {
	if hs == nil {
		return nil
	}
	out := make([]NV, len(hs))
	for i, h := range hs {
		out[i] = h
		switch {
		case SecretHeader(h.Name):
			out[i].Value = Redacted
		case strings.EqualFold(h.Name, "location") || strings.EqualFold(h.Name, "referer") || h.Name == ":path":
			out[i].Value = RedactURL(h.Value)
		default:
			out[i].Value = redactText(h.Value)
		}
	}
	return out
}

func redactCookies(cs []Cookie) []Cookie {
	if cs == nil {
		return nil
	}
	out := make([]Cookie, len(cs))
	for i, c := range cs {
		out[i] = c
		out[i].Value = Redacted
	}
	return out
}

func redactNV(nv []NV) []NV { return redactNVWith(nv, SecretField) }

func redactNVWith(nv []NV, secretField func(string) bool) []NV {
	if nv == nil {
		return nil
	}
	out := make([]NV, len(nv))
	for i, p := range nv {
		out[i] = p
		if secretField(p.Name) {
			out[i].Value = Redacted
		} else {
			out[i].Value = redactText(p.Value)
		}
	}
	return out
}

// RedactURL removes the userinfo, the fragment and the value of every secret
// query field of raw. An unparsable URL is replaced whole.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Redacted
	}
	u.User = nil
	u.Fragment, u.RawFragment = "", ""
	if u.RawQuery != "" {
		u.RawQuery = redactQuery(u.RawQuery)
	}
	return u.String()
}

// redactQuery keeps the order and the encoding of every harmless pair.
func redactQuery(q string) string { return redactQueryWith(q, SecretField) }

func redactQueryWith(q string, secretField func(string) bool) string {
	parts := strings.Split(q, "&")
	for i, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		name, err := url.QueryUnescape(k)
		if err != nil {
			name = k
		}
		switch {
		case secretField(name):
			if ok {
				parts[i] = k + "=" + url.QueryEscape(Redacted)
			}
		case ok:
			val, err := url.QueryUnescape(v)
			if err != nil {
				val = v
			}
			if r := redactText(val); r != val {
				parts[i] = k + "=" + url.QueryEscape(r)
			}
		}
	}
	return strings.Join(parts, "&")
}

// RedactContent removes the secrets of a response body; a binary body is
// dropped (MIME type and size kept).
func RedactContent(c Content) Content {
	out := c
	if c.Encoding != "" || !textMIME(c.MimeType) {
		out.Text, out.Encoding = "", ""
		if c.Text != "" || c.Size > 0 {
			out.Comment = "binary body not recorded"
		}
		return out
	}
	if len(c.Text) > MaxBodyBytes {
		out.Text = c.Text[:MaxBodyBytes]
		out.Comment = "body cut at " + fmt.Sprint(MaxBodyBytes) + " bytes"
	}
	out.Text = RedactBody(c.MimeType, out.Text)
	return out
}

// textMIME reports whether a body of that type is kept as text.
func textMIME(mt string) bool {
	m := strings.ToLower(strings.TrimSpace(strings.Split(mt, ";")[0]))
	switch {
	case m == "", strings.HasPrefix(m, "text/"):
		return true
	case strings.HasSuffix(m, "+json"), strings.HasSuffix(m, "+xml"):
		return true
	}
	switch m {
	case "application/json", "application/javascript", "application/x-javascript", "application/ecmascript",
		"application/xml", "application/xhtml+xml", "application/x-www-form-urlencoded":
		return true
	}
	return false
}

// RedactBody removes the secrets of a text body of MIME type mt: secret
// JSON fields (when it parses as JSON), secret form fields (urlencoded),
// then JWTs, bearer tokens and password input values anywhere.
func RedactBody(mt, text string) string { return redactBodyWith(mt, text, SecretField) }

func redactBodyWith(mt, text string, secretField func(string) bool) string {
	if text == "" {
		return ""
	}
	m := strings.ToLower(strings.TrimSpace(strings.Split(mt, ";")[0]))
	switch {
	case m == "application/json" || strings.HasSuffix(m, "+json") || looksJSON(text):
		if out, ok := redactJSON(text, secretField); ok {
			return redactText(out)
		}
	case m == "application/x-www-form-urlencoded":
		return redactQueryWith(text, secretField)
	}
	return redactText(text)
}

func looksJSON(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}

// redactJSON replaces the value of every secret field, at any depth.
func redactJSON(text string, secretField func(string) bool) (string, bool) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() {
		return "", false
	}
	changed := false
	v = redactValue(v, secretField, &changed)
	if !changed {
		return text, true
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return "", false
	}
	return strings.TrimSuffix(buf.String(), "\n"), true
}

// redactValue sets *changed when it replaced a value that was not
// already Redacted.
func redactValue(v any, secretField func(string) bool, changed *bool) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretField(k) {
				if s, ok := val.(string); !ok || s != Redacted {
					*changed = true
				}
				x[k] = Redacted
			} else {
				x[k] = redactValue(val, secretField, changed)
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = redactValue(x[i], secretField, changed)
		}
		return x
	default:
		return v
	}
}

var (
	jwtRE    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}`)
	bearerRE = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	// An <input> tag; its type, name and value are read by redactInputs.
	inputRE = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRE  = regexp.MustCompile(`(?is)\b(type|name|id|value)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	// inlineKVRE is a key and a quoted string value in a script or inline
	// JSON: token: "…", "access_token":"…", csrfToken = '…'.
	inlineKVRE = regexp.MustCompile(`(["']?)([A-Za-z_$][A-Za-z0-9_$.-]{1,63})(["']?)(\s*[:=]\s*)("[^"\\\n]{6,}"|'[^'\\\n]{6,}')`)
	// metaRE is a <meta> tag; its name and content are read by redactMeta.
	metaRE     = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	metaAttrRE = regexp.MustCompile(`(?is)\b(name|content)\s*=\s*("[^"]*"|'[^']*')`)
)

// redactText removes JWTs, bearer/basic credentials and secret <input>
// values from free text.
func redactText(s string) string {
	if s == "" {
		return s
	}
	s = jwtRE.ReplaceAllString(s, Redacted)
	s = bearerRE.ReplaceAllString(s, "$1 "+Redacted)
	low := strings.ToLower(s)
	if strings.Contains(low, "<input") {
		s = inputRE.ReplaceAllStringFunc(s, redactInput)
	}
	if strings.Contains(low, "<meta") {
		s = metaRE.ReplaceAllStringFunc(s, redactMeta)
	}
	return inlineKVRE.ReplaceAllStringFunc(s, func(m string) string {
		p := inlineKVRE.FindStringSubmatch(m)
		if !SecretField(p[2]) || p[1] != p[3] {
			return m
		}
		q := p[5][:1]
		return p[1] + p[2] + p[3] + p[4] + q + Redacted + q
	})
}

// redactMeta empties the content of a <meta> whose name is a secret field
// (csrf-token, _csrf…).
func redactMeta(tag string) string {
	secretMeta := false
	for _, m := range metaAttrRE.FindAllStringSubmatch(tag, -1) {
		if strings.EqualFold(m[1], "name") && SecretField(strings.Trim(m[2], `"'`)) {
			secretMeta = true
		}
	}
	if !secretMeta {
		return tag
	}
	return metaAttrRE.ReplaceAllStringFunc(tag, func(a string) string {
		m := metaAttrRE.FindStringSubmatch(a)
		if !strings.EqualFold(m[1], "content") {
			return a
		}
		return m[1] + `="` + Redacted + `"`
	})
}

// redactInput empties the value of a password input or of an input whose
// name or id is a secret field.
func redactInput(tag string) string {
	secretInput := false
	for _, m := range attrRE.FindAllStringSubmatch(tag, -1) {
		val := strings.Trim(m[2], `"'`)
		switch strings.ToLower(m[1]) {
		case "type":
			secretInput = secretInput || strings.EqualFold(val, "password")
		case "name", "id":
			secretInput = secretInput || SecretField(val)
		}
	}
	if !secretInput {
		return tag
	}
	return attrRE.ReplaceAllStringFunc(tag, func(a string) string {
		m := attrRE.FindStringSubmatch(a)
		if !strings.EqualFold(m[1], "value") {
			return a
		}
		return m[1] + `="` + Redacted + `"`
	})
}

// Check returns one finding per place where f still holds a value
// RedactEntry would remove. A file written by `facto record` has none.
// Findings name the entry and the place, never the value.
func Check(f *File) []string {
	var out []string
	for i, e := range f.Log.Entries {
		r := RedactEntry(e)
		a, _ := json.Marshal(e)
		b, _ := json.Marshal(r)
		if !bytes.Equal(a, b) {
			out = append(out, fmt.Sprintf("entry %d (%s %s): unredacted secret in %s",
				i, e.Request.Method, hostOf(e.Request.URL), strings.Join(diffPlaces(e, r), ", ")))
		}
	}
	return out
}

// Stabilize redacts every entry of f again until a further redaction
// changes nothing (Check is then clean), at most rounds times. It reports
// whether that fixed point was reached. Each round only removes values
// (RedactEntry never adds one), so it is always safe to apply: it absorbs
// shapes a first round creates (a scrubbed value inside a URL, a redaction
// that exposes a new key/value match).
func Stabilize(f *File, rounds int) bool {
	for range rounds {
		changed := false
		for i, e := range f.Log.Entries {
			r := RedactEntry(e)
			a, _ := json.Marshal(e)
			b, _ := json.Marshal(r)
			if !bytes.Equal(a, b) {
				f.Log.Entries[i] = r
				changed = true
			}
		}
		if !changed {
			return true
		}
	}
	return len(Check(f)) == 0
}

// diffPlaces names the parts of e that redaction changes (header names,
// never values).
func diffPlaces(e, r Entry) []string {
	var out []string
	if e.Request.URL != r.Request.URL {
		out = append(out, "request url")
	}
	nv := func(where string, a, b []NV) {
		for i := range a {
			if i < len(b) && a[i].Value != b[i].Value {
				out = append(out, where+" "+safeName(a[i].Name))
			}
		}
	}
	nv("request header", e.Request.Headers, r.Request.Headers)
	nv("query", e.Request.QueryString, r.Request.QueryString)
	nv("response header", e.Response.Headers, r.Response.Headers)
	if len(e.Request.Cookies) > 0 && !slices.Equal(e.Request.Cookies, r.Request.Cookies) {
		out = append(out, "request cookies")
	}
	if len(e.Response.Cookies) > 0 && !slices.Equal(e.Response.Cookies, r.Response.Cookies) {
		out = append(out, "response cookies")
	}
	if e.Request.PostData != nil && r.Request.PostData != nil {
		if e.Request.PostData.Text != r.Request.PostData.Text {
			out = append(out, "request body ("+safeName(e.Request.PostData.MimeType)+")")
		}
		nv("form param", e.Request.PostData.Params, r.Request.PostData.Params)
	}
	if e.Response.RedirectURL != r.Response.RedirectURL {
		out = append(out, "redirect url")
	}
	if e.Response.Content != r.Response.Content {
		out = append(out, "response body ("+safeName(e.Response.Content.MimeType)+")")
	}
	if len(out) == 0 {
		out = append(out, "entry")
	}
	return out
}

// safeName keeps a header name or MIME type printable and short.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 0x20 && r < 0x7f && r != '"' {
			b.WriteRune(r)
		}
		if b.Len() >= 48 {
			break
		}
	}
	return b.String()
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "?"
	}
	return u.Host
}
