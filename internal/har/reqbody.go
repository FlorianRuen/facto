package har

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/url"
	"regexp"
	"strings"
)

// Request bodies (SEC-J2-2, SEC-J2-6, SEC-J2-10). A login page may post its
// credentials in any encoding and under any name: jQuery posts JSON as
// x-www-form-urlencoded, RPC APIs nest JSON in strings, OpenAM sends
// {"name":"IDToken2","value":"<password>"}, GraphQL renames variables.
// Field-name rules can never list them all, so a request body keeps its
// structure and loses every value, whatever its name:
//   - JSON (whenever the text is JSON, whatever the declared type): keys,
//     nesting, booleans and nulls are kept; every string and number becomes
//     Redacted. A string that is itself JSON is unwrapped the same way (up to
//     maxNesting); a GraphQL document keeps its text with every literal
//     redacted.
//   - urlencoded pairs: names kept, every non-empty value Redacted.
//   - multipart/form-data (declared, strict split): part names and headers
//     kept, every part body Redacted (file parts: fileNotRecorded).
//   - anything else (prose text/plain, XML, binary, a multipart body that
//     does not split cleanly) is dropped, its MIME type kept and a comment
//     left for the connector author.
// Check compares with RedactEntry, so an unredacted body is flagged. The
// taint (values scrubbed from the whole file) stays name-based: values of
// request fields, of name/value pairs whose name is one, of OpenAM IDToken
// inputs; tainting every request value would also wipe ids the responses
// legitimately repeat.

// droppedBodyComment marks a request body that was not recorded.
const droppedBodyComment = "request body not recorded: not urlencoded, JSON or multipart/form-data"

// fileNotRecorded replaces the content of a multipart file part.
const fileNotRecorded = "[file not recorded]"

// maxNesting bounds how deep JSON-in-a-string is unwrapped; a deeper
// string is redacted whole.
const maxNesting = 6

// argRE is a named argument inside a string: GraphQL `password: "x"`,
// `password: """x"""`, `pin: 1234`, script `email = 'y'`. Used for the
// taint of dropped bodies.
var argRE = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$.\[\]-]{0,63})(\s*[:=]\s*)("""(?s:.*?)"""|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,()\[\]{}"'=&\\]+)`)

// gqlLiteralRE is a GraphQL string literal (block or quoted, escapes
// included) or a number literal not glued to a name.
var gqlLiteralRE = regexp.MustCompile(`"""(?s:.*?)"""|"(?:[^"\\\n]|\\.)*"|(?:^|[^A-Za-z0-9_$.])-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`)

// gqlDocRE is the start of a GraphQL document.
var gqlDocRE = regexp.MustCompile(`^\s*(?:query|mutation|subscription|fragment)\b|^\s*\{`)

// idTokenRE is an OpenAM callback input name (IDToken1, IDToken2…).
var idTokenRE = regexp.MustCompile(`(?i)^IDToken[0-9]+$`)

// multipartValueRE is a loose multipart part: a form-data name, then (past
// any header lines and a blank line, CRLF or LF) the value's first line.
// Used for tainting only, on bodies the strict splitter refuses.
var multipartValueRE = regexp.MustCompile(`(?i)form-data;[^\n]*?\bname="([^"]{1,64})"[^\n]*\n(?:[^\n]*\S[^\n]*\n)*?\r?\n([^\n]*)`)

// pairNameRE is a plausible urlencoded field name (escaped form).
var pairNameRE = regexp.MustCompile(`^[A-Za-z0-9_.\[\]%~+-]{1,128}$`)

// paramNameRE is a plausible decoded field name (postData.params).
var paramNameRE = regexp.MustCompile(`^[A-Za-z0-9_.\[\]~:-]{1,128}$`)

// reqRedactor redacts one request body.
type reqRedactor struct {
	seen func(string) // taint: values under a credential-like name; may be nil
}

func (r *reqRedactor) taint(v string) {
	if r.seen != nil {
		r.seen(v)
	}
}

// credentialName reports a name whose value is tainted file-wide.
func credentialName(name string) bool { return requestField(name) || idTokenRE.MatchString(name) }

// redactRequestBody redacts a request body. ok is false when the body
// must be dropped.
func redactRequestBody(mt, text string) (string, bool) {
	return redactRequestBodyWith(mt, text, nil)
}

func redactRequestBodyWith(mt, text string, seen func(string)) (string, bool) {
	if text == "" {
		return "", true
	}
	r := &reqRedactor{seen: seen}
	m, params, _ := mime.ParseMediaType(mt)
	switch {
	case strings.EqualFold(m, "multipart/form-data"):
		return r.multipart(text, params["boundary"])
	case looksJSON(text):
		return r.json(text, 0)
	case urlencodedShape(text):
		return r.pairs(text), true
	}
	return "", false
}

// json keeps the structure of a JSON text and redacts every value.
func (r *reqRedactor) json(text string, depth int) (string, bool) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() {
		return "", false
	}
	v = r.value(v, "", depth)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return "", false
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	if out == strings.TrimSpace(text) {
		return text, true // already redacted: keep the bytes as they are
	}
	return out, true
}

// value redacts one JSON value found under key.
func (r *reqRedactor) value(v any, key string, depth int) any {
	switch x := v.(type) {
	case map[string]any:
		// A name/value pair ({"name":"password","value":…}, OpenAM
		// callbacks): its value is a credential when its name is one.
		if name, ok := x["name"].(string); ok && credentialName(name) {
			r.taintValue(x["value"])
		}
		for k, val := range x {
			if credentialName(k) {
				r.taintValue(val)
			}
			x[k] = r.value(val, k, depth)
		}
		return x
	case []any:
		for i := range x {
			x[i] = r.value(x[i], key, depth)
		}
		return x
	case json.Number:
		return Redacted
	case string:
		return r.str(x, key, depth)
	}
	return v // bool, null
}

func (r *reqRedactor) taintValue(v any) {
	switch s := v.(type) {
	case string:
		r.taint(s)
	case json.Number:
		r.taint(s.String())
	}
}

// str redacts a JSON string value: nested JSON keeps its structure, a
// GraphQL document keeps its text without literals, anything else is
// Redacted.
func (r *reqRedactor) str(s, key string, depth int) string {
	if s == Redacted || s == "" {
		return s
	}
	if depth < maxNesting && looksJSON(s) {
		if out, ok := r.json(s, depth+1); ok {
			return out
		}
	}
	if strings.EqualFold(key, "query") || gqlDocRE.MatchString(s) {
		if out, ok := r.graphQL(s); ok {
			return out
		}
	}
	return Redacted
}

// graphQL redacts every string and number literal of a GraphQL document.
// ok is false when a quote is left over (an unbalanced or unknown literal
// form): the caller then redacts the whole string.
func (r *reqRedactor) graphQL(doc string) (string, bool) {
	r.taintArgs(doc)
	out := gqlLiteralRE.ReplaceAllStringFunc(doc, func(m string) string {
		switch {
		case strings.HasPrefix(m, `"""`):
			return `"""` + Redacted + `"""`
		case strings.HasPrefix(m, `"`):
			return `"` + Redacted + `"`
		}
		// A number, with the one character before it kept.
		i := strings.IndexAny(m, "-0123456789")
		return m[:i] + Redacted
	})
	rest := strings.NewReplacer(`"""`+Redacted+`"""`, "", `"`+Redacted+`"`, "").Replace(out)
	if strings.ContainsAny(rest, "\"'`\\") {
		return "", false
	}
	return out, true
}

// urlencodedShape reports text made only of name=value pairs joined by
// "&" (at least one "=", no whitespace, no unescaped "=" in a value but
// trailing padding).
func urlencodedShape(text string) bool {
	if !strings.Contains(text, "=") || strings.ContainsAny(text, " \t\r\n") {
		return false
	}
	for part := range strings.SplitSeq(text, "&") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || !pairNameRE.MatchString(k) || strings.Contains(strings.TrimRight(v, "="), "=") {
			return false
		}
	}
	return true
}

// pairs keeps the names of urlencoded pairs and redacts every non-empty
// value.
func (r *reqRedactor) pairs(q string) string {
	parts := strings.Split(q, "&")
	for i, p := range parts {
		k, v, _ := strings.Cut(p, "=")
		if v == "" {
			continue
		}
		name, err := url.QueryUnescape(k)
		if err != nil {
			name = k
		}
		if credentialName(name) {
			if val, err := url.QueryUnescape(v); err == nil {
				r.taint(val)
			}
			r.taint(v)
		}
		parts[i] = k + "=" + url.QueryEscape(Redacted)
	}
	return strings.Join(parts, "&")
}

// multipartPart is one part of a multipart body, as written.
type multipartPart struct {
	head, body string
	name       string
	file       bool
}

// splitMultipart splits text on boundary into its parts, keeping each
// part's raw header block. ok is false when text is not exactly
// "--b\r\n<part>\r\n--b\r\n…--b--" (an optional trailing CRLF).
func splitMultipart(text, boundary string) ([]multipartPart, bool) {
	if boundary == "" || len(boundary) > 70 {
		return nil, false
	}
	delim := "--" + boundary
	body, ok := strings.CutSuffix(strings.TrimSuffix(text, "\r\n"), "\r\n"+delim+"--")
	if !ok {
		return nil, false
	}
	body, ok = strings.CutPrefix(body, delim+"\r\n")
	if !ok {
		return nil, false
	}
	var parts []multipartPart
	for raw := range strings.SplitSeq(body, "\r\n"+delim+"\r\n") {
		head, content, ok := strings.Cut(raw, "\r\n\r\n")
		if !ok {
			return nil, false
		}
		// A delimiter left inside a part (padded "--b ", LF-only "\n--b")
		// is one a lenient server may split on: fail closed.
		if strings.Contains(raw, delim) {
			return nil, false
		}
		p := multipartPart{head: head, body: content}
		dispositions := 0
		for line := range strings.SplitSeq(head, "\r\n") {
			k, v, _ := strings.Cut(line, ":")
			if !strings.EqualFold(strings.TrimSpace(k), "Content-Disposition") {
				continue
			}
			// Two dispositions: servers keep the first, a last-wins reader
			// would mis-name the part. Fail closed.
			if dispositions++; dispositions > 1 {
				return nil, false
			}
			disp, dp, err := mime.ParseMediaType(strings.TrimSpace(v))
			if err != nil || disp != "form-data" {
				return nil, false
			}
			p.name = dp["name"]
			_, p.file = dp["filename"]
		}
		if p.name == "" {
			return nil, false
		}
		parts = append(parts, p)
	}
	return parts, true
}

// multipart keeps part names and headers and redacts every part body.
// Anything that does not split cleanly is dropped.
func (r *reqRedactor) multipart(text, boundary string) (string, bool) {
	parts, ok := splitMultipart(text, boundary)
	if !ok {
		return "", false
	}
	delim := "--" + boundary
	var b strings.Builder
	for _, p := range parts {
		switch {
		case p.file:
			p.body = fileNotRecorded
		case p.body == "" || p.body == Redacted:
		default:
			if credentialName(p.name) {
				r.taint(p.body)
			} else if looksJSON(p.body) {
				// Tainting only (GraphQL operations, JSON parts): the
				// part body is redacted whole below.
				_, _ = (&reqRedactor{seen: r.seen}).json(p.body, 1)
			}
			p.body = Redacted
		}
		b.WriteString(delim + "\r\n" + p.head + "\r\n\r\n" + p.body + "\r\n")
	}
	b.WriteString(delim + "--\r\n")
	return b.String(), true
}

// taintArgs taints the values of named credential arguments in s.
func (r *reqRedactor) taintArgs(s string) {
	for _, p := range argRE.FindAllStringSubmatch(s, -1) {
		if !credentialName(p[1]) {
			continue
		}
		v := p[3]
		switch {
		case strings.HasPrefix(v, "$"):
		case strings.HasPrefix(v, `"""`):
			r.taint(strings.TrimSuffix(strings.TrimPrefix(v, `"""`), `"""`))
		case strings.HasPrefix(v, `"`) || strings.HasPrefix(v, "'"):
			r.taint(v[1 : len(v)-1])
		default:
			r.taint(v)
		}
	}
}

// collectRequestBody taints the credential-like values of a request body
// (the same walk as the redaction), and, for a body that is dropped, what
// still looks like one (multipart parts, urlencoded pairs, named
// arguments).
func (t *Taint) collectRequestBody(mt, text string) {
	if text == "" {
		return
	}
	if _, ok := redactRequestBodyWith(mt, text, t.add); ok {
		return
	}
	for _, m := range multipartValueRE.FindAllStringSubmatch(text, -1) {
		if credentialName(m[1]) {
			t.add(strings.TrimRight(m[2], "\r"))
		}
	}
	t.collectPairs(text, requestField)
	(&reqRedactor{seen: t.add}).taintArgs(text)
}

// redactParams keeps the name of each postData param that looks like a
// field name (others become Redacted: a JSON body posted as urlencoded
// would put the whole JSON in a name) and redacts every non-empty value.
func redactParams(nv []NV) []NV {
	if nv == nil {
		return nil
	}
	out := make([]NV, len(nv))
	for i, p := range nv {
		out[i] = p
		if !paramNameRE.MatchString(p.Name) {
			out[i].Name = Redacted
		}
		if p.Value != "" {
			out[i].Value = Redacted
		}
	}
	return out
}
