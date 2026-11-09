package har

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/url"
	"regexp"
	"strings"
)

// Request bodies (SEC-J2-2, SEC-J2-6). A login page may post its
// credentials in any encoding, and the declared content type is not to be
// trusted: jQuery posts JSON as x-www-form-urlencoded, RPC APIs nest JSON
// inside JSON strings or urlencoded values, GraphQL carries arguments in a
// query string. So a request body is redacted by what it is, recursively:
// multipart/form-data when declared (the boundary is needed), otherwise
// JSON or urlencoded pairs when the text is one of them, and every nested
// string value unwrapped the same way, then named arguments and the
// free-text rules. Anything else (text/plain prose, XML, binary, a
// multipart body that does not split cleanly, nesting past maxNesting) is
// dropped, its MIME type kept and a comment left for the connector author.
// The taint collects exactly what this redaction removes (one code path),
// and Check compares with RedactEntry, so an unredacted body is flagged.

// droppedBodyComment marks a request body that was not recorded.
const droppedBodyComment = "request body not recorded: not urlencoded, JSON or multipart/form-data"

// fileNotRecorded replaces the content of a multipart file part.
const fileNotRecorded = "[file not recorded]"

// maxNesting bounds how deep encodings are unwrapped (JSON in a string in
// a urlencoded value in a multipart part…). A body nested deeper is
// dropped.
const maxNesting = 6

// argRE is a named argument inside a string: GraphQL `password: "x"`,
// `password: """x"""`, `pin: 1234`, script `email = 'y'`. No minimum
// length: a request body field is a credential however short.
var argRE = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$.\[\]-]{0,63})(\s*[:=]\s*)("""(?s:.*?)"""|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,()\[\]{}"'=&\\]+)`)

// multipartValueRE is a loose multipart part: a form-data name, then (past
// any header lines and a blank line, CRLF or LF) the value's first line.
// Used for tainting only, on bodies the strict splitter refuses.
var multipartValueRE = regexp.MustCompile(`(?i)form-data;[^\n]*?\bname="([^"]{1,64})"[^\n]*\n(?:[^\n]*\S[^\n]*\n)*?\r?\n([^\n]*)`)

// pairNameRE is a plausible urlencoded field name (escaped form).
var pairNameRE = regexp.MustCompile(`^[A-Za-z0-9_.\[\]%~+-]{1,128}$`)

// reqRedactor redacts one request body.
type reqRedactor struct {
	seen    func(string) // called with every value removed (taint); may be nil
	tooDeep bool
}

func (r *reqRedactor) remove(v string) {
	if r.seen != nil {
		r.seen(v)
	}
}

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
	var out string
	switch {
	case strings.EqualFold(m, "multipart/form-data"):
		var ok bool
		if out, ok = r.multipart(text, params["boundary"]); !ok {
			return "", false
		}
	case looksJSON(text):
		var ok bool
		if out, ok = r.json(text, 0); !ok {
			return "", false
		}
		// String values were unwrapped by deep; the encoded text only
		// gets the free-text rules (named arguments would misread \").
		out = redactText(out)
	case urlencodedShape(text):
		out = r.deep(text, 0)
	default:
		return "", false
	}
	if r.tooDeep {
		return "", false
	}
	return out, true
}

// deep redacts one string value: as JSON when it parses as JSON, as
// urlencoded pairs when it has that shape, otherwise its named arguments;
// then the free-text rules (JWTs, bearer credentials).
func (r *reqRedactor) deep(s string, depth int) string {
	if depth > maxNesting {
		r.tooDeep = true
		return s
	}
	switch {
	case looksJSON(s):
		if out, ok := r.json(s, depth); ok {
			return redactText(out)
		}
	case urlencodedShape(s):
		// Fields handled pair by pair; named arguments would re-match
		// "name=%5Bredacted%5D".
		return redactText(r.pairs(s, depth))
	}
	return redactText(r.args(s))
}

// json redacts request fields at any depth of a JSON text; every other
// string value goes through deep.
func (r *reqRedactor) json(text string, depth int) (string, bool) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() {
		return "", false
	}
	changed := false
	v = r.value(v, depth, &changed)
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

func (r *reqRedactor) value(v any, depth int, changed *bool) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if requestField(k) {
				switch s := val.(type) {
				case string:
					r.remove(s)
				case json.Number:
					r.remove(s.String())
				}
				if s, ok := val.(string); !ok || s != Redacted {
					*changed = true
				}
				x[k] = Redacted
				continue
			}
			x[k] = r.value(val, depth, changed)
		}
		return x
	case []any:
		for i := range x {
			x[i] = r.value(x[i], depth, changed)
		}
		return x
	case string:
		if out := r.deep(x, depth+1); out != x {
			*changed = true
			return out
		}
	}
	return v
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
		// An encoder escapes "=" in values; only base64 padding may stay.
		if !ok || !pairNameRE.MatchString(k) || strings.Contains(strings.TrimRight(v, "="), "=") {
			return false
		}
	}
	return true
}

// pairs redacts urlencoded pairs: a request field's value is replaced,
// every other value goes through deep (decoded, re-encoded when changed).
func (r *reqRedactor) pairs(q string, depth int) string {
	parts := strings.Split(q, "&")
	for i, p := range parts {
		k, v, _ := strings.Cut(p, "=")
		name, err := url.QueryUnescape(k)
		if err != nil {
			name = k
		}
		val, err := url.QueryUnescape(v)
		if err != nil {
			val = v
		}
		if requestField(name) {
			r.remove(val)
			r.remove(v)
			parts[i] = k + "=" + url.QueryEscape(Redacted)
			continue
		}
		if out := r.deep(val, depth+1); out != val {
			parts[i] = k + "=" + url.QueryEscape(out)
		}
	}
	return strings.Join(parts, "&")
}

// args replaces the value of every named argument of s whose name is a
// request field. A GraphQL variable reference ($p) is not a value.
func (r *reqRedactor) args(s string) string {
	return argRE.ReplaceAllStringFunc(s, func(m string) string {
		p := argRE.FindStringSubmatch(m)
		v := p[3]
		if !requestField(p[1]) || strings.HasPrefix(v, "$") || strings.Contains(v, Redacted) {
			return m
		}
		switch {
		case strings.HasPrefix(v, `"""`):
			r.remove(strings.TrimSuffix(strings.TrimPrefix(v, `"""`), `"""`))
			return p[1] + p[2] + `"""` + Redacted + `"""`
		case strings.HasPrefix(v, `"`) || strings.HasPrefix(v, "'"):
			r.remove(v[1 : len(v)-1])
			return p[1] + p[2] + v[:1] + Redacted + v[:1]
		}
		r.remove(v)
		return p[1] + p[2] + Redacted
	})
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

// multipart redacts a multipart/form-data body part by part: a request
// field's value and any file content are replaced, every other value goes
// through deep. Anything that does not split cleanly is dropped.
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
		case requestField(p.name):
			r.remove(p.body)
			p.body = Redacted
		default:
			p.body = r.deep(p.body, 1)
		}
		b.WriteString(delim + "\r\n" + p.head + "\r\n\r\n" + p.body + "\r\n")
	}
	b.WriteString(delim + "--\r\n")
	return b.String(), true
}

// collectRequestBody taints every value the request body redaction
// removes (one code path: what is redacted is what is tainted). For a body
// that is dropped, it still taints what looks like a request field's
// value (multipart parts, urlencoded pairs, named arguments).
func (t *Taint) collectRequestBody(mt, text string) {
	if text == "" {
		return
	}
	if _, ok := redactRequestBodyWith(mt, text, t.add); ok {
		return
	}
	for _, m := range multipartValueRE.FindAllStringSubmatch(text, -1) {
		if requestField(m[1]) {
			t.add(strings.TrimRight(m[2], "\r"))
		}
	}
	t.collectPairs(text, requestField)
	(&reqRedactor{seen: t.add}).args(text)
}
