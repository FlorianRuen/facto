package har

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

// Taint is the set of values seen in a secret position while recording:
// cookie values, Authorization and other secret header values, secret and
// login request fields (query, form, JSON). Field-name rules cannot see a
// password a login page inlines in a script, or a bearer token an SPA
// embeds in its HTML; Scrub removes every tainted value from every string
// of the file, wherever it shows up. A Taint lives in memory only and is
// never written.
type Taint struct {
	values map[string]struct{}
}

// MinTaintLen is the shortest value tainted: shorter ones ("1", "en",
// "true") are too common to scrub without wiping harmless text.
const MinTaintLen = 6

// NewTaint returns an empty set.
func NewTaint() *Taint { return &Taint{values: map[string]struct{}{}} }

// Len is the number of tainted values.
func (t *Taint) Len() int { return len(t.values) }

// add taints v and its URL-encoded forms.
func (t *Taint) add(v string) {
	v = strings.TrimSpace(v)
	if len(v) < MinTaintLen || v == Redacted {
		return
	}
	switch strings.ToLower(v) {
	case "true", "false", "null", "undefined":
		return
	}
	for _, form := range []string{v, url.QueryEscape(v), url.PathEscape(v)} {
		t.values[form] = struct{}{}
	}
	if b, err := json.Marshal(v); err == nil {
		// JSON-escaped form without the quotes ("/" stays, "<" becomes <).
		t.values[strings.Trim(string(b), `"`)] = struct{}{}
	}
}

// Collect taints the secret values of an unredacted entry.
func (t *Taint) Collect(e Entry) {
	for _, h := range slices.Concat(e.Request.Headers, e.Response.Headers) {
		if !SecretHeader(h.Name) {
			continue
		}
		t.add(h.Value)
		t.addCredential(h.Value)
		switch strings.ToLower(h.Name) {
		case "cookie":
			for part := range strings.SplitSeq(h.Value, ";") {
				_, v, _ := strings.Cut(strings.TrimSpace(part), "=")
				t.add(v)
			}
		case "set-cookie", "set-cookie2":
			first, _, _ := strings.Cut(h.Value, ";")
			_, v, _ := strings.Cut(strings.TrimSpace(first), "=")
			t.add(v)
		}
	}
	for _, c := range slices.Concat(e.Request.Cookies, e.Response.Cookies) {
		t.add(c.Value)
	}
	for _, p := range e.Request.QueryString {
		if SecretField(p.Name) {
			t.add(p.Value)
		}
	}
	if u, err := url.Parse(e.Request.URL); err == nil {
		t.collectPairs(u.RawQuery, SecretField)
		if u.User != nil {
			t.add(u.User.Username())
			if pw, ok := u.User.Password(); ok {
				t.add(pw)
			}
		}
	}
	if pd := e.Request.PostData; pd != nil {
		for _, p := range pd.Params {
			if requestField(p.Name) {
				t.add(p.Value)
			}
		}
		t.collectBody(pd.MimeType, pd.Text, requestField)
	}
	t.collectBody(e.Response.Content.MimeType, e.Response.Content.Text, SecretField)
	t.collectInline(e.Response.Content.Text)
}

// collectInline taints the values redactText removes from free text:
// secret keys of inline scripts and secret <meta> contents.
func (t *Taint) collectInline(text string) {
	if text == "" {
		return
	}
	for _, p := range inlineKVRE.FindAllStringSubmatch(text, -1) {
		if SecretField(p[2]) && p[1] == p[3] {
			t.add(p[5][1 : len(p[5])-1])
		}
	}
	for _, tag := range metaRE.FindAllString(text, -1) {
		secretMeta, content := false, ""
		for _, m := range metaAttrRE.FindAllStringSubmatch(tag, -1) {
			v := strings.Trim(m[2], `"'`)
			switch strings.ToLower(m[1]) {
			case "name":
				secretMeta = secretMeta || SecretField(v)
			case "content":
				content = v
			}
		}
		if secretMeta {
			t.add(content)
		}
	}
}

// addCredential taints the credential of "Bearer <x>" / "Basic <x>" values.
func (t *Taint) addCredential(v string) {
	scheme, cred, ok := strings.Cut(strings.TrimSpace(v), " ")
	if ok && (strings.EqualFold(scheme, "bearer") || strings.EqualFold(scheme, "basic")) {
		t.add(cred)
	}
}

// collectPairs taints the values of the secret fields of a urlencoded
// string.
func (t *Taint) collectPairs(q string, secretField func(string) bool) {
	for part := range strings.SplitSeq(q, "&") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name, err := url.QueryUnescape(k)
		if err != nil {
			name = k
		}
		if !secretField(name) {
			continue
		}
		if val, err := url.QueryUnescape(v); err == nil {
			t.add(val)
		}
		t.add(v)
	}
}

func (t *Taint) collectBody(mt, text string, secretField func(string) bool) {
	if text == "" {
		return
	}
	m := strings.ToLower(strings.TrimSpace(strings.Split(mt, ";")[0]))
	if m == "application/x-www-form-urlencoded" {
		t.collectPairs(text, secretField)
		return
	}
	if m != "application/json" && !strings.HasSuffix(m, "+json") && !looksJSON(text) {
		return
	}
	var v any
	if json.Unmarshal([]byte(text), &v) != nil {
		return
	}
	t.collectJSON(v, secretField)
}

func (t *Taint) collectJSON(v any, secretField func(string) bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && secretField(k) {
				t.add(s)
				continue
			}
			t.collectJSON(val, secretField)
		}
	case []any:
		for _, val := range x {
			t.collectJSON(val, secretField)
		}
	}
}

// Scrub replaces every tainted value in every string of f with Redacted,
// longest values first.
func (t *Taint) Scrub(f *File) {
	if len(t.values) == 0 {
		return
	}
	vals := make([]string, 0, len(t.values))
	for v := range t.values {
		vals = append(vals, v)
	}
	slices.SortFunc(vals, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	pairs := make([]string, 0, 2*len(vals))
	for _, v := range vals {
		pairs = append(pairs, v, Redacted)
	}
	r := strings.NewReplacer(pairs...)
	s := func(p *string) { *p = r.Replace(*p) }
	nv := func(l []NV) {
		for i := range l {
			s(&l[i].Name)
			s(&l[i].Value)
		}
	}
	for i := range f.Log.Entries {
		e := &f.Log.Entries[i]
		s(&e.Comment)
		s(&e.Request.URL)
		nv(e.Request.Headers)
		nv(e.Request.QueryString)
		for j := range e.Request.Cookies {
			s(&e.Request.Cookies[j].Value)
		}
		if e.Request.PostData != nil {
			s(&e.Request.PostData.Text)
			nv(e.Request.PostData.Params)
		}
		nv(e.Response.Headers)
		for j := range e.Response.Cookies {
			s(&e.Response.Cookies[j].Value)
		}
		s(&e.Response.RedirectURL)
		s(&e.Response.Content.Text)
		s(&e.Response.Content.Comment)
	}
	for i := range f.Log.Pages {
		s(&f.Log.Pages[i].Title)
	}
}
