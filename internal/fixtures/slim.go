package fixtures

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/FlorianRuen/facto/internal/har"
)

// ErrUnredacted reports a HAR that still holds a value har.RedactEntry
// would remove: harslim only reads what `facto record` wrote.
var ErrUnredacted = errors.New("fixtures: the HAR is not redacted (record it with facto record; never feed a raw browser export)")

// SlimOptions configures Slim.
type SlimOptions struct {
	// Hosts are the supplier hosts to keep (exact, lowercase). Empty: the
	// host of the first document request.
	Hosts []string
	// PDFs is how many PDF responses to keep (default 1).
	PDFs int
}

// Step is one kept request of the flow.
type Step struct {
	Method      string   `json:"method"`
	Host        string   `json:"host"`
	Path        string   `json:"path"` // path and query
	Status      int      `json:"status"`
	Type        string   `json:"type,omitempty"`      // resource type
	MimeType    string   `json:"mime_type,omitempty"` // response MIME type
	Body        string   `json:"body,omitempty"`      // file holding the response body
	RequestType string   `json:"request_type,omitempty"`
	RequestBody string   `json:"request_body,omitempty"` // redacted form or JSON
	Location    string   `json:"location,omitempty"`     // redirect target
	Cookies     []string `json:"set_cookies,omitempty"`  // names of the cookies set
}

// Flow is flow.json: the kept requests, in order.
type Flow struct {
	Source string `json:"source"` // HAR creator
	Steps  []Step `json:"steps"`
}

// Slimmed is what Slim returns: flow.json and the body files, by name.
type Slimmed struct {
	Flow  Flow
	Files map[string][]byte
}

// methodGET is http.MethodGet (net/http is denied outside internal/httpx).
const methodGET = "GET"

// skipTypes are resource types a connector never needs.
var skipTypes = []string{"image", "stylesheet", "font", "media", "ping", "manifest", "texttrack", "websocket", "eventsource", "cspviolationreport", "preflight"}

// Slim keeps only what a connector needs from a redacted recording: the
// documents, XHR/fetch calls and PDFs of the supplier hosts that got an
// answer (no static asset, no blocked or failed request, no 404, no other
// host), at most PDFs PDF responses (replaced by a synthetic placeholder:
// run scripts/fakepdf for a realistic one). Body files are named
// NNN-<method>-<path>.<ext> (fsx.SafeName-safe).
func Slim(f *har.File, opts SlimOptions) (*Slimmed, error) {
	if findings := har.Check(f); len(findings) > 0 {
		return nil, fmt.Errorf("%w: %d entries", ErrUnredacted, len(findings))
	}
	if opts.PDFs <= 0 {
		opts.PDFs = 1
	}
	hosts := slices.Clone(opts.Hosts)
	if len(hosts) == 0 {
		for _, e := range f.Log.Entries {
			if e.ResourceType == "document" {
				if u, err := url.Parse(e.Request.URL); err == nil {
					hosts = []string{strings.ToLower(u.Hostname())}
					break
				}
			}
		}
	}
	out := &Slimmed{Flow: Flow{Source: f.Log.Creator.Name + " " + f.Log.Creator.Version}, Files: map[string][]byte{}}
	pdfs := 0
	for _, e := range f.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		switch {
		case !slices.Contains(hosts, host),
			slices.Contains(skipTypes, e.ResourceType),
			e.Response.Status == 0, e.Response.Status == 404,
			e.ResourceType == "script" && e.Request.Method == methodGET:
			continue
		}
		mime := baseMIME(e.Response.Content.MimeType)
		pdf := mime == "application/pdf"
		if pdf {
			if pdfs >= opts.PDFs {
				continue
			}
			pdfs++
		}
		n := len(out.Flow.Steps) + 1
		st := Step{
			Method: e.Request.Method, Host: host, Path: u.EscapedPath(), Status: e.Response.Status,
			Type: e.ResourceType, MimeType: mime, Location: e.Response.RedirectURL,
		}
		if u.RawQuery != "" {
			st.Path += "?" + u.RawQuery
		}
		if pd := e.Request.PostData; pd != nil {
			st.RequestType, st.RequestBody = baseMIME(pd.MimeType), pd.Text
		}
		for _, c := range e.Response.Cookies {
			st.Cookies = append(st.Cookies, c.Name)
		}
		switch {
		case pdf:
			st.Body = bodyName(n, e.Request.Method, u.Path, "pdf")
			out.Files[st.Body] = BuildPDF(PDFSpec{Lines: []string{"Synthetic placeholder", "Replace with go run ./scripts/fakepdf"}})
		case e.Response.Content.Text != "":
			st.Body = bodyName(n, e.Request.Method, u.Path, extFor(mime))
			out.Files[st.Body] = []byte(e.Response.Content.Text)
		}
		out.Flow.Steps = append(out.Flow.Steps, st)
	}
	return out, nil
}

func baseMIME(mt string) string {
	return strings.ToLower(strings.TrimSpace(strings.Split(mt, ";")[0]))
}

func extFor(mime string) string {
	switch {
	case mime == "text/html" || mime == "application/xhtml+xml":
		return "html"
	case strings.Contains(mime, "json"):
		return "json"
	case strings.Contains(mime, "xml"):
		return "xml"
	case strings.Contains(mime, "javascript"):
		return "js"
	default:
		return "txt"
	}
}

var nameRE = regexp.MustCompile(`[^a-z0-9]+`)

// bodyName is NNN-<method>-<path slug>.<ext>, at most 80 bytes.
func bodyName(n int, method, p, ext string) string {
	slug := nameRE.ReplaceAllString(strings.ToLower(path.Clean("/"+p)), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "root"
	}
	if len(slug) > 60 {
		slug = slug[:60]
	}
	return fmt.Sprintf("%03d-%s-%s.%s", n, nameRE.ReplaceAllString(strings.ToLower(method), ""), strings.Trim(slug, "-"), ext)
}
