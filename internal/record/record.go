// Package record turns the Network events of the login page
// (browser.NetworkTap) into a HAR file for `facto record` (docs/spec.md
// "facto record"). Every entry goes through har.RedactEntry as soon as it
// is complete, after its secret values were added to a har.Taint; Run
// then scrubs every tainted value from the whole file (bodies of other
// entries included). The recorder keeps no unredacted entry once it is
// done, writes nothing itself, and never logs a URL, header or body.
package record

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/har"
)

// Defaults of Options.
const (
	DefaultMaxEntries = 5000
	// DefaultMaxBodyTotal bounds the text bodies one recording keeps in
	// memory (SEC-J2-5): each is cut at har.MaxBodyBytes, and 5000 of
	// them could otherwise reach 10 GiB.
	DefaultMaxBodyTotal = 256 << 20
	bodyTimeout         = 10 * time.Second
	// stabilizeRounds bounds the extra redaction rounds of Run.
	stabilizeRounds = 3
)

// Source is what the recorder reads: *browser.NetworkTap satisfies it.
type Source interface {
	Events() <-chan browser.Event
	Body(ctx context.Context, requestID string) (string, bool, error)
	Dropped() int64
}

var _ Source = (*browser.NetworkTap)(nil)

// Options configures a Recorder.
type Options struct {
	Clock      clock.Clock
	Creator    string // HAR creator name; "facto" when empty
	Version    string // HAR creator version
	MaxEntries int    // DefaultMaxEntries when <= 0
	// MaxBodyTotal bounds the bytes of text bodies kept, in all;
	// DefaultMaxBodyTotal when <= 0. Later bodies are not kept (a comment
	// says so); their entries still are.
	MaxBodyTotal int
}

// Recorder builds one HAR file. It is used by one goroutine (Run).
type Recorder struct {
	opts    Options
	pending map[string]*pendingEntry
	order   []string // request ids in arrival order (pending ones)
	file    *har.File
	dropped int
	taint   *har.Taint // secret values seen; in memory only
	// bodyBytes counts the text body bytes kept (MaxBodyTotal).
	bodyBytes int
}

// pendingEntry is a request not finished yet. Its headers may hold secrets
// until finish redacts the entry.
type pendingEntry struct {
	entry        har.Entry
	reqExtra     map[string]string
	respExtra    map[string]string
	hasResponse  bool
	encodedBytes int
}

// New returns a recorder.
func New(opts Options) *Recorder {
	if opts.Clock == nil {
		opts.Clock = clock.Real{}
	}
	if opts.Creator == "" {
		opts.Creator = "facto"
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultMaxEntries
	}
	if opts.MaxBodyTotal <= 0 {
		opts.MaxBodyTotal = DefaultMaxBodyTotal
	}
	return &Recorder{opts: opts, pending: map[string]*pendingEntry{}, file: har.New(opts.Creator, opts.Version), taint: har.NewTaint()}
}

// Run consumes src until its channel closes or ctx ends, then returns the
// redacted file: requests still in flight are kept with a comment.
func (r *Recorder) Run(ctx context.Context, src Source) *har.File {
	events := src.Events()
loop:
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				break loop
			}
			r.handle(ctx, src, ev)
		case <-ctx.Done():
			break loop
		}
	}
	for _, id := range slices.Clone(r.order) {
		p := r.pending[id]
		p.entry.Comment = "unfinished: the recording stopped before the response ended"
		r.finish(id)
	}
	var notes []string
	if r.dropped > 0 {
		notes = append(notes, strconv.Itoa(r.dropped)+" entries dropped over the cap")
	}
	if n := src.Dropped(); n > 0 {
		notes = append(notes, strconv.FormatInt(n, 10)+" browser events dropped (queue full)")
	}
	r.file.Log.Comment = strings.Join(notes, "; ")
	// Values seen in a secret position leave every other place too (a
	// login page that inlines the password, an SPA that inlines its token).
	r.taint.Scrub(r.file)
	r.taint = har.NewTaint()
	// Redact again until a further redaction changes nothing: facto record
	// refuses to write a file har.Check flags (fail closed), and real pages
	// can need more than one round (J2, Wecasa).
	har.Stabilize(r.file, stabilizeRounds)
	return r.file
}

// Wire shapes of the Network events read.
type (
	cdpRequest struct {
		URL         string            `json:"url"`
		Method      string            `json:"method"`
		Headers     map[string]string `json:"headers"`
		PostData    string            `json:"postData"`
		HasPostData bool              `json:"hasPostData"`
	}
	cdpResponse struct {
		URL        string            `json:"url"`
		Status     int               `json:"status"`
		StatusText string            `json:"statusText"`
		Headers    map[string]string `json:"headers"`
		MimeType   string            `json:"mimeType"`
		Protocol   string            `json:"protocol"`
	}
	willBeSent struct {
		RequestID        string       `json:"requestId"`
		Type             string       `json:"type"`
		WallTime         float64      `json:"wallTime"`
		Request          cdpRequest   `json:"request"`
		RedirectResponse *cdpResponse `json:"redirectResponse"`
	}
	extraInfo struct {
		RequestID string            `json:"requestId"`
		Headers   map[string]string `json:"headers"`
	}
	received struct {
		RequestID string      `json:"requestId"`
		Response  cdpResponse `json:"response"`
	}
	finished struct {
		RequestID         string  `json:"requestId"`
		EncodedDataLength float64 `json:"encodedDataLength"`
		ErrorText         string  `json:"errorText"`
		BlockedReason     string  `json:"blockedReason"`
	}
)

func (r *Recorder) handle(ctx context.Context, src Source, ev browser.Event) {
	switch ev.Method {
	case "Network.requestWillBeSent":
		var w willBeSent
		if json.Unmarshal(ev.Params, &w) != nil || w.RequestID == "" {
			return
		}
		if w.RedirectResponse != nil {
			if p, ok := r.pending[w.RequestID]; ok {
				r.setResponse(p, *w.RedirectResponse)
				p.entry.Response.RedirectURL = w.RedirectResponse.Headers[headerKey(w.RedirectResponse.Headers, "location")]
				r.finish(w.RequestID)
			}
		}
		r.start(w)
	case "Network.requestWillBeSentExtraInfo":
		var x extraInfo
		if json.Unmarshal(ev.Params, &x) == nil {
			if p, ok := r.pending[x.RequestID]; ok {
				p.reqExtra = x.Headers
			}
		}
	case "Network.responseReceivedExtraInfo":
		var x extraInfo
		if json.Unmarshal(ev.Params, &x) == nil {
			if p, ok := r.pending[x.RequestID]; ok {
				p.respExtra = x.Headers
			}
		}
	case "Network.responseReceived":
		var x received
		if json.Unmarshal(ev.Params, &x) == nil {
			if p, ok := r.pending[x.RequestID]; ok {
				r.setResponse(p, x.Response)
			}
		}
	case "Network.loadingFinished":
		var x finished
		if json.Unmarshal(ev.Params, &x) != nil {
			return
		}
		p, ok := r.pending[x.RequestID]
		if !ok {
			return
		}
		p.encodedBytes = int(x.EncodedDataLength)
		r.readBody(ctx, src, x.RequestID, p)
		r.finish(x.RequestID)
	case "Network.loadingFailed":
		var x finished
		if json.Unmarshal(ev.Params, &x) != nil {
			return
		}
		if p, ok := r.pending[x.RequestID]; ok {
			p.entry.Comment = "failed: " + sanitizeNote(x.ErrorText)
			if x.BlockedReason != "" {
				p.entry.Comment += " (" + sanitizeNote(x.BlockedReason) + ")"
			}
			r.finish(x.RequestID)
		}
	}
}

func (r *Recorder) start(w willBeSent) {
	if _, dup := r.pending[w.RequestID]; dup {
		r.finish(w.RequestID)
	}
	if len(r.file.Log.Entries)+len(r.pending) >= r.opts.MaxEntries {
		r.dropped++
		return
	}
	started := r.opts.Clock.Now().UTC()
	if w.WallTime > 0 {
		sec := int64(w.WallTime)
		started = time.Unix(sec, int64((w.WallTime-float64(sec))*1e9)).UTC()
	}
	e := har.Entry{
		StartedDateTime: started.Format(time.RFC3339Nano),
		Time:            -1,
		ResourceType:    strings.ToLower(w.Type),
		Timings:         har.Timings{Send: -1, Wait: -1, Receive: -1},
		Request: har.Request{
			Method:      w.Request.Method,
			URL:         w.Request.URL,
			HTTPVersion: "HTTP/1.1",
			Headers:     headerList(w.Request.Headers),
			QueryString: queryList(w.Request.URL),
			Cookies:     []har.Cookie{},
			HeadersSize: -1,
			BodySize:    len(w.Request.PostData),
		},
		Response: har.Response{Headers: []har.NV{}, Cookies: []har.Cookie{}, HeadersSize: -1, BodySize: -1},
	}
	if w.Request.HasPostData || w.Request.PostData != "" {
		mt := w.Request.Headers[headerKey(w.Request.Headers, "content-type")]
		e.Request.PostData = &har.PostData{MimeType: mt, Text: w.Request.PostData, Params: formParams(mt, w.Request.PostData)}
		if w.Request.PostData == "" {
			e.Request.PostData.Text = ""
			e.Comment = "request body not available from the browser"
		}
	}
	r.pending[w.RequestID] = &pendingEntry{entry: e}
	r.order = append(r.order, w.RequestID)
}

func (r *Recorder) setResponse(p *pendingEntry, resp cdpResponse) {
	p.hasResponse = true
	p.entry.Response.Status = resp.Status
	p.entry.Response.StatusText = resp.StatusText
	p.entry.Response.HTTPVersion = httpVersion(resp.Protocol)
	p.entry.Request.HTTPVersion = p.entry.Response.HTTPVersion
	p.entry.Response.Headers = headerList(resp.Headers)
	p.entry.Response.Content.MimeType = resp.MimeType
}

// readBody fetches a text body. Binary bodies are never fetched: only their
// size is kept (har.RedactContent drops them anyway).
func (r *Recorder) readBody(ctx context.Context, src Source, id string, p *pendingEntry) {
	c := &p.entry.Response.Content
	c.Size = p.encodedBytes
	if !p.hasResponse || p.entry.Response.Status == 204 || (p.entry.Response.Status >= 300 && p.entry.Response.Status < 400) {
		return
	}
	if !textual(c.MimeType) {
		c.Comment = "binary body not recorded"
		return
	}
	bctx, cancel := context.WithTimeout(ctx, bodyTimeout)
	defer cancel()
	body, b64, err := src.Body(bctx, id)
	if err != nil {
		c.Comment = "body not available from the browser"
		return
	}
	if b64 {
		raw, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			c.Comment = "body not available from the browser"
			return
		}
		body = string(raw)
	}
	c.Size = len(body)
	kept := min(len(body), har.MaxBodyBytes)
	if r.bodyBytes+kept > r.opts.MaxBodyTotal {
		c.Comment = "body not recorded: recording size cap reached"
		return
	}
	r.bodyBytes += kept
	c.Text = body // har.RedactContent cuts it at MaxBodyBytes, with a comment
}

// finish merges the extra-info headers, builds the cookie lists, redacts
// the entry and appends it; the unredacted copy is dropped.
func (r *Recorder) finish(id string) {
	p, ok := r.pending[id]
	if !ok {
		return
	}
	delete(r.pending, id)
	r.order = slices.DeleteFunc(r.order, func(s string) bool { return s == id })
	e := p.entry
	if p.reqExtra != nil {
		e.Request.Headers = headerList(p.reqExtra)
	}
	if p.respExtra != nil {
		e.Response.Headers = headerList(p.respExtra)
	}
	e.Request.Cookies = requestCookies(e.Request.Headers)
	e.Response.Cookies = responseCookies(e.Response.Headers)
	r.taint.Collect(e)
	r.file.Log.Entries = append(r.file.Log.Entries, har.RedactEntry(e))
	p.entry, p.reqExtra, p.respExtra = har.Entry{}, nil, nil
}

func headerKey(h map[string]string, lower string) string {
	for k := range h {
		if strings.EqualFold(k, lower) {
			return k
		}
	}
	return ""
}

// headerList turns a CDP header map into sorted HAR pairs; a value holding
// several lines (Chrome joins repeated headers with "\n") gives one pair
// per line.
func headerList(h map[string]string) []har.NV {
	out := []har.NV{}
	for k, v := range h {
		for line := range strings.SplitSeq(v, "\n") {
			out = append(out, har.NV{Name: k, Value: line})
		}
	}
	slices.SortStableFunc(out, func(a, b har.NV) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

func queryList(raw string) []har.NV {
	out := []har.NV{}
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return out
	}
	for part := range strings.SplitSeq(u.RawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		name, err1 := url.QueryUnescape(k)
		val, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			name, val = k, v
		}
		out = append(out, har.NV{Name: name, Value: val})
	}
	return out
}

func formParams(mt, body string) []har.NV {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(mt)), "application/x-www-form-urlencoded") || body == "" {
		return nil
	}
	return queryList("?" + body)
}

// requestCookies lists the cookies of the Cookie headers (values are
// redacted by har.RedactEntry; names are kept for the connector author).
func requestCookies(hs []har.NV) []har.Cookie {
	out := []har.Cookie{}
	for _, h := range hs {
		if !strings.EqualFold(h.Name, "cookie") {
			continue
		}
		for part := range strings.SplitSeq(h.Value, ";") {
			name, val, _ := strings.Cut(strings.TrimSpace(part), "=")
			if name != "" {
				out = append(out, har.Cookie{Name: name, Value: val})
			}
		}
	}
	return out
}

// responseCookies lists the Set-Cookie headers with their attributes.
func responseCookies(hs []har.NV) []har.Cookie {
	out := []har.Cookie{}
	for _, h := range hs {
		if !strings.EqualFold(h.Name, "set-cookie") {
			continue
		}
		parts := strings.Split(h.Value, ";")
		name, val, _ := strings.Cut(strings.TrimSpace(parts[0]), "=")
		if name == "" {
			continue
		}
		c := har.Cookie{Name: name, Value: val}
		for _, a := range parts[1:] {
			k, v, _ := strings.Cut(strings.TrimSpace(a), "=")
			switch strings.ToLower(k) {
			case "path":
				c.Path = v
			case "domain":
				c.Domain = v
			case "httponly":
				c.HTTPOnly = true
			case "secure":
				c.Secure = true
			}
		}
		out = append(out, c)
	}
	return out
}

func httpVersion(protocol string) string {
	switch strings.ToLower(protocol) {
	case "h2":
		return "HTTP/2.0"
	case "h3", "h3-29", "quic":
		return "HTTP/3.0"
	case "http/1.0":
		return "HTTP/1.0"
	default:
		return "HTTP/1.1"
	}
}

func textual(mt string) bool {
	m := strings.ToLower(strings.TrimSpace(strings.Split(mt, ";")[0]))
	return m == "" || strings.HasPrefix(m, "text/") || strings.Contains(m, "json") ||
		strings.Contains(m, "javascript") || strings.Contains(m, "xml") || m == "application/x-www-form-urlencoded"
}

// sanitizeNote keeps a browser error code readable and short.
func sanitizeNote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == ':' || r == '.' || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	return b.String()
}

// Summary reports the entry count, for the CLI summary.
func Summary(f *har.File) string {
	return fmt.Sprintf("%d entries", len(f.Log.Entries))
}
