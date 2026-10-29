package fakeprovider_test

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/connectors/fakeprovider"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

const listPath = "/api/invoices"

// fixture reads a synthetic list page from testdata/list.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(filepath.Join("testdata", "list")), name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

// pagedList serves pages[page-1] as JSON on /api/invoices for a request
// carrying cookie; any other path is a 404. It records the queries seen.
type pagedList struct {
	cookie string
	pages  []string
	ctype  string // default application/json

	mu      sync.Mutex
	queries []string
}

func (p *pagedList) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.queries)
}

func (p *pagedList) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != listPath || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if !authed(w, r, p.cookie) {
			return
		}
		p.mu.Lock()
		p.queries = append(p.queries, r.URL.RawQuery)
		p.mu.Unlock()
		n, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil || n < 1 || n > len(p.pages) {
			http.NotFound(w, r)
			return
		}
		ct := p.ctype
		if ct == "" {
			ct = "application/json"
		}
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write([]byte(p.pages[n-1]))
	}
}

func i64(v int64) *int64 { return &v }

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// sameRef compares the fields List must fill; Extra must be empty.
func sameRef(a, b connector.DocumentRef) bool {
	amountEq := (a.AmountCents == nil && b.AmountCents == nil) ||
		(a.AmountCents != nil && b.AmountCents != nil && *a.AmountCents == *b.AmountCents)
	return a.ProviderID == b.ProviderID && a.Contract == b.Contract && a.Kind == b.Kind &&
		a.IssuedAt.Equal(b.IssuedAt) && a.IssuedAt.Location() == time.UTC &&
		a.PeriodStart.Equal(b.PeriodStart) && a.PeriodEnd.Equal(b.PeriodEnd) &&
		amountEq && a.Currency == b.Currency && a.MimeType == b.MimeType && len(a.Extra) == 0
}

func fmtRef(r connector.DocumentRef) string {
	amount := "nil"
	if r.AmountCents != nil {
		amount = strconv.FormatInt(*r.AmountCents, 10)
	}
	return fmt.Sprintf("{%s %s %s issued=%s %s..%s amount=%s %s %s extra=%d}",
		r.ProviderID, r.Contract, r.Kind, r.IssuedAt.Format(time.RFC3339),
		r.PeriodStart.Format(time.DateOnly), r.PeriodEnd.Format(time.DateOnly),
		amount, r.Currency, r.MimeType, len(r.Extra))
}

func TestList_ParsesJSONStrictWithCaps(t *testing.T) {
	t.Parallel()

	t.Run("two pages", func(t *testing.T) {
		t.Parallel()
		ck := canaryCookie(t)
		pl := &pagedList{cookie: ck, pages: []string{fixture(t, "page1.json"), fixture(t, "page2.json")}}
		s := newSite(t, pl.handler(t))
		c := fakeprovider.New(fakeprovider.Options{})

		got, err := c.List(t.Context(), s.session(t, ck), year2025)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		want := []connector.DocumentRef{
			{
				ProviderID: "FP-2025-0001", Contract: "CTR-0001", Kind: connector.Invoice,
				IssuedAt: day(2025, 1, 15), PeriodStart: day(2024, 12, 1), PeriodEnd: day(2024, 12, 31),
				AmountCents: i64(4599), Currency: "EUR", MimeType: "application/pdf",
			},
			{
				ProviderID: "FP-2025-0002", Contract: "CTR-0001", Kind: connector.Invoice,
				IssuedAt: day(2025, 2, 15), PeriodStart: day(2025, 1, 1), PeriodEnd: day(2025, 1, 31),
				AmountCents: i64(0), Currency: "EUR", MimeType: "application/pdf",
			},
			{
				ProviderID: "FP-2025-0003", Contract: "CTR-0002", Kind: connector.Invoice,
				IssuedAt: day(2025, 12, 31), MimeType: "application/pdf",
			},
		}
		if len(got) != len(want) {
			t.Fatalf("List returned %d refs, want %d", len(got), len(want))
		}
		for i := range want {
			if !sameRef(got[i], want[i]) {
				t.Errorf("ref %d = %s\nwant      %s", i, fmtRef(got[i]), fmtRef(want[i]))
			}
		}
		wantQ := []string{
			"from=2025-01-01&page=1&to=2026-01-01",
			"from=2025-01-01&page=2&to=2026-01-01",
		}
		var gotQ []string
		for _, q := range pl.seen() {
			gotQ = append(gotQ, canonicalQuery(t, q))
		}
		if !slices.Equal(gotQ, wantQ) {
			t.Errorf("queries = %q, want %q", gotQ, wantQ)
		}
	})

	t.Run("empty year", func(t *testing.T) {
		t.Parallel()
		ck := canaryCookie(t)
		pl := &pagedList{cookie: ck, pages: []string{fixture(t, "empty.json")}}
		s := newSite(t, pl.handler(t))
		got, err := fakeprovider.New(fakeprovider.Options{}).List(t.Context(), s.session(t, ck), year2025)
		if err != nil {
			t.Fatalf("List on an empty year: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("List on an empty year returned %d refs", len(got))
		}
		if n := len(s.hitList()); n != 1 {
			t.Fatalf("empty year made %d requests, want 1", n)
		}
	})

	t.Run("items outside the period are dropped", func(t *testing.T) {
		t.Parallel()
		ck := canaryCookie(t)
		page := `{"invoices":[
			{"id":"FP-2024-0099","contract":"CTR-0001","issued_at":"2024-12-31"},
			{"id":"FP-2025-0001","contract":"CTR-0001","issued_at":"2025-01-01"},
			{"id":"FP-2026-0001","contract":"CTR-0001","issued_at":"2026-01-01"}
		],"next_page":null}`
		pl := &pagedList{cookie: ck, pages: []string{page}}
		s := newSite(t, pl.handler(t))
		got, err := fakeprovider.New(fakeprovider.Options{}).List(t.Context(), s.session(t, ck), year2025)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 1 || got[0].ProviderID != "FP-2025-0001" {
			ids := make([]string, 0, len(got))
			for _, r := range got {
				ids = append(ids, r.ProviderID)
			}
			t.Fatalf("List kept %q, want only FP-2025-0001 ([Start, End) is half-open)", ids)
		}
	})

	// Every malformed or oversized answer is a site change: ErrBroken.
	item := func(fields string) string {
		return `{"invoices":[{` + fields + `}],"next_page":null}`
	}
	const okItem = `"id":"FP-2025-0001","contract":"CTR-0001","issued_at":"2025-01-15"`
	padded := `{"invoices":[{` + okItem + `}],"next_page":null,` +
		`"x":"` + strings.Repeat("a", 2048) + `"}`
	threeItems := `{"invoices":[
		{"id":"FP-2025-0001","contract":"CTR-0001","issued_at":"2025-01-15"},
		{"id":"FP-2025-0002","contract":"CTR-0001","issued_at":"2025-02-15"},
		{"id":"FP-2025-0003","contract":"CTR-0001","issued_at":"2025-03-15"}
	],"next_page":null}`

	broken := []struct {
		name    string
		pages   []string
		ctype   string
		opts    fakeprovider.Options
		alsoIs  error // second errors.Is target, optional
		maxHits int   // 0: no bound checked
	}{
		{name: "unknown top-level field", pages: []string{`{"invoices":[],"next_page":null,"debug":true}`}},
		{name: "unknown item field", pages: []string{item(okItem + `,"pdf_url":"https://evil.test/x.pdf"`)}},
		{name: "missing invoices", pages: []string{`{"next_page":null}`}},
		{name: "null invoices", pages: []string{`{"invoices":null,"next_page":null}`}},
		{name: "renamed list key", pages: []string{`{"items":[],"next_page":null}`}},
		{name: "trailing data", pages: []string{`{"invoices":[],"next_page":null}{"invoices":[]}`}},
		{name: "not json", pages: []string{`<html><body>Maintenance</body></html>`}},
		{name: "html content type", pages: []string{fixtureLiteralEmpty}, ctype: "text/html; charset=utf-8"},
		{name: "empty id", pages: []string{item(`"id":"","contract":"CTR-0001","issued_at":"2025-01-15"`)}},
		{name: "id with path", pages: []string{item(`"id":"../../FP-1","contract":"CTR-0001","issued_at":"2025-01-15"`)}},
		{name: "id with slash", pages: []string{item(`"id":"FP/1","contract":"CTR-0001","issued_at":"2025-01-15"`)}},
		{name: "id with query", pages: []string{item(`"id":"FP-1?x=1","contract":"CTR-0001","issued_at":"2025-01-15"`)}},
		{name: "id too long", pages: []string{item(`"id":"` + strings.Repeat("A", 65) + `","contract":"CTR-0001","issued_at":"2025-01-15"`)}},
		{name: "contract missing", pages: []string{item(`"id":"FP-2025-0001","issued_at":"2025-01-15"`)}},
		{name: "contract with control char", pages: []string{item(`"id":"FP-2025-0001","contract":"CTR\u001b[2J","issued_at":"2025-01-15"`)}},
		{name: "issued_at missing", pages: []string{item(`"id":"FP-2025-0001","contract":"CTR-0001"`)}},
		{name: "impossible date", pages: []string{item(`"id":"FP-2025-0001","contract":"CTR-0001","issued_at":"2025-13-01"`)}},
		{name: "french date format", pages: []string{item(`"id":"FP-2025-0001","contract":"CTR-0001","issued_at":"15/01/2025"`)}},
		{name: "datetime instead of date", pages: []string{item(`"id":"FP-2025-0001","contract":"CTR-0001","issued_at":"2025-01-15T00:00:00Z"`)}},
		{name: "period reversed", pages: []string{item(okItem + `,"period_start":"2025-02-01","period_end":"2025-01-01"`)}},
		{name: "period half given", pages: []string{item(okItem + `,"period_start":"2025-01-01"`)}},
		{name: "amount not integer", pages: []string{item(okItem + `,"amount_cents":45.99,"currency":"EUR"`)}},
		{name: "amount as string", pages: []string{item(okItem + `,"amount_cents":"4599","currency":"EUR"`)}},
		{name: "amount over cap", pages: []string{item(okItem + `,"amount_cents":100000000001,"currency":"EUR"`)}},
		{name: "negative amount over cap", pages: []string{item(okItem + `,"amount_cents":-100000000001,"currency":"EUR"`)}},
		{name: "amount without currency", pages: []string{item(okItem + `,"amount_cents":4599`)}},
		{name: "lowercase currency", pages: []string{item(okItem + `,"amount_cents":4599,"currency":"eur"`)}},
		{name: "currency too long", pages: []string{item(okItem + `,"amount_cents":4599,"currency":"EURO"`)}},
		{
			name: "duplicate id across pages",
			pages: []string{
				`{"invoices":[{` + okItem + `}],"next_page":2}`,
				`{"invoices":[{` + okItem + `}],"next_page":null}`,
			},
		},
		{
			name:    "next_page loops back",
			pages:   []string{`{"invoices":[],"next_page":1}`},
			maxHits: 1,
		},
		{
			name:    "next_page skips ahead",
			pages:   []string{`{"invoices":[],"next_page":7}`},
			maxHits: 1,
		},
		{name: "next_page not a number", pages: []string{`{"invoices":[],"next_page":"2"}`}},
		{
			name:    "page body over cap",
			pages:   []string{padded},
			opts:    fakeprovider.Options{MaxListBytes: 512},
			alsoIs:  httpx.ErrBodyTooLarge,
			maxHits: 1,
		},
		{
			name:  "items over cap",
			pages: []string{threeItems},
			opts:  fakeprovider.Options{MaxItems: 2},
		},
		{
			name: "pages over cap",
			pages: []string{
				`{"invoices":[],"next_page":2}`,
				`{"invoices":[],"next_page":3}`,
				`{"invoices":[],"next_page":4}`,
				`{"invoices":[],"next_page":5}`,
			},
			opts:    fakeprovider.Options{MaxPages: 3},
			maxHits: 3,
		},
	}
	for _, tc := range broken {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ck := canaryCookie(t)
			pl := &pagedList{cookie: ck, pages: tc.pages, ctype: tc.ctype}
			s := newSite(t, pl.handler(t))
			got, err := fakeprovider.New(tc.opts).List(t.Context(), s.session(t, ck), year2025)
			if !errors.Is(err, connector.ErrBroken) {
				t.Fatalf("List = %d refs, %v; want ErrBroken", len(got), err)
			}
			if tc.alsoIs != nil && !errors.Is(err, tc.alsoIs) {
				t.Errorf("List error %v does not match %v", err, tc.alsoIs)
			}
			if got != nil {
				t.Errorf("List returned %d refs alongside an error", len(got))
			}
			if tc.maxHits > 0 {
				if n := len(s.hitList()); n > tc.maxHits {
					t.Errorf("List made %d requests, want at most %d", n, tc.maxHits)
				}
			}
			if strings.Contains(err.Error(), ck) {
				t.Errorf("error renders the session cookie")
			}
		})
	}
}

// fixtureLiteralEmpty is a valid empty page, used where only the headers
// are wrong.
const fixtureLiteralEmpty = `{"invoices":[],"next_page":null}`

// canonicalQuery re-encodes a raw query with sorted keys.
func canonicalQuery(t *testing.T, raw string) string {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("parse query %q: %v", raw, err)
	}
	return v.Encode()
}

func TestList_ErrorsNeverEchoBodyValues(t *testing.T) {
	t.Parallel()
	ck := canaryCookie(t)
	tok := testsecrets.Canary(t, testsecrets.Token)
	cases := map[string]string{
		"bad id":        `{"invoices":[{"id":"` + tok + `/x","contract":"CTR-0001","issued_at":"2025-01-15"}],"next_page":null}`,
		"bad date":      `{"invoices":[{"id":"FP-1","contract":"CTR-0001","issued_at":"` + tok + `"}],"next_page":null}`,
		"bad contract":  `{"invoices":[{"id":"FP-1","contract":"` + tok + ` x","issued_at":"2025-01-15"}],"next_page":null}`,
		"unknown value": `{"invoices":[],"next_page":null,"x":"` + tok + `"}`,
		"not json":      `<html>` + tok + `</html>`,
	}
	for name, page := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pl := &pagedList{cookie: ck, pages: []string{page}}
			s := newSite(t, pl.handler(t))
			_, err := fakeprovider.New(fakeprovider.Options{}).List(t.Context(), s.session(t, ck), year2025)
			if !errors.Is(err, connector.ErrBroken) {
				t.Fatalf("List error = %v, want ErrBroken", err)
			}
			if strings.Contains(err.Error(), tok) || strings.Contains(fmt.Sprintf("%+v", err), tok) {
				t.Fatalf("error echoes a response body value: %v", err)
			}
		})
	}
}

func TestList_429IsRateLimited(t *testing.T) {
	t.Parallel()
	for _, onPage := range []int{1, 2} {
		t.Run("page "+strconv.Itoa(onPage), func(t *testing.T) {
			t.Parallel()
			ck := canaryCookie(t)
			s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
				if !authed(w, r, ck) {
					return
				}
				if r.URL.Query().Get("page") == strconv.Itoa(onPage) {
					// Honouring this would hang the test: the connector must
					// return at once and let the orchestrator decide.
					w.Header().Set("Retry-After", "3600")
					http.Error(w, "slow down", http.StatusTooManyRequests)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"invoices":[],"next_page":2}`))
			})
			got, err := fakeprovider.New(fakeprovider.Options{}).List(t.Context(), s.session(t, ck), year2025)
			if !errors.Is(err, connector.ErrRateLimited) {
				t.Fatalf("List = %d refs, %v; want ErrRateLimited", len(got), err)
			}
			for _, other := range []error{connector.ErrBroken, connector.ErrNeedsLogin, connector.ErrAuthFailed} {
				if errors.Is(err, other) {
					t.Errorf("rate limit also matches %v", other)
				}
			}
			if n := len(s.hitList()); n != onPage {
				t.Fatalf("List made %d requests, want %d: nothing after the 429, no retry", n, onPage)
			}
			noQueryInError(t, err)
		})
	}
}

func TestList_404IsBroken(t *testing.T) {
	t.Parallel()
	ck := canaryCookie(t)
	s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r, ck) {
			return
		}
		http.NotFound(w, r)
	})
	_, err := fakeprovider.New(fakeprovider.Options{}).List(t.Context(), s.session(t, ck), year2025)
	if !errors.Is(err, connector.ErrBroken) {
		t.Fatalf("List error = %v, want ErrBroken", err)
	}
	if !strings.Contains(err.Error(), listPath) {
		t.Errorf("error %q does not name the missing endpoint %s", err, listPath)
	}
	noQueryInError(t, err)
	if n := len(s.hitList()); n != 1 {
		t.Errorf("List made %d requests after a 404, want 1", n)
	}
}

// Status and redirect mapping shared by every endpoint, checked on List.
func TestList_StatusMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		h    func(w http.ResponseWriter, r *http.Request)
		want error
	}{
		{
			name: "401 expired session",
			h:    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "expired", http.StatusUnauthorized) },
			want: connector.ErrNeedsLogin,
		},
		{
			name: "redirect to the sso login page",
			h: func(w http.ResponseWriter, r *http.Request) {
				if r.Host == ssoHost && r.URL.Path == "/login" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = w.Write([]byte(`<html><form id="login"></form></html>`))
					return
				}
				http.Redirect(w, r, "https://"+ssoHost+"/login?next=%2Fapi%2Finvoices", http.StatusFound)
			},
			want: connector.ErrNeedsLogin,
		},
		{
			name: "403 forbidden",
			h:    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "forbidden", http.StatusForbidden) },
			want: connector.ErrAuthFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newSite(t, tc.h)
			_, err := fakeprovider.New(fakeprovider.Options{}).List(t.Context(), s.session(t, canaryCookie(t)), year2025)
			if !errors.Is(err, tc.want) {
				t.Fatalf("List error = %v, want %v", err, tc.want)
			}
			noQueryInError(t, err)
		})
	}
}

func TestList_RedirectOffAllowlistNeverDialled(t *testing.T) {
	t.Parallel()
	s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+evilHost+"/collect", http.StatusFound)
	})
	_, err := fakeprovider.New(fakeprovider.Options{}).List(t.Context(), s.session(t, canaryCookie(t)), year2025)
	if !errors.Is(err, httpx.ErrDomainNotAllowed) {
		t.Fatalf("List error = %v, want httpx.ErrDomainNotAllowed", err)
	}
	for _, d := range s.dialList() {
		if strings.HasPrefix(d, evilHost) {
			t.Fatalf("dialled %s: the allowlist must stop the hop before any connection", d)
		}
	}
}

func TestList_RefusesBadInputsWithoutRequest(t *testing.T) {
	t.Parallel()
	s := newSite(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unexpected request", http.StatusTeapot)
	})
	sess := s.session(t, canaryCookie(t))
	c := fakeprovider.New(fakeprovider.Options{})
	cases := []struct {
		name string
		sess connector.Session
		p    connector.Period
	}{
		{name: "nil session", sess: nil, p: year2025},
		{name: "foreign session type", sess: "not a session", p: year2025},
		{name: "empty period", sess: sess, p: connector.Period{Start: day(2025, 1, 1), End: day(2025, 1, 1)}},
		{name: "reversed period", sess: sess, p: connector.Period{Start: day(2026, 1, 1), End: day(2025, 1, 1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.List(t.Context(), tc.sess, tc.p)
			if err == nil {
				t.Fatalf("List = %d refs, nil error; want an error", len(got))
			}
		})
	}
	if hits := s.hitList(); len(hits) != 0 {
		t.Fatalf("bad inputs reached the site: %q", hits)
	}
}
