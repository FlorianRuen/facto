package wecasa_test

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/connectors/wecasa"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// wantRef is the part of a DocumentRef the list tests compare.
type wantRef struct {
	id     string
	issued time.Time
}

// recorded2026 is what the recording lists for 2026, in list order: every
// item is a Done order, invoiced, 9532 EUR cents; appointments in UTC.
var recorded2026 = []wantRef{
	{"sz4Jk11V7Q4H", utc(2026, time.October, 8, 15)},
	{"MmBPtjTkFqsp", utc(2026, time.September, 3, 14)},
	{"xwT3jTghJdc1", utc(2026, time.August, 13, 14)},
	{"aCMmbqzTPFDb", utc(2026, time.July, 11, 8)},
	{"mtBo4xaHRCz8", utc(2026, time.June, 5, 11)},
	{"LmaperYr57wH", utc(2026, time.May, 21, 14)},
	{"PK6iZymjbDf3", utc(2026, time.April, 30, 14)},
	{"Tg2CqwTK7Pvi", utc(2026, time.February, 28, 15)},
	{"FLjcTky8TUVW", utc(2026, time.January, 3, 15)},
}

func assertRefs(t *testing.T, got []connector.DocumentRef, want []wantRef) {
	t.Helper()
	if len(got) != len(want) {
		ids := make([]string, 0, len(got))
		for _, r := range got {
			ids = append(ids, r.ProviderID)
		}
		t.Fatalf("List returned %d refs %v, want %d", len(got), ids, len(want))
	}
	for i, w := range want {
		r := got[i]
		if r.ProviderID != w.id {
			t.Errorf("ref %d: ProviderID = %q, want %q", i, r.ProviderID, w.id)
		}
		if !r.IssuedAt.Equal(w.issued) || r.IssuedAt.Location() != time.UTC {
			t.Errorf("ref %d (%s): IssuedAt = %v, want %v UTC", i, w.id, r.IssuedAt, w.issued)
		}
		if r.Kind != connector.Invoice || r.MimeType != "application/pdf" {
			t.Errorf("ref %d: Kind %v MimeType %q, want invoice application/pdf", i, r.Kind, r.MimeType)
		}
		if r.AmountCents == nil || *r.AmountCents != 9532 || r.Currency != "EUR" {
			t.Errorf("ref %d: amount %v %q, want 9532 EUR", i, r.AmountCents, r.Currency)
		}
	}
}

// TestList_RecordedFixtures: the recorded delivered list and order
// details give the right refs, amounts and UTC dates for each period; an
// order is detailed only when its appointment is inside the period.
func TestList_RecordedFixtures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		p    connector.Period
		want []wantRef
	}{
		{name: "2026", p: connector.Year(2026), want: recorded2026},
		{name: "2025", p: connector.Year(2025), want: []wantRef{
			{"rpqu3HuXFrVC", utc(2025, time.December, 4, 15)},
			{"mQjvSmJkfzJ7", utc(2025, time.November, 9, 15)},
			{"YbVEZohXNcZB", utc(2025, time.October, 9, 15)},
			{"9TtKGUY5gK1a", utc(2025, time.September, 11, 14)},
		}},
		{name: "empty year", p: connector.Year(2024), want: nil},
		{name: "one month", p: connector.Period{Start: utc(2026, time.July, 1, 0), End: utc(2026, time.August, 1, 0)}, want: []wantRef{
			{"aCMmbqzTPFDb", utc(2026, time.July, 11, 8)},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSite(t)
			c := wecasa.New(wecasa.Options{})
			sess := s.session(t)
			refs, err := c.List(t.Context(), sess, tt.p)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if refs == nil {
				t.Error("List returned nil without an error, want an empty slice")
			}
			assertRefs(t, refs, tt.want)
			if n := s.hitsWithPrefix("GET " + pathDelivered); n != 1 {
				t.Errorf("delivered list fetched %d times, want 1", n)
			}
			if n := s.hitsWithPrefix("GET " + pathOrders); n != len(tt.want) {
				t.Errorf("order details fetched %d times, want %d (only orders in the period)", n, len(tt.want))
			}
			if n := s.badAuthCount(); n != 0 {
				t.Errorf("%d API requests without the bearer token", n)
			}
		})
	}
}

// item renders one delivered-list item.
func item(id, appointment, stage, typ string) string {
	return fmt.Sprintf(`{"appointment":%q,"duration":180,"public_id":%q,"stage":%q,"type":%q,"title":"Ménage","universe":"cleaning","pro":{"first_name":"X"}}`,
		appointment, id, stage, typ)
}

func list(items ...string) []byte { return []byte("[" + strings.Join(items, ",") + "]") }

// order renders one order detail answer.
func order(id string, invoices bool, price, currency string) []byte {
	return fmt.Appendf(nil, `{"success":true,"data":{"public_id":%q,"invoices":%t,"total_price":%s,"currency":%s,"stage":"Done","type":"order","extra":{"nested":[1,2]}}}`,
		id, invoices, price, currency)
}

// TestList_FiltersItems: only type "order" with stage "Done" in the
// period are detailed; invoices:false is skipped; the appointment is
// compared in UTC (a 00:30+01:00 New Year appointment belongs to the
// previous year).
func TestList_FiltersItems(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	s.setDelivered(list(
		item("DoneOrder0001", "2026-03-01T10:00:00.000+01:00", "Done", "order"),
		item("CancelledOrd1", "2026-03-02T10:00:00.000+01:00", "Cancelled", "order"),
		item("PendingOrder1", "2026-03-03T10:00:00.000+01:00", "Pending", "order"),
		item("PotentialAbc1", "2026-03-04T10:00:00.000+01:00", "Done", "potential"),
		item("NoInvoice0001", "2026-03-05T10:00:00.000+01:00", "Done", "order"),
		item("NewYearOrder1", "2026-01-01T00:30:00.000+01:00", "Done", "order"),
		// A skipped item is not validated: its odd shape must not fail List.
		`{"public_id":"!!","appointment":null,"stage":"Unknown","type":"gift"}`,
	))
	s.setOrder("DoneOrder0001", order("DoneOrder0001", true, "12345", `"EUR"`))
	s.setOrder("NoInvoice0001", order("NoInvoice0001", false, "500", `"EUR"`))
	s.setOrder("NewYearOrder1", order("NewYearOrder1", true, "100", `"EUR"`))
	c := wecasa.New(wecasa.Options{})
	sess := s.session(t)

	refs, err := c.List(t.Context(), sess, connector.Year(2026))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 1 || refs[0].ProviderID != "DoneOrder0001" {
		t.Fatalf("List = %+v, want only DoneOrder0001", refs)
	}
	if *refs[0].AmountCents != 12345 || !refs[0].IssuedAt.Equal(utc(2026, time.March, 1, 9)) {
		t.Errorf("ref = %+v", refs[0])
	}
	for _, skipped := range []string{"CancelledOrd1", "PendingOrder1", "PotentialAbc1", "NewYearOrder1"} {
		if n := s.hitsWithPrefix("GET " + pathOrders + skipped); n != 0 {
			t.Errorf("%s detailed %d times, want 0", skipped, n)
		}
	}

	refs, err = c.List(t.Context(), sess, connector.Year(2025))
	if err != nil {
		t.Fatalf("List 2025: %v", err)
	}
	if len(refs) != 1 || refs[0].ProviderID != "NewYearOrder1" || !refs[0].IssuedAt.Equal(utc(2025, time.December, 31, 23).Add(30*time.Minute)) {
		t.Errorf("List 2025 = %+v, want NewYearOrder1 at 2025-12-31 23:30 UTC", refs)
	}
}

// TestList_EmptyDeliveredList: an empty array is an empty year, not an
// error.
func TestList_EmptyDeliveredList(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	s.setDelivered([]byte(" [ ]\n"))
	refs, err := wecasa.New(wecasa.Options{}).List(t.Context(), s.session(t), connector.Year(2026))
	if err != nil || refs == nil || len(refs) != 0 {
		t.Fatalf("List = %v, %v; want empty, nil", refs, err)
	}
}

// TestList_MalformedAnswersBroken: every malformed list or order answer
// wraps ErrBroken, the result is nil and the error never echoes a body
// value.
func TestList_MalformedAnswersBroken(t *testing.T) {
	t.Parallel()
	const leak = "LEAKVALUE"
	const id = "DoneOrder0001"
	okItem := item(id, "2026-03-01T10:00:00.000+01:00", "Done", "order")
	tests := []struct {
		name      string
		delivered []byte
		order     []byte
		wantPiece string // the error names this piece
	}{
		{name: "not an array", delivered: []byte(`{"bookings":[]}`), wantPiece: pathDelivered},
		{name: "null", delivered: []byte(`null`), wantPiece: pathDelivered},
		{name: "truncated", delivered: []byte(`[{"public_id":"` + leak), wantPiece: pathDelivered},
		{name: "trailing data", delivered: []byte(`[] []`), wantPiece: pathDelivered},
		{name: "public_id wrong type", delivered: []byte(`[{"public_id":5,"type":"order","stage":"Done"}]`), wantPiece: pathDelivered},
		{name: "bad public_id", delivered: list(item("bad/"+leak, "2026-03-01T10:00:00.000+01:00", "Done", "order")), wantPiece: "public_id"},
		{name: "short public_id", delivered: list(item("abc", "2026-03-01T10:00:00.000+01:00", "Done", "order")), wantPiece: "public_id"},
		{name: "bad appointment", delivered: list(item(id, leak, "Done", "order")), wantPiece: "appointment"},
		{name: "appointment without zone", delivered: list(item(id, "2026-03-01T10:00:00", "Done", "order")), wantPiece: "appointment"},
		{name: "duplicate id", delivered: list(okItem, okItem), wantPiece: "duplicate"},
		{name: "order success false", delivered: list(okItem), order: []byte(`{"success":false,"data":{}}`), wantPiece: "success"},
		{name: "order without data", delivered: list(okItem), order: []byte(`{"success":true}`), wantPiece: "data"},
		{name: "order other id", delivered: list(okItem), order: order("OtherOrder001", true, "1", `"EUR"`), wantPiece: "public_id"},
		{name: "order invoices missing", delivered: list(okItem), order: []byte(`{"success":true,"data":{"public_id":"` + id + `","total_price":1,"currency":"EUR"}}`), wantPiece: "invoices"},
		{name: "order price not integer", delivered: list(okItem), order: order(id, true, "95.32", `"EUR"`), wantPiece: "total_price"},
		{name: "order price string", delivered: list(okItem), order: order(id, true, `"`+leak+`"`, `"EUR"`), wantPiece: "total_price"},
		{name: "order price over cap", delivered: list(okItem), order: order(id, true, "100000001", `"EUR"`), wantPiece: "total_price"},
		{name: "order negative price", delivered: list(okItem), order: order(id, true, "-1", `"EUR"`), wantPiece: "total_price"},
		{name: "order bad currency", delivered: list(okItem), order: order(id, true, "1", `"`+leak+`"`), wantPiece: "currency"},
		{name: "order price without currency", delivered: list(okItem), order: order(id, true, "1", "null"), wantPiece: "currency"},
		{name: "order malformed", delivered: list(okItem), order: []byte(`{"success":true,"data":` + leak), wantPiece: pathOrders},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSite(t)
			s.setDelivered(tt.delivered)
			if tt.order != nil {
				s.setOrder(id, tt.order)
			}
			refs, err := wecasa.New(wecasa.Options{}).List(t.Context(), s.session(t), connector.Year(2026))
			if !errors.Is(err, connector.ErrBroken) {
				t.Fatalf("List = %v, %v; want ErrBroken", refs, err)
			}
			if refs != nil {
				t.Errorf("List returned refs with its error: %v", refs)
			}
			if !strings.Contains(err.Error(), tt.wantPiece) {
				t.Errorf("error %q does not name %q", err, tt.wantPiece)
			}
			if strings.Contains(err.Error(), leak) {
				t.Errorf("error echoes a body value: %v", err)
			}
			s.noSecretIn(t, "List error", fmt.Sprintf("%v|%+v|%#v", err, err, err))
		})
	}
}

// TestList_NullPriceHasNoAmount: an order without a price is listed
// without an amount.
func TestList_NullPriceHasNoAmount(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	s.setDelivered(list(item("DoneOrder0001", "2026-03-01T10:00:00.000+01:00", "Done", "order")))
	s.setOrder("DoneOrder0001", order("DoneOrder0001", true, "null", "null"))
	refs, err := wecasa.New(wecasa.Options{}).List(t.Context(), s.session(t), connector.Year(2026))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 1 || refs[0].AmountCents != nil || refs[0].Currency != "" {
		t.Errorf("List = %+v, want one ref without amount", refs)
	}
}

// TestList_Caps: the list body (declared or not) and the item count are
// capped; a cap hit wraps ErrBroken and httpx.ErrBodyTooLarge for bodies.
func TestList_Caps(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte(" "), 4096)
	tests := []struct {
		name     string
		opts     wecasa.Options
		h        http.HandlerFunc
		body     []byte
		wantBody bool
	}{
		{name: "declared length over cap", opts: wecasa.Options{MaxListBytes: 1024}, h: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(len(big)+2))
			_, _ = w.Write(append(append([]byte("["), big...), ']'))
		}, wantBody: true},
		{name: "undeclared body over cap", opts: wecasa.Options{MaxListBytes: 1024}, h: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.(http.Flusher).Flush() // chunked: no Content-Length
			_, _ = w.Write(append(append([]byte("["), big...), ']'))
		}, wantBody: true},
		{name: "too many items", opts: wecasa.Options{MaxItems: 2}, body: list(
			item("CancelledOrd1", "2026-03-02T10:00:00.000+01:00", "Cancelled", "order"),
			item("CancelledOrd2", "2026-03-02T10:00:00.000+01:00", "Cancelled", "order"),
			item("CancelledOrd3", "2026-03-02T10:00:00.000+01:00", "Cancelled", "order"),
		)},
		{name: "wrong content type", h: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("[]"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSite(t)
			if tt.h != nil {
				s.route(pathDelivered, tt.h)
			}
			if tt.body != nil {
				s.setDelivered(tt.body)
			}
			refs, err := wecasa.New(tt.opts).List(t.Context(), s.session(t), connector.Year(2026))
			if !errors.Is(err, connector.ErrBroken) || refs != nil {
				t.Fatalf("List = %v, %v; want nil, ErrBroken", refs, err)
			}
			if tt.wantBody && !errors.Is(err, httpx.ErrBodyTooLarge) {
				t.Errorf("List = %v, want httpx.ErrBodyTooLarge too", err)
			}
			if n := s.hitsWithPrefix("GET " + pathOrders); n != 0 {
				t.Errorf("%d order details fetched after a list failure", n)
			}
		})
	}
}

// TestList_DefaultCapsFromSheet: 2 MiB list, 2000 items, 20 MiB PDF.
func TestList_DefaultCapsFromSheet(t *testing.T) {
	t.Parallel()
	if wecasa.DefaultMaxListBytes != 2<<20 || wecasa.DefaultMaxItems != 2000 || wecasa.DefaultMaxPDFBytes != 20<<20 {
		t.Errorf("defaults = %d, %d, %d; want 2 MiB, 2000, 20 MiB",
			wecasa.DefaultMaxListBytes, wecasa.DefaultMaxItems, wecasa.DefaultMaxPDFBytes)
	}
}

// TestList_StatusMapping: 401 → ErrNeedsLogin, 403 → ErrAuthFailed, 429 →
// ErrRateLimited after exactly one request (no retry), 404 → ErrBroken
// naming the endpoint, 500 → ErrBroken; on the list and on an order.
func TestList_StatusMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code int
		want error
	}{
		{http.StatusUnauthorized, connector.ErrNeedsLogin},
		{http.StatusForbidden, connector.ErrAuthFailed},
		{http.StatusTooManyRequests, connector.ErrRateLimited},
		{http.StatusNotFound, connector.ErrBroken},
		{http.StatusInternalServerError, connector.ErrBroken},
	}
	for _, tt := range tests {
		for _, path := range []string{pathDelivered, pathOrders + "aCMmbqzTPFDb"} {
			t.Run(fmt.Sprintf("%d %s", tt.code, path), func(t *testing.T) {
				t.Parallel()
				s := newSite(t)
				s.route(path, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Retry-After", "3600")
					w.WriteHeader(tt.code)
				})
				refs, err := wecasa.New(wecasa.Options{}).List(t.Context(), s.session(t), connector.Year(2026))
				if !errors.Is(err, tt.want) || refs != nil {
					t.Fatalf("List = %v, %v; want %v", refs, err, tt.want)
				}
				if n := s.hitsWithPrefix("GET " + path); n != 1 {
					t.Errorf("%s requested %d times, want exactly 1", path, n)
				}
				if !strings.Contains(err.Error(), path) {
					t.Errorf("error %q does not name %s", err, path)
				}
				noQueryInError(t, err)
			})
		}
	}
}

// TestList_ExpiredSessionNeedsLogin: the API answers 401 once the token
// is no longer accepted (the site's real expiry mode).
func TestList_ExpiredSessionNeedsLogin(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	sess := s.session(t)
	s.mu.Lock()
	s.token = "rotated-" + s.token
	s.mu.Unlock()
	_, err := wecasa.New(wecasa.Options{}).List(t.Context(), sess, connector.Year(2026))
	if !errors.Is(err, connector.ErrNeedsLogin) {
		t.Fatalf("List = %v, want ErrNeedsLogin", err)
	}
	s.noSecretIn(t, "List error", fmt.Sprintf("%v|%+v|%#v", err, err, err))
}

// TestList_RedirectToLoginNeedsLogin: an API call redirected to the login
// page means the session is gone.
func TestList_RedirectToLoginNeedsLogin(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	s.route(pathDelivered, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+wwwHost+pathLoginPage, http.StatusFound)
	})
	_, err := wecasa.New(wecasa.Options{}).List(t.Context(), s.session(t), connector.Year(2026))
	if !errors.Is(err, connector.ErrNeedsLogin) {
		t.Fatalf("List = %v, want ErrNeedsLogin", err)
	}
}

// TestList_RedirectOffAllowlistNeverDialled: a redirect to another host is
// refused before any connection.
func TestList_RedirectOffAllowlistNeverDialled(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	s.route(pathDelivered, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+evilHost+"/steal?x=1", http.StatusFound)
	})
	_, err := wecasa.New(wecasa.Options{}).List(t.Context(), s.session(t), connector.Year(2026))
	if !errors.Is(err, httpx.ErrDomainNotAllowed) {
		t.Fatalf("List = %v, want httpx.ErrDomainNotAllowed", err)
	}
	if slices.Contains(s.dialList(), evilHost+":443") {
		t.Errorf("dialled %s: %v", evilHost, s.dialList())
	}
	noQueryInError(t, err)
}

// TestList_RefusesBadInputsWithoutRequest: a foreign session or an empty
// period fails before any request.
func TestList_RefusesBadInputsWithoutRequest(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	sess := s.session(t)
	before := len(s.hitList())
	c := wecasa.New(wecasa.Options{})
	if _, err := c.List(t.Context(), "not a session", connector.Year(2026)); err == nil {
		t.Error("List(foreign session) succeeded")
	}
	if _, err := c.List(t.Context(), (*wecasa.Session)(nil), connector.Year(2026)); err == nil {
		t.Error("List(nil session) succeeded")
	}
	if _, err := c.List(t.Context(), &wecasa.Session{}, connector.Year(2026)); err == nil {
		t.Error("List(zero session) succeeded")
	}
	p := connector.Year(2026)
	if _, err := c.List(t.Context(), sess, connector.Period{Start: p.End, End: p.Start}); err == nil {
		t.Error("List(reversed period) succeeded")
	}
	if n := len(s.hitList()); n != before {
		t.Errorf("%d requests sent for refused inputs", n-before)
	}
}
