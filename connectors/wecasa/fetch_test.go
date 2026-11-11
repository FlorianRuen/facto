package wecasa_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/connectors/wecasa"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

const pdfPath = pathOrders + "aCMmbqzTPFDb/download_invoices"

func refFor(id string) connector.DocumentRef {
	return connector.DocumentRef{ProviderID: id, Kind: connector.Invoice, MimeType: "application/pdf"}
}

// TestFetch_RecordedPDF: login-free happy path on the recorded PDF, bearer
// token sent, bytes unchanged.
func TestFetch_RecordedPDF(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	rc, err := wecasa.New(wecasa.Options{}).Fetch(t.Context(), s.session(t), refFor("aCMmbqzTPFDb"))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, err := io.ReadAll(rc)
	if cerr := rc.Close(); cerr != nil {
		t.Errorf("Close: %v", cerr)
	}
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, fixture(t, fxPDF)) {
		t.Errorf("PDF bytes differ from the fixture (%d bytes)", len(got))
	}
	if n := s.hitsWithPrefix("GET " + pdfPath); n != 1 {
		t.Errorf("PDF requested %d times, want 1", n)
	}
	if n := s.badAuthCount(); n != 0 {
		t.Errorf("%d API requests without the bearer token", n)
	}
}

// TestFetch_RefusedAnswers: non-PDF types and bodies, oversized bodies
// (declared or not) and statuses are refused with the right sentinel.
func TestFetch_RefusedAnswers(t *testing.T) {
	t.Parallel()
	pdf := []byte("%PDF-1.7\n" + strings.Repeat("x", 4096))
	tests := []struct {
		name     string
		opts     wecasa.Options
		h        http.HandlerFunc
		want     error
		wantRead error // when Fetch succeeds, the read must fail with it
	}{
		{name: "html body", h: serve("text/html", []byte("<html>login</html>"), false), want: connector.ErrBroken},
		{name: "pdf type html body", h: serve("application/pdf", []byte("<html>login</html>"), false), want: connector.ErrBroken},
		{name: "json type", h: serve("application/json", pdf, false), want: connector.ErrBroken},
		{name: "empty body", h: serve("application/pdf", nil, false), want: connector.ErrBroken},
		{name: "declared length over cap", opts: wecasa.Options{MaxPDFBytes: 1024}, h: serve("application/pdf", pdf, true), want: httpx.ErrBodyTooLarge},
		{name: "undeclared body over cap", opts: wecasa.Options{MaxPDFBytes: 1024}, h: serve("application/pdf", pdf, false), wantRead: httpx.ErrBodyTooLarge},
		{name: "cap smaller than magic", opts: wecasa.Options{MaxPDFBytes: 3}, h: serve("application/pdf", pdf, false), want: httpx.ErrBodyTooLarge},
		{name: "401", h: status(http.StatusUnauthorized), want: connector.ErrNeedsLogin},
		{name: "404", h: status(http.StatusNotFound), want: connector.ErrBroken},
		{name: "429", h: status(http.StatusTooManyRequests), want: connector.ErrRateLimited},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newSite(t)
			s.route(pdfPath, tt.h)
			rc, err := wecasa.New(tt.opts).Fetch(t.Context(), s.session(t), refFor("aCMmbqzTPFDb"))
			if tt.wantRead != nil {
				if err != nil {
					t.Fatalf("Fetch: %v", err)
				}
				_, rerr := io.ReadAll(rc)
				_ = rc.Close()
				if !errors.Is(rerr, tt.wantRead) {
					t.Fatalf("read = %v, want %v", rerr, tt.wantRead)
				}
				return
			}
			if !errors.Is(err, tt.want) || rc != nil {
				t.Fatalf("Fetch = %v, %v; want %v", rc, err, tt.want)
			}
			if errors.Is(tt.want, httpx.ErrBodyTooLarge) && !errors.Is(err, connector.ErrBroken) {
				t.Errorf("Fetch = %v, want ErrBroken too", err)
			}
			if n := s.hitsWithPrefix("GET " + pdfPath); n != 1 {
				t.Errorf("PDF requested %d times, want exactly 1", n)
			}
			s.noSecretIn(t, "Fetch error", fmt.Sprintf("%v|%+v|%#v", err, err, err))
		})
	}
}

func serve(ctype string, body []byte, declare bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ctype)
		if declare {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		} else {
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write(body)
	}
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

// TestFetch_InvalidProviderIDRefusedBeforeRequest: an id that is not
// ^[A-Za-z0-9]{8,32}$ never reaches the network.
func TestFetch_InvalidProviderIDRefusedBeforeRequest(t *testing.T) {
	t.Parallel()
	s := newSite(t)
	sess := s.session(t)
	before := len(s.hitList())
	c := wecasa.New(wecasa.Options{})
	for _, id := range []string{"", "short", "../../api/v1/user", "aCMmbqzTPFDb/x", "aCMmbqzTPFDb?x=1", "aCMmbqzTPFDb%2F", "aCMmbqzT-PFDb", strings.Repeat("a", 33), "aCMmbqzTPFDé"} {
		rc, err := c.Fetch(t.Context(), sess, refFor(id))
		if err == nil || rc != nil {
			t.Errorf("Fetch(%q) = %v, %v; want an error", id, rc, err)
		}
	}
	if _, err := c.Fetch(t.Context(), "not a session", refFor("aCMmbqzTPFDb")); err == nil {
		t.Error("Fetch(foreign session) succeeded")
	}
	if n := len(s.hitList()); n != before {
		t.Errorf("%d requests sent for invalid ids", n-before)
	}
}
