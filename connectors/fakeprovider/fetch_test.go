package fakeprovider_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/connectors/fakeprovider"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// syntheticPDF is a minimal, synthetic PDF-looking body (no real document).
var syntheticPDF = []byte("%PDF-1.7\n% synthetic fakeprovider test document\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n")

const pdfID = "FP-2025-0001"

func pdfRef(id string) connector.DocumentRef {
	return connector.DocumentRef{
		ProviderID: id, Contract: "CTR-0001", Kind: connector.Invoice,
		IssuedAt: day(2025, 1, 15), MimeType: "application/pdf",
	}
}

// pdfSite serves body with ctype on /api/invoices/FP-2025-0001/pdf. When
// chunked is set the length is not declared (no Content-Length).
func pdfSite(t *testing.T, ck, ctype string, body []byte, chunked bool) *site {
	t.Helper()
	return newSite(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/invoices/"+pdfID+"/pdf" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if !authed(w, r, ck) {
			return
		}
		w.Header().Set("Content-Type", ctype)
		if !chunked {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
			return
		}
		// Several writes with flushes: net/http sends it chunked.
		for chunk := range slices2(body, 256) {
			_, _ = w.Write(chunk)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})
}

// slices2 yields b in pieces of n bytes.
func slices2(b []byte, n int) func(func([]byte) bool) {
	return func(yield func([]byte) bool) {
		for len(b) > 0 {
			k := min(n, len(b))
			if !yield(b[:k]) {
				return
			}
			b = b[k:]
		}
	}
}

func TestFetch_PDF(t *testing.T) {
	t.Parallel()

	t.Run("streams the document", func(t *testing.T) {
		t.Parallel()
		for _, ctype := range []string{"application/pdf", "application/pdf; name=\"FP-2025-0001.pdf\"", "Application/PDF"} {
			t.Run(ctype, func(t *testing.T) {
				t.Parallel()
				ck := canaryCookie(t)
				s := pdfSite(t, ck, ctype, syntheticPDF, false)
				rc, err := fakeprovider.New(fakeprovider.Options{}).Fetch(t.Context(), s.session(t, ck), pdfRef(pdfID))
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
				if !bytes.Equal(got, syntheticPDF) {
					t.Fatalf("body = %q, want the served PDF byte for byte (magic bytes included)", got)
				}
				if hits := s.hitList(); len(hits) != 1 || hits[0] != "GET "+wwwHost+" /api/invoices/"+pdfID+"/pdf" {
					t.Fatalf("requests = %q, want one GET of the PDF endpoint on %s", hits, wwwHost)
				}
			})
		}
	})

	t.Run("declared size over cap fails before reading", func(t *testing.T) {
		t.Parallel()
		ck := canaryCookie(t)
		big := append(append([]byte{}, syntheticPDF...), bytes.Repeat([]byte{' '}, 4096)...)
		s := pdfSite(t, ck, "application/pdf", big, false)
		rc, err := fakeprovider.New(fakeprovider.Options{MaxPDFBytes: 1024}).Fetch(t.Context(), s.session(t, ck), pdfRef(pdfID))
		if err == nil {
			_ = rc.Close()
			t.Fatal("Fetch accepted a Content-Length over MaxPDFBytes")
		}
		if !errors.Is(err, httpx.ErrBodyTooLarge) {
			t.Fatalf("Fetch error = %v, want httpx.ErrBodyTooLarge", err)
		}
	})

	t.Run("undeclared size over cap fails the read", func(t *testing.T) {
		t.Parallel()
		ck := canaryCookie(t)
		big := append(append([]byte{}, syntheticPDF...), bytes.Repeat([]byte{' '}, 4096)...)
		s := pdfSite(t, ck, "application/pdf", big, true)
		rc, err := fakeprovider.New(fakeprovider.Options{MaxPDFBytes: 1024}).Fetch(t.Context(), s.session(t, ck), pdfRef(pdfID))
		if err != nil {
			// Refusing up front is fine too, as long as it is the size cap.
			if !errors.Is(err, httpx.ErrBodyTooLarge) {
				t.Fatalf("Fetch error = %v, want httpx.ErrBodyTooLarge", err)
			}
			return
		}
		defer func() { _ = rc.Close() }()
		got, err := io.ReadAll(rc)
		if !errors.Is(err, httpx.ErrBodyTooLarge) {
			t.Fatalf("read = %d bytes, %v; want httpx.ErrBodyTooLarge (never a silent truncation)", len(got), err)
		}
		if len(got) > 1024 {
			t.Fatalf("read %d bytes past the 1024-byte cap", len(got))
		}
	})

	t.Run("status mapping", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name   string
			status int
			want   error
		}{
			{"401", http.StatusUnauthorized, connector.ErrNeedsLogin},
			{"403", http.StatusForbidden, connector.ErrAuthFailed},
			{"404", http.StatusNotFound, connector.ErrBroken},
			{"429", http.StatusTooManyRequests, connector.ErrRateLimited},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				s := newSite(t, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Retry-After", "3600")
					http.Error(w, http.StatusText(tc.status), tc.status)
				})
				rc, err := fakeprovider.New(fakeprovider.Options{}).Fetch(t.Context(), s.session(t, canaryCookie(t)), pdfRef(pdfID))
				if err == nil {
					_ = rc.Close()
				}
				if !errors.Is(err, tc.want) {
					t.Fatalf("Fetch error = %v, want %v", err, tc.want)
				}
				if n := len(s.hitList()); n != 1 {
					t.Errorf("Fetch made %d requests, want 1 (no retry)", n)
				}
				noQueryInError(t, err)
			})
		}
	})

	t.Run("invalid ref never requested", func(t *testing.T) {
		t.Parallel()
		s := newSite(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unexpected request", http.StatusTeapot)
		})
		sess := s.session(t, canaryCookie(t))
		c := fakeprovider.New(fakeprovider.Options{})
		for _, id := range []string{"", "../../api/me", "FP/1", "FP-1?x=1", "FP-1#x", "fp-lower", "FP 1", "%2e%2e", strings.Repeat("A", 65)} {
			rc, err := c.Fetch(t.Context(), sess, pdfRef(id))
			if err == nil {
				_ = rc.Close()
				t.Errorf("Fetch(%q) accepted an invalid ProviderID", id)
			}
		}
		for _, bad := range []connector.Session{nil, "not a session"} {
			rc, err := c.Fetch(t.Context(), bad, pdfRef(pdfID))
			if err == nil {
				_ = rc.Close()
				t.Errorf("Fetch accepted session %#v", bad)
			}
		}
		if hits := s.hitList(); len(hits) != 0 {
			t.Fatalf("invalid refs reached the site: %q", hits)
		}
	})
}

func TestFetch_NonPDFRefused(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		ctype string
		body  []byte
	}{
		{"html page", "text/html; charset=utf-8", []byte("<html><body>Session expired</body></html>")},
		{"octet-stream even with pdf magic", "application/octet-stream", syntheticPDF},
		{"no content type", "", syntheticPDF},
		{"pdf type, html body", "application/pdf", []byte("<html><body>Error</body></html>")},
		{"pdf type, magic not at start", "application/pdf", append([]byte("\n\n"), syntheticPDF...)},
		{"pdf type, empty body", "application/pdf", nil},
		{"pdf type, truncated magic", "application/pdf", []byte("%PD")},
		{"json error", "application/json", []byte(`{"error":"not found"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ck := canaryCookie(t)
			s := newSite(t, func(w http.ResponseWriter, r *http.Request) {
				if !authed(w, r, ck) {
					return
				}
				// An empty value suppresses net/http's content sniffing.
				w.Header()["Content-Type"] = []string{tc.ctype}
				_, _ = w.Write(tc.body)
			})
			rc, err := fakeprovider.New(fakeprovider.Options{}).Fetch(t.Context(), s.session(t, ck), pdfRef(pdfID))
			if err == nil {
				_ = rc.Close()
				t.Fatal("Fetch returned a reader for a non-PDF answer")
			}
			if !errors.Is(err, connector.ErrBroken) {
				t.Fatalf("Fetch error = %v, want ErrBroken", err)
			}
			if bytes.Contains([]byte(err.Error()), []byte("<html")) {
				t.Errorf("error echoes the response body: %v", err)
			}
		})
	}
}

// TestFetch_DeclaredLengthCapWrapsErrBroken (plan J1 T21, from the T20
// review): a declared Content-Length over MaxPDFBytes is classified like
// List's body cap, so the orchestrator marks the connector broken: the
// error matches both httpx.ErrBodyTooLarge and connector.ErrBroken, names
// the endpoint path and never its query, and no byte is read.
func TestFetch_DeclaredLengthCapWrapsErrBroken(t *testing.T) {
	t.Parallel()
	ck := canaryCookie(t)
	big := append(append([]byte{}, syntheticPDF...), bytes.Repeat([]byte{' '}, 4096)...)
	s := pdfSite(t, ck, "application/pdf", big, false)

	rc, err := fakeprovider.New(fakeprovider.Options{MaxPDFBytes: 1024}).Fetch(t.Context(), s.session(t, ck), pdfRef(pdfID))
	if err == nil {
		_ = rc.Close()
		t.Fatal("Fetch accepted a Content-Length over MaxPDFBytes")
	}
	if !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Errorf("Fetch error = %v, want httpx.ErrBodyTooLarge in the chain", err)
	}
	if !errors.Is(err, connector.ErrBroken) {
		t.Errorf("Fetch error = %v, want connector.ErrBroken in the chain (same classification as List)", err)
	}
	if !strings.Contains(err.Error(), "/api/invoices/"+pdfID+"/pdf") {
		t.Errorf("Fetch error = %q, want it to name the endpoint path", err)
	}
	noQueryInError(t, err)
	if strings.Contains(err.Error(), ck) {
		t.Error("Fetch error renders the session cookie")
	}
}
