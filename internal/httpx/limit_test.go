package httpx_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// closeRecorder counts Close calls on the wrapped reader.
type closeRecorder struct {
	io.Reader
	closes int
}

func (c *closeRecorder) Close() error {
	c.closes++
	return nil
}

func TestLimitBody_Caps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		size    int
		max     int64
		wantErr bool
	}{
		{name: "empty", size: 0, max: 10},
		{name: "under", size: 9, max: 10},
		{name: "exact", size: 10, max: 10},
		{name: "one over", size: 11, max: 10, wantErr: true},
		{name: "far over", size: 1 << 20, max: 1 << 10, wantErr: true},
		{name: "zero max empty body", size: 0, max: 0},
		{name: "zero max one byte", size: 1, max: 0, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := bytes.Repeat([]byte("a"), tc.size)
			rc := &closeRecorder{Reader: bytes.NewReader(src)}
			lb := httpx.LimitBody(rc, tc.max)
			got, err := io.ReadAll(lb)
			if tc.wantErr {
				if !errors.Is(err, httpx.ErrBodyTooLarge) {
					t.Fatalf("ReadAll error = %v, want ErrBodyTooLarge", err)
				}
				if int64(len(got)) > tc.max {
					t.Errorf("read %d bytes, want at most %d", len(got), tc.max)
				}
			} else {
				if err != nil {
					t.Fatalf("ReadAll error = %v", err)
				}
				if !bytes.Equal(got, src) {
					t.Errorf("read %d bytes, want all %d", len(got), len(src))
				}
			}
			if err := lb.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
			if rc.closes != 1 {
				t.Errorf("underlying Close called %d times, want 1", rc.closes)
			}
		})
	}
}

func TestLimitBody_ErrorIsSticky(t *testing.T) {
	t.Parallel()
	lb := httpx.LimitBody(io.NopCloser(strings.NewReader("0123456789")), 4)
	if _, err := io.ReadAll(lb); !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Fatalf("first ReadAll error = %v, want ErrBodyTooLarge", err)
	}
	n, err := lb.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Errorf("Read after overflow = %d, %v; want 0, ErrBodyTooLarge (never io.EOF)", n, err)
	}
}

func TestLimitBody_OnResponse(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("x", 64<<10)
	e := newEnv(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, big) })
	resp, err := e.client(t, "fournisseur.test").Get(t.Context(), "https://fournisseur.test/invoice.pdf")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := httpx.LimitBody(resp.Body, 1<<10)
	defer func() { _ = body.Close() }()
	if _, err := io.ReadAll(body); !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Fatalf("ReadAll error = %v, want ErrBodyTooLarge", err)
	}
}

// TestParseAllowlist_AgreesWithConnectorValidateInfo pins a single allowlist
// syntax: connector.ValidateInfo (registration) and httpx (enforcement) must
// accept and refuse exactly the same AllowedDomains.
func TestParseAllowlist_AgreesWithConnectorValidateInfo(t *testing.T) {
	t.Parallel()
	check := func(list []string, wantValid bool) {
		t.Helper()
		_, herr := httpx.ParseAllowlist(list)
		cerr := connector.ValidateInfo(connector.Info{ID: "fournisseur", Name: "Fournisseur", AllowedDomains: list})
		if (herr == nil) != wantValid {
			t.Errorf("httpx.ParseAllowlist(%q) error = %v, want valid=%v", list, herr, wantValid)
		}
		if (cerr == nil) != wantValid {
			t.Errorf("connector.ValidateInfo(AllowedDomains %q) error = %v, want valid=%v", list, cerr, wantValid)
		}
	}
	for _, l := range validAllowlists {
		check(l, true)
	}
	for _, l := range invalidAllowlists {
		check(l, false)
	}
}
