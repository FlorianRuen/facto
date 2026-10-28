package httpx_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/httpx"
)

func TestLimitBody_NegativeLimitActsAsZero(t *testing.T) {
	t.Parallel()
	_, err := io.ReadAll(httpx.LimitBody(io.NopCloser(strings.NewReader("x")), -5))
	if !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Fatalf("ReadAll error = %v, want ErrBodyTooLarge", err)
	}
	got, err := io.ReadAll(httpx.LimitBody(io.NopCloser(bytes.NewReader(nil)), -5))
	if err != nil || len(got) != 0 {
		t.Fatalf("empty body = %q, %v; want nothing, nil", got, err)
	}
}

// errReader fails every read with a non-EOF error.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errReader) Close() error             { return io.ErrClosedPipe }

func TestLimitBody_PropagatesReadAndCloseErrors(t *testing.T) {
	t.Parallel()
	lb := httpx.LimitBody(errReader{}, 10)
	if _, err := lb.Read(make([]byte, 4)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("Read error = %v, want io.ErrUnexpectedEOF in the chain", err)
	}
	if err := lb.Close(); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Close error = %v, want io.ErrClosedPipe in the chain", err)
	}
}

// A malformed Location header makes net/http quote the raw header (query
// included) in its error: httpx must withhold that cause.
func TestClient_MalformedLocationNotEchoed(t *testing.T) {
	t.Parallel()
	const marker = "zz-location-marker"
	e := newEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://fournisseur.test/%zz?tok="+marker)
		w.WriteHeader(http.StatusFound)
	})
	_, _, err := get(t, e.client(t, "fournisseur.test"), "https://fournisseur.test/start")
	if err == nil {
		t.Fatal("malformed Location: nil error")
	}
	for _, ce := range chain(err) {
		if strings.Contains(ce.Error(), marker) {
			t.Errorf("error chain echoes the Location header: %T", ce)
		}
	}
	if !strings.Contains(err.Error(), "fournisseur.test") {
		t.Errorf("error %q does not name the host", err)
	}
}

// An empty userinfo username must not make every error look like a leak:
// the dial failure cause stays in the chain.
func TestClient_EmptyUsernameKeepsCause(t *testing.T) {
	t.Parallel()
	c := mustNew(t, []string{"fournisseur.test"}, httpx.Options{DialContext: failingDial})
	_, _, err := get(t, c, "https://:zz-pw-marker@fournisseur.test/")
	if err == nil || !strings.Contains(err.Error(), "synthetic refusal") {
		t.Fatalf("error = %v, want the dial cause kept", err)
	}
	if strings.Contains(err.Error(), "zz-pw-marker") {
		t.Errorf("error %q echoes the userinfo", err)
	}
}

func TestClient_DoRejectsNilRequest(t *testing.T) {
	t.Parallel()
	c := mustNew(t, []string{"fournisseur.test"}, httpx.Options{})
	for name, req := range map[string]*http.Request{"nil request": nil, "nil url": {}} {
		resp, err := c.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Errorf("Do(%s) = nil error", name)
		}
	}
}
