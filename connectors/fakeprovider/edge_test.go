package fakeprovider_test

// Edge cases of the T20 HTTP side not pinned by the plan's named tests:
// login stub, session construction guards, Persist/Restore refusals, and
// status/body corners of Probe and Fetch.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/connectors/fakeprovider"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
)

func TestLogin_NotImplementedUntilT21(t *testing.T) {
	t.Parallel()
	sess, err := fakeprovider.New(fakeprovider.Options{}).Login(t.Context(), connector.Env{})
	if !errors.Is(err, fakeprovider.ErrLoginNotImplemented) || sess != nil {
		t.Fatalf("Login = %v, %v; want nil, ErrLoginNotImplemented", sess, err)
	}
}

func TestSession_RendersPlaceholderOnly(t *testing.T) {
	t.Parallel()
	ck := canaryCookie(t)
	s := newSite(t, http.NotFound)
	sess := s.session(t, ck)
	for _, out := range []string{sess.String(), sess.GoString(), fmt.Sprintf("%x %v %d", sess, sess, sess), rendered(sess)} {
		if strings.Contains(out, ck) || !strings.Contains(out, secret.Masked) {
			t.Fatalf("session renders %q", out)
		}
	}
}

func TestNewSession_RefusesInvalidCookies(t *testing.T) {
	t.Parallel()
	s := newSite(t, http.NotFound)
	if _, err := fakeprovider.NewSession(nil, nil); err == nil {
		t.Error("NewSession(nil client) succeeded")
	}
	tok := canaryCookie(t)
	cases := map[string]func(c *connector.Cookie){
		"empty name":     func(c *connector.Cookie) { c.Name = "" },
		"name with semi": func(c *connector.Cookie) { c.Name = "a;b" },
		"value with semi": func(c *connector.Cookie) {
			c.Value = secret.FromString(tok + ";x")
		},
		"empty value":   func(c *connector.Cookie) { c.Value = secret.Secret{} },
		"relative path": func(c *connector.Cookie) { c.Path = "api" },
	}
	for name, mutate := range cases {
		c := sessionCookie(tok)
		mutate(&c)
		_, err := fakeprovider.NewSession(s.client(t), []connector.Cookie{c})
		if err == nil {
			t.Errorf("%s: NewSession accepted the cookie", name)
			continue
		}
		if strings.Contains(err.Error(), tok) {
			t.Errorf("%s: error echoes the cookie value", name)
		}
	}
	// A leading dot and letter case designate the same allowed host.
	c := sessionCookie(tok)
	c.Domain = ".WWW.fakeprovider.test"
	sess, err := fakeprovider.NewSession(s.client(t), []connector.Cookie{c})
	if err != nil {
		t.Fatalf("NewSession(.WWW host): %v", err)
	}
	if _, err := sess.Persist(t.Context()); err != nil {
		t.Fatalf("Persist after a dotted domain: %v", err)
	}
}

func TestPersist_WithoutCookieNeedsLogin(t *testing.T) {
	t.Parallel()
	s := newSite(t, http.NotFound)
	foreign := sessionCookie(canaryCookie(t))
	foreign.Domain = evilHost
	sess, err := fakeprovider.NewSession(s.client(t), []connector.Cookie{foreign})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := sess.Persist(t.Context()); !errors.Is(err, connector.ErrNeedsLogin) {
		t.Fatalf("Persist with no allowed cookie = %v, want ErrNeedsLogin", err)
	}
	var nilSess *fakeprovider.Session
	if _, err := nilSess.Persist(t.Context()); err == nil {
		t.Fatal("Persist on a nil session succeeded")
	}
}

func TestRestore_RefusesEveryOddBlob(t *testing.T) {
	t.Parallel()
	s := newSite(t, http.NotFound)
	tok := canaryCookie(t)
	if _, err := fakeprovider.Restore(nil, secret.FromString("{}")); err == nil {
		t.Error("Restore(nil client) succeeded")
	}
	ok := `{"name":"fp_session","value":"` + tok + `","domain":"www.fakeprovider.test","path":"/"}`
	cases := map[string]string{
		"version 2":      `{"v":2,"cookies":[` + ok + `]}`,
		"no cookies":     `{"v":1,"cookies":[]}`,
		"trailing data":  `{"v":1,"cookies":[` + ok + `]} {}`,
		"unknown member": `{"v":1,"cookies":[` + ok + `],"x":1}`,
		"dotted domain":  `{"v":1,"cookies":[{"name":"fp_session","value":"` + tok + `","domain":".www.fakeprovider.test","path":"/"}]}`,
		"bad name":       `{"v":1,"cookies":[{"name":"a b","value":"` + tok + `","domain":"www.fakeprovider.test","path":"/"}]}`,
		"bad value":      `{"v":1,"cookies":[{"name":"fp_session","value":"` + tok + ` x","domain":"www.fakeprovider.test","path":"/"}]}`,
		"no path":        `{"v":1,"cookies":[{"name":"fp_session","value":"` + tok + `","domain":"www.fakeprovider.test","path":""}]}`,
	}
	for name, b := range cases {
		_, err := fakeprovider.Restore(s.client(t), secret.FromString(b))
		if !errors.Is(err, connector.ErrNeedsLogin) {
			t.Errorf("%s: Restore = %v, want ErrNeedsLogin", name, err)
			continue
		}
		if strings.Contains(rendered(err), tok) {
			t.Errorf("%s: error echoes the blob", name)
		}
	}
	if hits := s.hitList(); len(hits) != 0 {
		t.Fatalf("Restore contacted the site: %q", hits)
	}
}

func TestProbe_BodyCorners(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		status int
		body   string
		want   error
	}{
		"500":            {status: http.StatusInternalServerError, body: `{}`, want: connector.ErrBroken},
		"empty account":  {status: http.StatusOK, body: `{"account":""}`, want: connector.ErrBroken},
		"unknown member": {status: http.StatusOK, body: `{"account":"ACC-1","debug":1}`, want: connector.ErrBroken},
		"wrong type":     {status: http.StatusOK, body: `{"account":1}`, want: connector.ErrBroken},
		"empty body":     {status: http.StatusOK, body: ``, want: connector.ErrBroken},
		"trailing token": {status: http.StatusOK, body: `{"account":"ACC-1"} 1`, want: connector.ErrBroken},
		"trailing junk":  {status: http.StatusOK, body: `{"account":"ACC-1"} }`, want: connector.ErrBroken},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newSite(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			err := fakeprovider.New(fakeprovider.Options{}).Probe(t.Context(), s.session(t, canaryCookie(t)))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Probe = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestFetch_CapSmallerThanMagic(t *testing.T) {
	t.Parallel()
	ck := canaryCookie(t)
	s := pdfSite(t, ck, "application/pdf", syntheticPDF, true)
	rc, err := fakeprovider.New(fakeprovider.Options{MaxPDFBytes: 3}).Fetch(t.Context(), s.session(t, ck), pdfRef(pdfID))
	if err == nil {
		_ = rc.Close()
		t.Fatal("Fetch accepted a body over a 3-byte cap")
	}
	if !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Fatalf("Fetch = %v, want httpx.ErrBodyTooLarge", err)
	}
}

func TestList_DeclaredLengthOverCap(t *testing.T) {
	t.Parallel()
	ck := canaryCookie(t)
	page := `{"invoices":[],"next_page":null}` + strings.Repeat(" ", 1024)
	pl := &pagedList{cookie: ck, pages: []string{page}}
	s := newSite(t, pl.handler(t))
	_, err := fakeprovider.New(fakeprovider.Options{MaxListBytes: 64}).List(t.Context(), s.session(t, ck), year2025)
	if !errors.Is(err, connector.ErrBroken) || !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Fatalf("List = %v, want ErrBroken and httpx.ErrBodyTooLarge", err)
	}
}
