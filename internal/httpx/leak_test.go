package httpx_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// chain returns every error reachable through Unwrap() error and
// Unwrap() []error.
func chain(err error) []error {
	var out []error
	stack := []error{err}
	for len(stack) > 0 {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if e == nil {
			continue
		}
		out = append(out, e)
		if u, ok := e.(interface{ Unwrap() error }); ok {
			stack = append(stack, u.Unwrap())
		}
		if u, ok := e.(interface{ Unwrap() []error }); ok {
			stack = append(stack, u.Unwrap()...)
		}
	}
	return out
}

// TestClient_ErrorOmitsCanaryFromURLAndHeaders drives every failure mode with
// canaries in the query, fragment, userinfo and headers. Neither the error
// message nor any error in its chain may contain a canary. Every message is
// written under ArtifactDir for make leakcheck.
func TestClient_ErrorOmitsCanaryFromURLAndHeaders(t *testing.T) {
	t.Parallel()
	query := testsecrets.Canary(t, testsecrets.Token)
	frag := testsecrets.Canary(t, testsecrets.Token)
	userPW := testsecrets.Canary(t, testsecrets.Password)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	bearer := testsecrets.Canary(t, testsecrets.Session)
	canaries := []string{query, frag, userPW, cookie, bearer}

	slow := make(chan struct{})
	t.Cleanup(func() { close(slow) })
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-evil":
			http.Redirect(w, r, "https://evil.test/steal?tok="+query+"#"+frag, http.StatusFound)
		case "/to-http":
			http.Redirect(w, r, "http://fournisseur.test/x?tok="+query, http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop?tok="+query, http.StatusFound)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-slow:
			}
		default:
			ok(w, r)
		}
	})
	allowed := []string{"fournisseur.test"}

	base := e.opts()
	untrusted := e.opts()
	untrusted.RootCAs = nil
	dialFail := e.opts()
	dialFail.DialContext = failingDial
	fast := e.opts()
	fast.Timeout = 100 * time.Millisecond

	q := "?tok=" + query + "&page=2#" + frag
	cases := []struct {
		name string
		opts httpx.Options
		url  string
	}{
		{name: "disallowed domain", opts: base, url: "https://evil.test/collect" + q},
		{name: "disallowed with userinfo", opts: base, url: "https://someone:" + userPW + "@evil.test/" + q},
		{name: "allowed with userinfo then dial failure", opts: dialFail, url: "https://someone:" + userPW + "@fournisseur.test/" + q},
		{name: "plain http", opts: base, url: "http://fournisseur.test/" + q},
		{name: "untrusted certificate", opts: untrusted, url: "https://fournisseur.test/" + q},
		{name: "dial failure", opts: dialFail, url: "https://fournisseur.test/a/b" + q},
		{name: "redirect off allowlist", opts: base, url: "https://fournisseur.test/to-evil" + q},
		{name: "redirect to http", opts: base, url: "https://fournisseur.test/to-http" + q},
		{name: "redirect loop", opts: base, url: "https://fournisseur.test/loop" + q},
		{name: "timeout", opts: fast, url: "https://fournisseur.test/slow" + q},
	}

	var report strings.Builder
	for _, tc := range cases {
		c := mustNew(t, allowed, tc.opts)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tc.url, http.NoBody)
		if err != nil {
			t.Fatalf("%s: NewRequest: %v", tc.name, err)
		}
		req.Header.Set("Cookie", "sid="+cookie)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("X-Api-Token", bearer)
		resp, err := c.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Errorf("%s: Do succeeded, want an error", tc.name)
			continue
		}
		recordChain(t, &report, tc.name, err, canaries)
	}

	// Malformed URL through Get.
	resp, err := mustNew(t, allowed, base).Get(t.Context(), "https://fournisseur.test/%zz?tok="+query)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Error("Get(malformed): nil error")
	} else {
		recordChain(t, &report, "malformed url", err, canaries)
	}

	writeArtifact(t, "httpx-errors.txt", report.String())
}

func recordChain(t *testing.T, report *strings.Builder, name string, err error, canaries []string) {
	t.Helper()
	for i, e := range chain(err) {
		msg := e.Error()
		fmt.Fprintf(report, "%s[%d]\t%T\t%s\n", name, i, e, msg)
		for _, c := range canaries {
			if strings.Contains(msg, c) {
				t.Errorf("%s: error chain[%d] (%T) contains a canary (message not printed)", name, i, e)
			}
		}
	}
	if s := fmt.Sprintf("%+v", err); containsAny(s, canaries) {
		t.Errorf("%s: %%+v of the error contains a canary (message not printed)", name)
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func writeArtifact(t *testing.T, name, content string) {
	t.Helper()
	r, err := fsx.Open(testsecrets.ArtifactDir(t))
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, []byte(content)); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
}
