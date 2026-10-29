package httpx_test

import (
	"context"
	"errors"
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

	slow := newSlowRoute()
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/to-evil":
			http.Redirect(w, r, "https://evil.test/steal?tok="+query+"#"+frag, http.StatusFound)
		case "/to-http":
			http.Redirect(w, r, "http://fournisseur.test/x?tok="+query, http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop?tok="+query, http.StatusFound)
		case "/slow":
			slow.serve(w, r)
		default:
			ok(w, r)
		}
	})
	slow.releaseAtCleanup(t) // after newEnv: runs before the server's Close
	allowed := []string{"fournisseur.test"}

	base := e.opts()
	untrusted := e.opts()
	untrusted.RootCAs = nil
	dialFail := e.opts()
	dialFail.DialContext = failingDial
	// The timeout case reaches its deadline through expireOnArrival once
	// the request is blocked in /slow; Timeout is only a safety net.
	fast := e.opts()
	fast.Timeout = time.Minute

	q := "?tok=" + query + "&page=2#" + frag
	cases := []struct {
		name     string
		opts     httpx.Options
		url      string
		deadline bool // send with expireOnArrival; want DeadlineExceeded
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
		{name: "timeout", opts: fast, url: "https://fournisseur.test/slow" + q, deadline: true},
	}

	var report strings.Builder
	for _, tc := range cases {
		c := mustNew(t, allowed, tc.opts)
		ctx := t.Context()
		if tc.deadline {
			ctx = expireOnArrival(t, slow)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tc.url, http.NoBody)
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
		if tc.deadline && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: error is not context.DeadlineExceeded (message not printed)", tc.name)
		}
		recordChain(t, &report, tc.name, err, canaries)
	}

	if n := slow.hits.Load(); n != 1 {
		t.Errorf("/slow hit %d times, want 1", n)
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
