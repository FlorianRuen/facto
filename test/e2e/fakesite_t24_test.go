//go:build e2e

package e2e

// Unit tests of the fake site's hostile login pages (J1 T24, A11): every
// login page tries to reach evil.test through each kind of subresource a
// page can start (img, fetch, WebSocket, a dedicated worker), and shows its
// form only once every attempt has settled, so the browser-allowlist
// scenario cannot pass because the login won a race against them. No
// browser and no facto binary: the markup and the worker script are checked
// as served.

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// hiddenFormRE matches a <form> start tag with id login-form (or the
// site-changed signin-form) carrying the boolean hidden attribute.
var hiddenFormRE = regexp.MustCompile(`<form\b[^>]*\bid="(login-form|signin-form)"[^>]*\shidden(\s|>|=)`)

func TestFakeSite_LoginPagesTryEveryOffAllowlistKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mode     string
		host     string
		path     string
		gateForm bool // a form page: the form stays hidden until the attempts settle
	}{
		{name: "password form", mode: ModePassword, host: HostWWW, path: "/login", gateForm: true},
		{name: "expired-session form", mode: ModeExpiredSession, host: HostWWW, path: "/login", gateForm: true},
		{name: "sso form", mode: ModeSSORedirect, host: HostSSO, path: "/login", gateForm: true},
		{name: "site-changed form", mode: ModeSiteChanged, host: HostWWW, path: "/login", gateForm: true},
		{name: "captcha page", mode: ModeCaptcha, host: HostWWW, path: "/login/captcha"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := unitSite(t, tt.mode)
			resp, body := get(t, s.Client(t), "https://"+tt.host+tt.path)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			for _, want := range []struct{ kind, marker string }{
				{"img", `src="https://` + EvilHost + `/`},
				{"fetch", `fetch("https://` + EvilHost + `/`},
				{"websocket", `new WebSocket("wss://` + EvilHost + `/`},
				{"worker", `new Worker("` + workerPath + `"`},
			} {
				if !strings.Contains(body, want.marker) {
					t.Errorf("%s: page does not try evil.test through %s (want %q in the page):\n%s", tt.path, want.kind, want.marker, body)
				}
			}
			if tt.gateForm && !hiddenFormRE.MatchString(body) {
				t.Errorf("%s: the form is visible before the off-allowlist attempts settle (want a hidden attribute on it):\n%s", tt.path, body)
			}
		})
	}
}

func TestFakeSite_WorkerScriptTriesEvilFromInside(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mode string
		host string
	}{
		{name: "www", mode: ModePassword, host: HostWWW},
		{name: "sso host in sso-redirect mode", mode: ModeSSORedirect, host: HostSSO},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := unitSite(t, tt.mode)
			resp, body := get(t, s.Client(t), "https://"+tt.host+workerPath)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s%s status = %d, want 200", tt.host, workerPath, resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
				t.Errorf("Content-Type = %q, want text/javascript", ct)
			}
			if !strings.Contains(body, `fetch("https://`+EvilHost+`/`) {
				t.Errorf("worker script does not fetch evil.test:\n%s", body)
			}
			// The worker reports back so the page can reveal its form.
			if !strings.Contains(body, "postMessage(") {
				t.Errorf("worker script never reports to the page (postMessage):\n%s", body)
			}
			if got := s.Requests(); len(got) != 1 || got[0].Host != tt.host || got[0].Path != workerPath {
				t.Errorf("worker script request not logged on %s: %+v", tt.host, got)
			}
		})
	}
}

// The worker script is no way around the API guards: it is a static
// script, served without a session and never on the off-allowlist host.
func TestFakeSite_WorkerScriptNegative(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mode     string
		host     string
		path     string
		wantCode int
	}{
		{name: "never served by evil.test", mode: ModePassword, host: EvilHost, path: workerPath, wantCode: http.StatusOK},
		{name: "no POST", mode: ModePassword, host: HostWWW, path: workerPath, wantCode: http.StatusNotFound},
		{name: "sso host outside sso-redirect mode", mode: ModePassword, host: HostSSO, path: workerPath, wantCode: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := unitSite(t, tt.mode)
			c := s.Client(t)
			var resp *reply
			var body string
			if tt.name == "no POST" {
				resp, body = postForm(t, c, "https://"+tt.host+tt.path, nil)
			} else {
				resp, body = get(t, c, "https://"+tt.host+tt.path)
			}
			if resp.StatusCode != tt.wantCode {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantCode)
			}
			if tt.host == EvilHost && strings.Contains(body, "postMessage(") {
				t.Errorf("evil.test served the worker script: it must only ever answer the inert GIF")
			}
			if resp.Header.Get("Set-Cookie") != "" {
				t.Errorf("worker script response sets a cookie")
			}
		})
	}
}
