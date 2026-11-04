// Tests for J1 task T9 (feat(browser): allowlist enforcement inside the
// browser), ADR 0008 "Hardening / In-browser allowlist (A11)" and "Tests
// required" (T9). The browser is the scripted peer of fakecdp_test.go.
//
// Expected behaviour of NewPage and Page (page.go), written before the
// implementation:
//
//	// NewPage setup, after Target.attachToTarget and before returning (it
//	// still never navigates):
//	//   - Target.setAutoAttach {autoAttach:true, waitForDebuggerOnStart:true,
//	//     flatten:true} on the page session (OOPIFs, dedicated and service
//	//     workers) AND on the browser session (pop-ups, opened as new page
//	//     targets);
//	//   - Fetch.enable {patterns:[{urlPattern:"*"}]} on the page session
//	//     (requestStage absent or "Request"), with the page subscribed to
//	//     Fetch.requestPaused (FailClosed) first.
//	//   A failure of either fails NewPage and disposes the context.
//	//
//	// Target.attachedToTarget {sessionId, targetInfo{targetId,type},
//	// waitingForDebugger:true} for a target of the login context:
//	//   1. Fetch.enable {patterns:[{urlPattern:"*"}]} on the child session
//	//      (plus Target.setAutoAttach with the same flags for "page" and
//	//      "iframe" children, for nested frames);
//	//   2. only then Runtime.runIfWaitingForDebugger on the child session.
//	//   If a step of 1 fails, the target is closed (Target.closeTarget
//	//   {targetId} on the browser session) and never resumed.
//	//
//	// Fetch.requestPaused on the page or a child session:
//	//   - allowed: Fetch.continueRequest {requestId} on the same session,
//	//     without url, method, postData or headers;
//	//   - otherwise Fetch.failRequest {requestId, errorReason:"BlockedByClient"}
//	//     on the same session, never continueRequest.
//	//   Allowed means: request.url parses, scheme "https", no userinfo, not an
//	//   IP literal, and httpx.Allowlist.Allows(u.Host) for the page
//	//   allowlist (the same code as internal/httpx: port 443 only, ASCII
//	//   case-insensitive, no trailing dot, no IDN). Anything else, including
//	//   an undecodable request, http:, ws:, data:, blob: and about:, fails
//	//   closed.
//	//
//	// BlockedHosts returns a copy of the number of failed requests per
//	// lowercased host (no scheme, port, path, query or fragment); requests
//	// without a parsable host are counted under "". Logs name at most the
//	// host, never the path, query, headers or post data.
//	func (p *Page) BlockedHosts() map[string]int
package browser_test

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// autoAttachFlags reports whether c is Target.setAutoAttach with the
// flags ADR 0008 requires.
func autoAttachFlags(c cdpCall) bool {
	return c.Method == "Target.setAutoAttach" && c.Params["autoAttach"] == true &&
		c.Params["waitForDebuggerOnStart"] == true && c.Params["flatten"] == true
}

// fetchEnableAll reports whether c is Fetch.enable intercepting every URL
// at the request stage.
func fetchEnableAll(c cdpCall) bool {
	if c.Method != "Fetch.enable" {
		return false
	}
	pats, ok := c.Params["patterns"].([]any)
	if !ok {
		return false
	}
	for _, p := range pats {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		stage, has := m["requestStage"]
		if m["urlPattern"] == "*" && (!has || stage == "Request") {
			return true
		}
	}
	return false
}

// blocked waits for the failRequest of requestID on session and checks it.
func blocked(t *testing.T, f *fakeCDP, session, requestID string) {
	t.Helper()
	got := f.waitCalls(t, 1, isCall("Fetch.failRequest", session, requestID))
	if r := got[0].Params["errorReason"]; r != "BlockedByClient" {
		t.Errorf("failRequest %s errorReason = %v, want BlockedByClient", requestID, r)
	}
}

// continued waits for the continueRequest of requestID on session and
// checks it carries no override.
func continued(t *testing.T, f *fakeCDP, session, requestID string) {
	t.Helper()
	got := f.waitCalls(t, 1, isCall("Fetch.continueRequest", session, requestID))
	for _, k := range []string{"url", "method", "postData", "headers"} {
		if _, ok := got[0].Params[k]; ok {
			t.Errorf("continueRequest %s overrides %q: %v", requestID, k, got[0].Params)
		}
	}
}

// neverContinued checks no continueRequest went out for requestID, after a
// later allowed request on the same session was continued (the decision
// for requestID was made before it).
func neverContinued(t *testing.T, f *fakeCDP, session, requestID string) {
	t.Helper()
	f.requestPaused(session, "sentinel-"+requestID, "https://login.supplier.example/ok", "Script", nil)
	continued(t, f, session, "sentinel-"+requestID)
	for _, c := range f.snapshot() {
		if c.Method == "Fetch.continueRequest" && c.Params["requestId"] == requestID {
			t.Errorf("continueRequest sent for blocked request %s", requestID)
		}
	}
}

func TestFetch_BlocksOffAllowlistSubresource(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		url, resourceType string
	}{
		{"https://evil.test/x.js", "Script"},
		{"https://evil.test/pixel.gif", "Image"},
		{"https://evil.test/api", "XHR"},
		{"https://evil.test/api", "Fetch"},
		{"https://evil.test/beacon", "Ping"},
		{"https://evil.test/stream", "EventSource"},
		{"https://cdn.evil.test/font.woff2", "Font"},
		{"https://evil.test/", "Document"},
		{"https://supplier.example.evil.test/", "Script"},
	} {
		t.Run(tc.resourceType+" "+tc.url, func(t *testing.T) {
			t.Parallel()
			e := newPage(t)
			e.navigate(t, loginURL)
			e.f.requestPaused(fakeSessionID, "req-1", tc.url, tc.resourceType, nil)
			blocked(t, e.f, fakeSessionID, "req-1")
			neverContinued(t, e.f, fakeSessionID, "req-1")
		})
	}
}

func TestFetch_BlocksOffAllowlistRedirect(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.navigate(t, loginURL)
	// The allowlisted document is let through, then the server redirects
	// it off the list: Chrome pauses the redirected request again.
	e.f.requestPaused(fakeSessionID, "doc-1", loginURL, "Document", nil)
	continued(t, e.f, fakeSessionID, "doc-1")
	e.f.requestPaused(fakeSessionID, "doc-2", "https://evil.test/phish?from=login", "Document", map[string]any{
		"redirectedRequestId": "doc-1",
		"networkId":           "net-doc-1",
	})
	blocked(t, e.f, fakeSessionID, "doc-2")
	neverContinued(t, e.f, fakeSessionID, "doc-2")

	t.Run("redirect to http on an allowlisted host", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.requestPaused(fakeSessionID, "doc-3", "http://login.supplier.example/login", "Document", map[string]any{
			"redirectedRequestId": "doc-0",
		})
		blocked(t, e.f, fakeSessionID, "doc-3")
	})
}

func TestFetch_AllowsAllowlistedHTTPS(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.navigate(t, loginURL)
	for i, u := range []string{
		loginURL,
		"https://supplier.example/",
		"https://static.supplier.example/app.js?v=1",
		"https://LOGIN.Supplier.Example/x",
		"https://login.supplier.example:443/x",
	} {
		id := fmt.Sprintf("ok-%d", i)
		e.f.requestPaused(fakeSessionID, id, u, "Script", nil)
		continued(t, e.f, fakeSessionID, id)
	}
	if fails := filter(e.f.snapshot(), "Fetch.failRequest"); len(fails) != 0 {
		t.Errorf("allowlisted requests failed: %v", fails)
	}
	if got := e.p.BlockedHosts(); len(got) != 0 {
		t.Errorf("BlockedHosts = %v, want empty", got)
	}
}

func TestFetch_BlockedHostsReportedWithoutQuery(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Token)
	e := newPage(t)
	e.navigate(t, loginURL)
	reqs := []string{
		"https://evil.test/collect/" + canary + "?token=" + canary + "#" + canary,
		"https://EVIL.test/collect?session=" + canary,
		"https://evil.test:8443/c?x=" + canary,
		"https://tracker.test/p.gif?uid=" + canary,
		"http://login.supplier.example/?q=" + canary,
	}
	for i, u := range reqs {
		e.f.requestPaused(fakeSessionID, fmt.Sprintf("b-%d", i), u, "Image", map[string]any{
			"request": map[string]any{
				"url": u, "method": "POST", "postData": "secret=" + canary,
				"headers": map[string]any{"Cookie": "sid=" + canary, "Authorization": "Bearer " + canary},
			},
		})
	}
	for i := range reqs {
		blocked(t, e.f, fakeSessionID, fmt.Sprintf("b-%d", i))
	}
	got := e.p.BlockedHosts()
	want := map[string]int{"evil.test": 3, "tracker.test": 1, "login.supplier.example": 1}
	if !maps.Equal(got, want) {
		t.Errorf("BlockedHosts = %v, want %v (host only, lowercased, no port)", got, want)
	}
	for h := range got {
		if strings.ContainsAny(h, "/?#=:@") || strings.Contains(h, canary) {
			t.Errorf("BlockedHosts key %q carries more than a host", h)
		}
	}
	got["evil.test"] = 1000
	if again := e.p.BlockedHosts(); again["evil.test"] != 3 {
		t.Errorf("BlockedHosts returned its internal map (mutation visible: %v)", again)
	}
	logs := e.logs.String()
	for _, leak := range []string{canary, "/collect", "token=", "uid=", "Bearer", "sid="} {
		if strings.Contains(logs, leak) {
			t.Errorf("logs carry %q (path, query, header or body): %s", leak, logs)
		}
	}
}

func TestFetch_BlocksOffAllowlistBeforeFirstNavigation(t *testing.T) {
	t.Parallel()

	t.Run("setup order", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		setup := e.f.snapshot()
		iTgt := index(setup, "Target.createTarget")
		iAtt := index(setup, "Target.attachToTarget")
		iFetch := slices.IndexFunc(setup, func(c cdpCall) bool { return fetchEnableAll(c) && c.Session == fakeSessionID })
		iAuto := slices.IndexFunc(setup, func(c cdpCall) bool { return autoAttachFlags(c) && c.Session == fakeSessionID })
		iAutoBrowser := slices.IndexFunc(setup, func(c cdpCall) bool { return autoAttachFlags(c) && c.Session == "" })
		if iFetch < 0 {
			t.Fatalf("NewPage sent no Fetch.enable {patterns:[{urlPattern:\"*\"}]} on the page session: %q", methods(setup))
		}
		if iAuto < 0 {
			t.Errorf("NewPage sent no Target.setAutoAttach {autoAttach, waitForDebuggerOnStart, flatten} on the page session: %q", methods(setup))
		}
		if iAutoBrowser < 0 {
			t.Errorf("NewPage sent no Target.setAutoAttach {autoAttach, waitForDebuggerOnStart, flatten} on the browser session (pop-ups): %q", methods(setup))
		}
		if iTgt >= iAtt || iAtt >= iFetch {
			t.Errorf("order = %q; want createTarget(about:blank), attachToTarget, then Fetch.enable", methods(setup))
		}
		if index(setup, "Page.navigate") >= 0 {
			t.Errorf("NewPage navigated: %q", methods(setup))
		}
		m := e.f.mark()
		e.navigate(t, loginURL)
		if i := index(e.f.since(m), "Fetch.enable"); i >= 0 {
			t.Errorf("Fetch.enable sent again at navigation; it must be on before the first one")
		}
	})

	t.Run("request paused before any Navigate is failed", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.f.requestPaused(fakeSessionID, "early", "https://evil.test/preload", "Document", nil)
		blocked(t, e.f, fakeSessionID, "early")
		if e.p.BlockedHosts()["evil.test"] != 1 {
			t.Errorf("BlockedHosts = %v, want evil.test counted", e.p.BlockedHosts())
		}
	})

	for _, method := range []string{"Fetch.enable", "Target.setAutoAttach"} {
		t.Run(method+" failure fails NewPage and disposes the context", func(t *testing.T) {
			t.Parallel()
			f, c, opts, _ := newEnv(t)
			f.setOverride(method, func(cdpCall) any { return &cdpErr{code: -32000} })
			p, err := browser.NewPage(testCtx(t), c, opts)
			if err == nil {
				_ = p.Close()
				t.Fatalf("NewPage = nil error with %s failing, want it to fail closed", method)
			}
			disp := filter(f.snapshot(), "Target.disposeBrowserContext")
			if len(disp) != 1 {
				t.Errorf("disposeBrowserContext calls = %d, want 1", len(disp))
			}
			if index(f.snapshot(), "Page.navigate") >= 0 {
				t.Error("navigated although the allowlist is not enforced")
			}
		})
	}
}

// childCase drives one auto-attached target type.
type childCase struct {
	typ string
	// parent is the session the attach event arrives on.
	parent string
	extra  map[string]any
	// nested: the child must get setAutoAttach too (frames and pages).
	nested bool
}

func runChildBlocked(t *testing.T, cc childCase) {
	t.Helper()
	const child, target = "sess-child-1", "tgt-child-1"

	t.Run("fetch enabled before resume, off-list request failed", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.attachChild(cc.parent, child, target, cc.typ, cc.extra)
		e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", child, ""))
		calls := e.f.snapshot()
		iEnable := slices.IndexFunc(calls, func(c cdpCall) bool { return fetchEnableAll(c) && c.Session == child })
		iResume := slices.IndexFunc(calls, func(c cdpCall) bool {
			return c.Method == "Runtime.runIfWaitingForDebugger" && c.Session == child
		})
		if iEnable < 0 || iEnable > iResume {
			t.Fatalf("%s: Fetch.enable on the child (%d) must come before runIfWaitingForDebugger (%d): %q",
				cc.typ, iEnable, iResume, methods(calls))
		}
		if cc.nested {
			iAuto := slices.IndexFunc(calls, func(c cdpCall) bool { return autoAttachFlags(c) && c.Session == child })
			if iAuto < 0 || iAuto > iResume {
				t.Errorf("%s: no Target.setAutoAttach on the child before resume: %q", cc.typ, methods(calls))
			}
		}
		e.f.requestPaused(child, "c-1", "https://evil.test/ws-fallback?x=1", "XHR", nil)
		blocked(t, e.f, child, "c-1")
		neverContinued(t, e.f, child, "c-1")
		if e.p.BlockedHosts()["evil.test"] != 1 {
			t.Errorf("BlockedHosts = %v, want the child's block counted", e.p.BlockedHosts())
		}
	})

	t.Run("enable failure closes the target, never resumes it", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setOverride("Fetch.enable", func(c cdpCall) any {
			if c.Session == child {
				return &cdpErr{code: -32000}
			}
			return map[string]any{}
		})
		e.f.attachChild(cc.parent, child, target, cc.typ, cc.extra)
		closed := e.f.waitCalls(t, 1, func(c cdpCall) bool {
			return c.Method == "Target.closeTarget" && c.Params["targetId"] == target
		})
		if s := closed[0].Session; s != "" {
			t.Errorf("closeTarget sent on session %q, want the browser session", s)
		}
		for _, c := range filter(e.f.snapshot(), "Runtime.runIfWaitingForDebugger") {
			if c.Session == child {
				t.Errorf("%s resumed although Fetch.enable failed on it", cc.typ)
			}
		}
	})
}

func TestFetch_BlocksOffAllowlistInOOPIF(t *testing.T) {
	t.Parallel()
	runChildBlocked(t, childCase{typ: "iframe", parent: fakeSessionID, nested: true})
}

func TestFetch_BlocksOffAllowlistInWorker(t *testing.T) {
	t.Parallel()
	// Dedicated workers can start nested workers: they get auto-attach too.
	runChildBlocked(t, childCase{typ: "worker", parent: fakeSessionID, nested: true})
}

func TestFetch_BlocksOffAllowlistInServiceWorker(t *testing.T) {
	t.Parallel()
	runChildBlocked(t, childCase{typ: "service_worker", parent: fakeSessionID})
}

func TestFetch_BlocksOffAllowlistInPopup(t *testing.T) {
	t.Parallel()
	// Pop-ups are new page targets: the browser-level auto-attach reports
	// them on the browser session.
	runChildBlocked(t, childCase{typ: "page", parent: "", nested: true, extra: map[string]any{"openerId": fakeTargetID}})
}

// TestFetch_MatcherSharedWithHttpx: the in-browser decision for a URL is
// the httpx one (https, no userinfo, no IP literal, Allowlist.Allows on
// the host) for every URL-confusion trick.
func TestFetch_MatcherSharedWithHttpx(t *testing.T) {
	t.Parallel()
	allow, err := httpx.ParseAllowlist(testAllow)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		url   string
		allow bool
	}{
		{"exact host", "https://supplier.example/", true},
		{"wildcard subdomain", "https://login.supplier.example/a", true},
		{"upper case host", "https://LOGIN.SUPPLIER.EXAMPLE/a", true},
		{"explicit 443", "https://login.supplier.example:443/a", true},
		{"other port", "https://login.supplier.example:8443/a", false},
		{"zero-padded port", "https://login.supplier.example:0443/a", false},
		{"empty port", "https://login.supplier.example:/a", false},
		{"trailing dot", "https://login.supplier.example./a", false},
		{"userinfo on allowed host", "https://user@login.supplier.example/", false},
		{"userinfo hiding evil host", "https://login.supplier.example@evil.test/", false},
		{"user and pass", "https://a:b@login.supplier.example/", false},
		{"suffix confusion", "https://login.supplier.example.evil.test/", false},
		{"lookalike label", "https://loginsupplier.example/", false},
		{"allowed host in path", "https://evil.test/login.supplier.example", false},
		{"allowed host in query", "https://evil.test/?h=login.supplier.example", false},
		{"backslash", "https://evil.test\\@login.supplier.example/", false},
		{"escaped host", "https://login%2esupplier.example/", false},
		{"IDN unicode", "https://login.süpplier.example/", false},
		{"punycode", "https://login.xn--spplier-l2a.example/", false},
		{"IPv4 literal", "https://93.184.216.34/", false},
		{"IPv4 loopback", "https://127.0.0.1/", false},
		{"IPv6 literal", "https://[::1]/", false},
		{"IPv6 mapped", "https://[::ffff:127.0.0.1]/", false},
		{"http", "http://login.supplier.example/", false},
		{"ws", "ws://login.supplier.example/socket", false},
		{"wss", "wss://evil.test/socket", false},
		{"ftp", "ftp://login.supplier.example/", false},
		{"data", "data:text/html,<script>fetch('https://evil.test')</script>", false},
		{"blob", "blob:https://login.supplier.example/0b5e2c3a-1111-4222-8333-444455556666", false},
		{"about", "about:blank", false},
		{"javascript", "javascript:alert(1)", false},
		{"scheme-relative", "//login.supplier.example/", false},
		{"no host", "https:///path", false},
	}
	e := newPage(t)
	e.navigate(t, loginURL)
	for i, tc := range tests {
		// Same decision as httpx wherever httpx is asked at all (escaped
		// or backslashed inputs are refused before the host is looked at).
		if u, err := url.Parse(tc.url); err == nil && u.Scheme == "https" && u.User == nil && u.Host != "" &&
			!strings.ContainsAny(tc.url, "%\\") {
			_, ipErr := netip.ParseAddr(strings.Trim(u.Hostname(), "[]"))
			if ipErr != nil && allow.Allows(u.Host) != tc.allow {
				t.Fatalf("%s: table says %v but httpx.Allows(%q) = %v: fix the table", tc.name, tc.allow, u.Host, !tc.allow)
			}
		}
		id := fmt.Sprintf("m-%d", i)
		e.f.requestPaused(fakeSessionID, id, tc.url, "Script", nil)
		if tc.allow {
			continued(t, e.f, fakeSessionID, id)
		} else {
			blocked(t, e.f, fakeSessionID, id)
		}
	}
	for i, tc := range tests {
		id := fmt.Sprintf("m-%d", i)
		for _, c := range e.f.snapshot() {
			if c.Params["requestId"] != id {
				continue
			}
			if (c.Method == "Fetch.continueRequest" && !tc.allow) || (c.Method == "Fetch.failRequest" && tc.allow) {
				t.Errorf("%s (%s): %s, want allow=%v", tc.name, tc.url, c.Method, tc.allow)
			}
		}
	}
}

func TestFetch_UnparsableURLFailsClosed(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.navigate(t, loginURL)
	tests := []struct {
		name    string
		request any
	}{
		{"bad escape in host", map[string]any{"url": "https://%zz.supplier.example/"}},
		{"bad escape in path", map[string]any{"url": "https://login.supplier.example/%"}},
		{"control character", map[string]any{"url": "https://login.supplier.example/\x00"}},
		{"space in host", map[string]any{"url": "https://login supplier.example/"}},
		{"empty url", map[string]any{"url": ""}},
		{"colons only", map[string]any{"url": "::::"}},
		{"url is a number", map[string]any{"url": 42}},
		{"url missing", map[string]any{"method": "GET"}},
		{"request missing", nil},
		{"request is a string", "https://login.supplier.example/"},
	}
	for i, tc := range tests {
		id := fmt.Sprintf("u-%d", i)
		params := map[string]any{"requestId": id, "resourceType": "Script", "frameId": fakeFrameID}
		if tc.request != nil {
			params["request"] = tc.request
		}
		e.f.emit(fakeSessionID, "Fetch.requestPaused", params)
		blocked(t, e.f, fakeSessionID, id)
		for _, c := range e.f.snapshot() {
			if c.Method == "Fetch.continueRequest" && c.Params["requestId"] == id {
				t.Errorf("%s: continued, want failed closed", tc.name)
			}
		}
	}
	// The page is still enforcing afterwards.
	neverContinued(t, e.f, fakeSessionID, "u-0")
	if _, err := e.p.CurrentURL(testCtx(t)); err != nil {
		t.Errorf("page dead after malformed pauses: %v", err)
	}
}

// TestFlags_HostResolverRulesMirrorAllowlist: the second layer is derived
// from the same allowlist (ADR 0008, T9 list).
func TestFlags_HostResolverRulesMirrorAllowlist(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		domains []string
		want    string
	}{
		{"one host", []string{"login.supplier.example"}, "MAP * ~NOTFOUND, EXCLUDE login.supplier.example"},
		{"host and wildcard", []string{"supplier.example", "*.supplier.example"}, "MAP * ~NOTFOUND, EXCLUDE *.supplier.example, EXCLUDE supplier.example"},
		{"case and duplicates", []string{"Login.Supplier.Example", "login.supplier.example"}, "MAP * ~NOTFOUND, EXCLUDE login.supplier.example"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := opts("linux")
			o.AllowedDomains = tc.domains
			got := mustFlags(t, o)
			var rules []string
			for _, a := range got {
				if v, ok := strings.CutPrefix(a, "--host-resolver-rules="); ok {
					rules = append(rules, v)
				}
			}
			if len(rules) != 1 || rules[0] != tc.want {
				t.Errorf("--host-resolver-rules = %q, want exactly [%q]", rules, tc.want)
			}
		})
	}
	for _, bad := range [][]string{{"93.184.216.34"}, {"localhost.example", "*.com"}, {"evil.test, EXCLUDE *"}} {
		o := opts("linux")
		o.AllowedDomains = bad
		if _, err := browser.Flags(o); !errors.Is(err, browser.ErrInvalidDomain) {
			t.Errorf("Flags(%q) = %v, want ErrInvalidDomain", bad, err)
		}
	}
}
