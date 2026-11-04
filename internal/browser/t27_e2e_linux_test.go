//go:build e2e && chrome && linux

// Real-Chrome checks of the J1 T27 fixes (red-team round): the WebRTC
// constructors are gone from every document of the login page target and
// a cross-site frame sends no ICE traffic either (ADR 0008 "Hardening /
// WebRTC"), and a legitimate login page still sees
// what TypeSecret types while page scripts are frozen around
// Input.insertText (ADR 0008 "Secret typing"). Everything is synthetic.
package browser_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
)

// t27Site serves fixed pages for siteHost and atkFrameHost on one TLS
// server of 127.0.0.1 and records the /got values (never printed).
type t27Site struct {
	tls    *httptest.Server
	port   int
	caSPKI string
	udp    net.PacketConn // STUN sink: counts datagrams
	mu     sync.Mutex
	got    []string
	udpN   int
}

func newT27Site(t *testing.T) *t27Site {
	t.Helper()
	s := &t27Site{}
	cert, spki := siteCertificate(t)
	s.caSPKI = spki
	s.tls = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.tls.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.tls.StartTLS()
	t.Cleanup(s.tls.Close)
	s.port = s.tls.Listener.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // httptest listens on TCP
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	s.udp = pc
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			s.mu.Lock()
			s.udpN++
			s.mu.Unlock()
		}
	}()
	return s
}

func (s *t27Site) udpPort() int { return s.udp.LocalAddr().(*net.UDPAddr).Port } //nolint:forcetypeassert // udp4

func (s *t27Site) datagrams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpN
}

func (s *t27Site) values() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

func (s *t27Site) serve(w http.ResponseWriter, r *http.Request) {
	html := func(body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><meta charset=\"utf-8\"><title>facto t27</title><body>"+body+"</body>")
	}
	switch r.URL.Path {
	case "/rtc-probe":
		// typeof of the WebRTC constructors in the main frame, in a fresh
		// same-origin about:blank frame and in a srcdoc frame.
		html(`<script>
const out = [];
const probe = (w) => ["RTCPeerConnection", "webkitRTCPeerConnection", "RTCDataChannel"].map((n) => typeof w[n]).join("/");
function done() { if (document.getElementById("done")) return; const p = document.createElement("p"); p.id = "done"; p.className = out.sort().join(" "); p.textContent = "done"; document.body.appendChild(p); }
function add(v) { out.push(v); if (out.length === 3) done(); }
setTimeout(done, 5000);
add("main=" + probe(window));
const b = document.createElement("iframe"); document.body.appendChild(b);
add("blank=" + probe(b.contentWindow));
const d = document.createElement("iframe"); d.srcdoc = "<p>x</p>";
d.onload = () => add("srcdoc=" + probe(d.contentWindow)); document.body.appendChild(d);
</script>`)
	case "/rtc-oopif":
		// A cross-site (out-of-process) frame, which the no-WebRTC script
		// does not reach, gathers ICE candidates against a STUN server on
		// 127.0.0.1; so does the realm of a pop-up the page opens.
		html(fmt.Sprintf(`<script>
const out = new Set();
function done(v) { out.add(v); if (document.getElementById("done")) return; if (out.size < 2 && v !== "timeout") return;
  const p = document.createElement("p"); p.id = "done"; p.className = [...out].join(" "); p.textContent = "done"; document.body.appendChild(p); }
addEventListener("message", (e) => done("frame-" + e.data));
try {
  const w = window.open("about:blank", "_blank");
  if (!w || !w.RTCPeerConnection) { done("popup-none"); } else {
    const pc = new w.RTCPeerConnection({iceServers: [{urls: ["stun:127.0.0.1:%[2]d"]}]});
    pc.createDataChannel("x");
    pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === "complete") done("popup-complete"); };
    pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => done("popup-error"));
  }
} catch (e) { done("popup-error"); }
setTimeout(() => done("timeout"), 8000);
</script><iframe src="https://%[1]s/rtc-frame?p=%[2]d"></iframe>`, atkFrameHost, s.udpPort()))
	case "/rtc-frame":
		html(`<script>
const port = new URLSearchParams(location.search).get("p");
try {
  const pc = new RTCPeerConnection({iceServers: [{urls: ["stun:127.0.0.1:" + port]}]});
  pc.createDataChannel("x");
  pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === "complete") parent.postMessage("complete", "*"); };
  pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => parent.postMessage("error", "*"));
} catch (e) { parent.postMessage("unsupported", "*"); }
</script>`)
	case "/listen":
		// A login page whose own script tracks the field (as a framework
		// would): it must see the typed value once TypeSecret returns.
		html(`<input id="pass" type="password"><p id="ready">ready</p><script>
const p = document.getElementById("pass");
p.addEventListener("input", () => { if (!document.getElementById("seen")) { const s = document.createElement("p"); s.id = "seen"; s.textContent = "seen"; document.body.appendChild(s); }
  fetch("/got?v=" + encodeURIComponent(p.value)); });
</script>`)
	case "/got":
		s.mu.Lock()
		s.got = append(s.got, r.URL.Query().Get("v"))
		s.mu.Unlock()
	default:
		http.NotFound(w, r)
	}
}

func t27Rig(t *testing.T, s *t27Site) *chromeRig {
	t.Helper()
	return newChromeRig(t, func(r *chromeRig) browser.Starter {
		return func(ctx context.Context, cmd browser.Command) (browser.Process, error) {
			profile, ok := argValue(cmd.Args, "--user-data-dir=")
			if !ok {
				return nil, errors.New("t27 starter: no --user-data-dir")
			}
			args, err := browser.FlagsE2E(browser.Options{
				ProfileDir:     profile,
				AllowedDomains: atkDomains,
				Visible:        !slices.Contains(cmd.Args, headlessFlag),
				AllowProxy:     !slices.Contains(cmd.Args, "--no-proxy-server"),
			}, browser.E2EOverrides{LoopbackHosts: atkDomains, LoopbackPort: s.port, TestCASPKI: []string{s.caSPKI}})
			if err != nil {
				return nil, fmt.Errorf("t27 starter: %w", err)
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

func t27Launch(ctx context.Context, t *testing.T, r *chromeRig) *browser.PoolBrowser {
	t.Helper()
	b, err := r.pool.Launch(ctx, connector.LaunchOptions{AllowedDomains: atkDomains})
	if err != nil {
		t.Fatalf("Launch real Chrome: %v", err)
	}
	pb := b.(*browser.PoolBrowser) //nolint:forcetypeassert // the pool's own type
	closeAtCleanup(t, pb)
	return pb
}

// TestChrome_NoWebRTCConstructorsInAnyDocument: RTCPeerConnection,
// webkitRTCPeerConnection and RTCDataChannel are undefined in the main
// frame, in a fresh about:blank frame, in a srcdoc frame and in a
// cross-site out-of-process frame.
func TestChrome_NoWebRTCConstructorsInAnyDocument(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
	defer cancel()
	s := newT27Site(t)
	b := t27Launch(ctx, t, t27Rig(t, s))
	if err := b.Navigate(ctx, "https://"+siteHost+"/rtc-probe"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
	defer wcancel()
	if err := b.WaitVisible(wctx, "#done"); err != nil {
		t.Fatalf("probe page did not settle: %v", err)
	}
	const gone = "undefined/undefined/undefined"
	for _, where := range []string{"main", "blank", "srcdoc"} {
		cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
		err := b.WaitVisible(cctx, fmt.Sprintf(`#done[class~="%s=%s"]`, where, gone))
		ccancel()
		if err != nil {
			t.Errorf("%s document still exposes a WebRTC constructor", where)
		}
	}
}

// TestChrome_WebRTCBlockedInCrossSiteFrame: where the no-WebRTC script does
// not reach (a cross-site out-of-process frame, the realm of a pop-up),
// --webrtc-ip-handling-policy alone keeps ICE off the network: no STUN
// datagram reaches 127.0.0.1.
func TestChrome_WebRTCBlockedInCrossSiteFrame(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
	defer cancel()
	s := newT27Site(t)
	b := t27Launch(ctx, t, t27Rig(t, s))
	if err := b.Navigate(ctx, "https://"+siteHost+"/rtc-oopif"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
	defer wcancel()
	if err := b.WaitVisible(wctx, "#done"); err != nil {
		t.Fatalf("rtc page did not settle: %v", err)
	}
	cctx, ccancel := context.WithTimeout(ctx, 2*time.Second)
	ran := b.WaitVisible(cctx, `#done[class~="frame-complete"]`) == nil
	ccancel()
	if !ran {
		t.Error("the cross-site frame did not complete ICE gathering: the check would be vacuous")
	}
	if n := s.datagrams(); n != 0 {
		t.Errorf("%d STUN datagrams reached 127.0.0.1 from a cross-site frame or a pop-up realm", n)
	}
}
