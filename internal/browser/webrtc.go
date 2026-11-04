package browser

import (
	"context"
	"fmt"
)

// WebRTC (ADR 0008 "Hardening / WebRTC", J1 T27). ICE traffic to STUN and
// TURN servers is UDP or TCP straight to an IP the page names: neither
// Fetch nor the resolver rules see it. The control is the browser switch
// --webrtc-ip-handling-policy=disable_non_proxied_udp (flags.go), which
// covers every target. This file is the defence in depth: a constant
// script, installed with Page.addScriptToEvaluateOnNewDocument on the login
// page session before the first navigation, deletes the WebRTC
// constructors from the main world of every document of that target (the
// main frame and its in-process frames, about:blank and srcdoc included)
// before any page script runs. The page never had a reference to them, so
// it cannot restore them.
//
// It is not installed on auto-attached targets (cross-site frames,
// pop-ups): on Chrome for Testing 156 a Page call on a paused frame
// target, before Runtime.runIfWaitingForDebugger, let the frame run and
// left the resume unanswered (measured in J1 T27). Those targets rely on
// the switch alone, proven by TestChrome_WebRTCBlockedInCrossSiteFrame.

// jsNoWebRTC removes the WebRTC constructors from the global object. It is
// a constant: nothing is ever concatenated into it.
const jsNoWebRTC = `(() => {
  for (const n of ["RTCPeerConnection", "webkitRTCPeerConnection", "RTCDataChannel", "RTCIceTransport"]) {
    try { delete globalThis[n]; } catch (e) {}
  }
})();`

// noWebRTCParams are the Page.addScriptToEvaluateOnNewDocument params:
// the main world (no worldName), run before the document's own scripts.
var noWebRTCParams = map[string]any{"source": jsNoWebRTC}

// installNoWebRTC registers jsNoWebRTC for every new document of session.
func (p *Page) installNoWebRTC(ctx context.Context, session string) error {
	if _, err := p.c.Call(ctx, session, "Page.addScriptToEvaluateOnNewDocument", noWebRTCParams); err != nil {
		return fmt.Errorf("no webrtc script: %w", err)
	}
	return nil
}
