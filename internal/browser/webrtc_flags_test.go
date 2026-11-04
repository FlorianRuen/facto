package browser_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// webrtcPolicy is the switch Chrome for Testing 156 reads the WebRTC IP
// handling policy from (the webrtc.ip_handling_policy pref). The legacy
// --force-webrtc-ip-handling-policy is not recognised there (ADR 0008
// "Hardening / WebRTC", J1 T27; real-Chrome proof:
// TestAttack_ChromeWebRTCToIPLiteral).
const webrtcPolicy = "--webrtc-ip-handling-policy=disable_non_proxied_udp"

// TestFlags_WebRTCPolicyReachesChrome: every release argv carries the
// switch Chrome reads, on every OS and option variant, once.
func TestFlags_WebRTCPolicyReachesChrome(t *testing.T) {
	t.Parallel()
	for _, o := range allOptionVariants() {
		got := mustFlags(t, o)
		n := 0
		for _, a := range got {
			if strings.HasPrefix(a, "--webrtc-ip-handling-policy") {
				n++
			}
		}
		if n != 1 || !slices.Contains(got, webrtcPolicy) {
			t.Errorf("%s visible=%v proxy=%v: want exactly one %s in %q", o.GOOS, o.Visible, o.AllowProxy, webrtcPolicy, got)
		}
	}
}

// TestCheckFlags_WebRTCPolicyMandatoryAndNotWeakened: CheckFlags refuses
// an argv without the switch, and any other value of it.
func TestCheckFlags_WebRTCPolicyMandatoryAndNotWeakened(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin", "windows"} {
		release := mustFlags(t, opts(goos))
		without := slices.DeleteFunc(slices.Clone(release), func(a string) bool { return a == webrtcPolicy })
		if len(without) != len(release)-1 {
			t.Fatalf("%s: release argv %q has no single %s", goos, release, webrtcPolicy)
		}
		if err := browser.CheckFlags(goos, without); !errors.Is(err, browser.ErrForbiddenFlag) {
			t.Errorf("CheckFlags(%s, argv without %s) = %v, want ErrForbiddenFlag", goos, webrtcPolicy, err)
		}
		for _, v := range []string{
			"--webrtc-ip-handling-policy=default",
			"--webrtc-ip-handling-policy=default_public_interface_only",
			"--webrtc-ip-handling-policy=default_public_and_private_interfaces",
			"--webrtc-ip-handling-policy=",
			"--webrtc-ip-handling-policy",
			"--WEBRTC-IP-HANDLING-POLICY=default",
			"--webrtc-ip-handling-policy=DISABLE_NON_PROXIED_UDP",
		} {
			if err := browser.CheckFlags(goos, append(slices.Clone(without), v)); !errors.Is(err, browser.ErrForbiddenFlag) {
				t.Errorf("CheckFlags(%s, +%q) = %v, want ErrForbiddenFlag", goos, v, err)
			}
		}
		if err := browser.CheckFlags(goos, append(slices.Clone(release), webrtcPolicy)); !errors.Is(err, browser.ErrForbiddenFlag) {
			t.Errorf("CheckFlags(%s, switch twice) = %v, want ErrForbiddenFlag", goos, err)
		}
	}
}
