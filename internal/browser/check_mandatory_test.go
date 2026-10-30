package browser_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestCheckFlags_MandatorySwitchesRequired (J1 T10, from the T6 review):
// CheckFlags stands alone at launch time, so an argv that lost one of the
// isolation switches is refused even though every remaining switch is
// allowed. Expected API: CheckFlags unchanged in signature; it now also
// returns ErrForbiddenFlag when --user-data-dir, --host-resolver-rules,
// --force-webrtc-ip-handling-policy, --dns-prefetch-disable, or the CDP
// transport (--remote-debugging-pipe on linux/darwin,
// --remote-debugging-port=0 on windows) is missing.
func TestCheckFlags_MandatorySwitchesRequired(t *testing.T) {
	t.Parallel()
	common := []string{
		"--user-data-dir=",
		"--host-resolver-rules=",
		"--force-webrtc-ip-handling-policy=",
		"--dns-prefetch-disable",
	}
	transport := map[string]string{
		"linux":   "--remote-debugging-pipe",
		"darwin":  "--remote-debugging-pipe",
		"windows": "--remote-debugging-port=",
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		release := mustFlags(t, opts(goos))
		if err := browser.CheckFlags(goos, release); err != nil {
			t.Fatalf("CheckFlags(%s, release) = %v, want nil", goos, err)
		}
		for _, prefix := range append(slices.Clone(common), transport[goos]) {
			t.Run(goos+" without "+strings.TrimSuffix(prefix, "="), func(t *testing.T) {
				t.Parallel()
				args := slices.DeleteFunc(slices.Clone(release), func(a string) bool {
					return strings.HasPrefix(a, prefix)
				})
				if len(args) != len(release)-1 {
					t.Fatalf("release argv %q has no single %s switch", release, prefix)
				}
				if err := browser.CheckFlags(goos, args); !errors.Is(err, browser.ErrForbiddenFlag) {
					t.Errorf("CheckFlags(%s, argv without %s) = %v, want ErrForbiddenFlag", goos, prefix, err)
				}
			})
		}
		t.Run(goos+" empty argv", func(t *testing.T) {
			t.Parallel()
			for _, args := range [][]string{nil, {}, {"--headless=new"}} {
				if err := browser.CheckFlags(goos, args); !errors.Is(err, browser.ErrForbiddenFlag) {
					t.Errorf("CheckFlags(%s, %q) = %v, want ErrForbiddenFlag", goos, args, err)
				}
			}
		})
	}
}
