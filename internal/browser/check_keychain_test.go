package browser_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestCheckFlags_DarwinRequiresMockKeychain (J1 T7c, from the T10 review):
// on darwin --use-mock-keychain is a mandatory switch, so Chrome never
// touches the user's login keychain. Expected API: CheckFlags unchanged in
// signature; mandatorySwitches("darwin") also holds "use-mock-keychain".
func TestCheckFlags_DarwinRequiresMockKeychain(t *testing.T) {
	t.Parallel()
	release := mustFlags(t, opts("darwin"))
	if err := browser.CheckFlags("darwin", release); err != nil {
		t.Fatalf("CheckFlags(darwin, release) = %v, want nil", err)
	}
	without := slices.DeleteFunc(slices.Clone(release), func(a string) bool {
		return strings.HasPrefix(a, "--use-mock-keychain")
	})
	if len(without) != len(release)-1 {
		t.Fatalf("darwin release argv %q has no single --use-mock-keychain", release)
	}
	if err := browser.CheckFlags("darwin", without); !errors.Is(err, browser.ErrForbiddenFlag) {
		t.Errorf("CheckFlags(darwin, argv without --use-mock-keychain) = %v, want ErrForbiddenFlag", err)
	}
	// Still refused on the other OSes (not one of their switches).
	for _, goos := range []string{"linux", "windows"} {
		args := append(mustFlags(t, opts(goos)), "--use-mock-keychain")
		if err := browser.CheckFlags(goos, args); !errors.Is(err, browser.ErrForbiddenFlag) {
			t.Errorf("CheckFlags(%s, +--use-mock-keychain) = %v, want ErrForbiddenFlag", goos, err)
		}
	}
}
