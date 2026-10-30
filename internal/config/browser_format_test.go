// Review follow-up of J1 T19: browser.path refuses Unicode format
// characters (bidi overrides, zero-width characters, BOM) as well as
// control characters, and never echoes them. Synthetic paths only.
package config_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
)

func TestConfig_BrowserPathRefusesFormatCharacters(t *testing.T) {
	t.Parallel()
	home := fakeHome(t)
	abs := filepath.ToSlash(filepath.Join(home, "opt", "chrome"))
	for _, tt := range []struct {
		name string
		r    string
	}{
		{name: "right-to-left override", r: "\u202e"},
		{name: "zero-width space", r: "\u200b"},
		{name: "byte order mark", r: "\ufeff"},
		{name: "soft hyphen", r: "\u00ad"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := parseErr(t, "browser:\n  path: \""+abs+tt.r+"x\"\n", home)
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Parse() error = %v, want ErrInvalid", err)
			}
			assertMentions(t, err, "browser.path")
			if strings.Contains(err.Error(), tt.r) {
				t.Errorf("error carries the format character: %q", err.Error())
			}
		})
	}
}
