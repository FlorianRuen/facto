// Tests for the browser config block (J1 task T19, ADR 0008 "Chrome for
// Testing": "other platforms pass an explicit browser path (config browser
// block, T19)"). Parse stays lexical: whether the path names an existing
// regular file is checked by cmd/facto when a browser is needed
// (TestBrowserPath_RegularFileOrInstalled). All paths are synthetic.
//
// Expected API (implementer: follow exactly; package config):
//
//	// Config gains:
//	//	// Browser configures the Chrome for Testing binary facto drives.
//	//	Browser Browser `yaml:"browser"`
//
//	// Browser is the browser block.
//	type Browser struct {
//		// Path is the Chrome binary: absolute after "~" expansion (same
//		// rules as output.local and state_dir), or empty for the copy
//		// installed by `facto browser install`.
//		Path string `yaml:"path"`
//	}
//
// Rules (Parse):
//   - absent block, absent or empty path: Browser.Path == "" (no default
//     is filled in: the installed copy is looked up at run time);
//   - "~/…" is expanded with Options.Home, an absolute path is cleaned;
//   - a relative path, "~user/…", or a path holding a control character
//     (NUL, newline, ESC…) is ErrInvalid naming "browser.path", never
//     quoting the value;
//   - decoding is strict: an unknown key under browser (browser.headless,
//     browser.args…) or a wrong type (browser: "<scalar>") is ErrInvalid.
//     facto has no setting that changes launch flags.
package config_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestConfig_BrowserPathRules: browser.path is absolute (or "~/…"), the
// block is decoded strictly and an invalid value is never echoed.
func TestConfig_BrowserPathRules(t *testing.T) {
	t.Parallel()
	home := fakeHome(t)
	abs := filepath.Join(home, "opt", "chrome-for-testing", "chrome")
	canary := testsecrets.Canary(t, testsecrets.Password)

	tests := []struct {
		name    string
		yaml    string
		want    string // expected Browser.Path when valid
		wantErr bool
		key     string // key the error must name
		noEcho  string // value the error must not quote ("" = not checked)
	}{
		{name: "block absent", yaml: "notify: none\n", want: ""},
		{name: "empty block", yaml: "browser: {}\n", want: ""},
		{name: "empty path", yaml: "browser:\n  path: ''\n", want: ""},
		{name: "absolute path kept", yaml: "browser:\n  path: '" + abs + "'\n", want: abs},
		{name: "absolute path cleaned", yaml: "browser:\n  path: '" + filepath.Join(home, "opt") + string(filepath.Separator) + "." + string(filepath.Separator) + "chrome'\n", want: filepath.Join(home, "opt", "chrome")},
		{name: "tilde expanded", yaml: "browser:\n  path: ~/chrome/chrome\n", want: filepath.Join(home, "chrome", "chrome")},
		{name: "relative path refused", yaml: "browser:\n  path: chrome\n", wantErr: true, key: "browser.path"},
		{name: "dot relative path refused", yaml: "browser:\n  path: ./bin/chrome\n", wantErr: true, key: "browser.path"},
		{name: "other user's home refused", yaml: "browser:\n  path: ~synthetic/chrome\n", wantErr: true, key: "browser.path"},
		{name: "secret pasted as path never echoed", yaml: "browser:\n  path: '" + canary + "'\n", wantErr: true, key: "browser.path", noEcho: canary},
		{name: "newline in path refused", yaml: "browser:\n  path: \"" + filepath.ToSlash(abs) + "\\nforged\"\n", wantErr: true, key: "browser.path"},
		{name: "escape in path refused", yaml: "browser:\n  path: \"" + filepath.ToSlash(abs) + "\\e[2J\"\n", wantErr: true, key: "browser.path"},
		{name: "nul in path refused", yaml: "browser:\n  path: \"" + filepath.ToSlash(abs) + "\\0\"\n", wantErr: true, key: "browser.path"},
		{name: "unknown key refused", yaml: "browser:\n  path: '" + abs + "'\n  headless: false\n", wantErr: true, key: "browser.headless"},
		{name: "launch args never configurable", yaml: "browser:\n  args: ['--no-sandbox']\n", wantErr: true, key: "browser.args"},
		{name: "scalar block refused", yaml: "browser: '" + canary + "'\n", wantErr: true, key: "browser", noEcho: canary},
		{name: "path list refused", yaml: "browser:\n  path: ['" + abs + "']\n", wantErr: true, key: "browser.path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !tt.wantErr {
				cfg := mustParse(t, tt.yaml, home)
				if cfg.Browser.Path != tt.want {
					t.Fatalf("Browser.Path = %q, want %q", cfg.Browser.Path, tt.want)
				}
				return
			}
			err := parseErr(t, tt.yaml, home)
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Parse() error = %v, want ErrInvalid", err)
			}
			assertMentions(t, err, tt.key)
			if tt.noEcho != "" {
				assertNoEcho(t, err, tt.noEcho)
			}
			if strings.ContainsAny(err.Error(), "\x00\x1b") {
				t.Errorf("error carries a raw control character: %q", err.Error())
			}
		})
	}
}
