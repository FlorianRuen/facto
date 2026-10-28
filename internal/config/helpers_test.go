package config_test

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/fsx"
)

var update = flag.Bool("update", false, "rewrite golden files")

// testUUID is a synthetic Bitwarden item id (the one used in docs/spec.md).
const testUUID = "3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90"

// fakeHome returns an absolute home directory that is never created: Parse
// and Validate are lexical, only Load touches the disk (for the config file).
func fakeHome(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "home", "synthetic")
}

// opts returns the Options every test uses: an injected home, never the real
// one.
func opts(home string) config.Options { return config.Options{Home: home} }

// writeConfig writes data as a 0600 config.yaml (through fsx) in a fresh
// directory and returns its path.
func writeConfig(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), "config.yaml", data); err != nil {
		t.Fatalf("setup WriteAtomic: %v", err)
	}
	return filepath.Join(dir, "config.yaml")
}

// mustParse parses yaml with the given home and fails the test on error.
func mustParse(t *testing.T, yaml, home string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml), opts(home))
	if err != nil {
		t.Fatalf("Parse() error = %v\ninput:\n%s", err, yaml)
	}
	if cfg == nil {
		t.Fatal("Parse() returned nil config without error")
	}
	return cfg
}

// parseErr parses yaml and returns the error, failing if there is none or if
// a config is returned along with it.
func parseErr(t *testing.T, yaml, home string) error {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml), opts(home))
	if err == nil {
		t.Fatalf("Parse() error = nil, want an error\ninput:\n%s", yaml)
	}
	if cfg != nil {
		t.Errorf("Parse() returned a config along with error %v", err)
	}
	return err
}

// flatten renders cfg as sorted "key = value" lines named after the YAML keys
// of docs/spec.md, with the injected home replaced by $HOME so that golden
// files do not depend on the temp dir or the OS separator.
func flatten(cfg *config.Config, home string) string {
	h := filepath.ToSlash(home)
	p := func(s string) string {
		s = filepath.ToSlash(s)
		switch {
		case s == h:
			return "$HOME"
		case strings.HasPrefix(s, h+"/"):
			return "$HOME" + s[len(h):]
		}
		return s
	}
	var b strings.Builder
	line := func(k string, v any) {
		if s, ok := v.(string); ok {
			v = fmt.Sprintf("%q", s)
		}
		fmt.Fprintf(&b, "%s = %v\n", k, v)
	}
	line("output.local", p(cfg.Output.Local))
	line("output.gdrive.enabled", cfg.Output.GDrive.Enabled)
	line("output.gdrive.root", cfg.Output.GDrive.Root)
	line("naming.file", cfg.Naming.File)
	line("naming.dir", cfg.Naming.Dir)
	line("naming.language", cfg.Naming.Language)
	line("secrets.default", cfg.Secrets.Default)
	line("sessions", cfg.Sessions)
	line("state_dir", p(cfg.StateDir))
	line("notify", cfg.Notify)
	ids := make([]string, 0, len(cfg.Connectors))
	for id := range cfg.Connectors {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	line("connectors.count", len(ids))
	for _, id := range ids {
		c := cfg.Connectors[id]
		k := "connectors." + id + "."
		line(k+"enabled", c.Enabled)
		line(k+"category", c.Category)
		line(k+"login", c.Login)
		line(k+"password", c.Password)
		line(k+"otp", c.OTP)
	}
	line("manual.count", len(cfg.Manual))
	for i, m := range cfg.Manual {
		k := fmt.Sprintf("manual[%d].", i)
		line(k+"id", m.ID)
		line(k+"name", m.Name)
		line(k+"category", m.Category)
		line(k+"reminder", m.Reminder)
	}
	return b.String()
}

// checkGolden compares got with the golden file, rewriting it (0600 through
// fsx) when -update is set.
func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		r, err := fsx.Open(".")
		if err != nil {
			t.Fatalf("update golden: %v", err)
		}
		defer func() { _ = r.Close() }()
		if err := r.MkdirPrivate(filepath.ToSlash(filepath.Dir(path))); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		if err := r.WriteAtomic(t.Context(), filepath.ToSlash(path), got); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read golden %s: %v (run go test -update and review)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch (run go test -update and review the diff)\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}

// assertMentions checks that the error names the offending key, so a user can
// find it in config.yaml.
func assertMentions(t *testing.T, err error, key string) {
	t.Helper()
	if !strings.Contains(err.Error(), key) {
		t.Errorf("error %q does not mention the key %q", err, key)
	}
}

// assertNoEcho checks that the error contains neither value nor any 7-byte
// piece of its random tail (after the last '-', see testsecrets.Canary): a
// password typed in the wrong field must not end up in a terminal, a log or a
// report, not even truncated (yaml type errors quote the first bytes).
func assertNoEcho(t *testing.T, err error, value string) {
	t.Helper()
	msg := err.Error()
	if strings.Contains(msg, value) {
		t.Fatalf("error %q echoes the value", msg)
	}
	tail := value[strings.LastIndex(value, "-")+1:]
	const window = 7
	for i := 0; i+window <= len(tail); i++ {
		if strings.Contains(msg, tail[i:i+window]) {
			t.Fatalf("error %q echoes part of the value (%q)", msg, tail[i:i+window])
		}
	}
}
