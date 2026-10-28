// Red-team attack tests for config.yaml (J0 task T30): YAML alias bombs and
// deep nesting under the size cap, values echoed by YAML tag resolution,
// block scalars, merge keys and parser errors, and values echoed by the
// naming-template validation. Uses writeConfig, opts, fakeHome, parseErr and
// assertNoEcho from helpers_test.go. Errors are written under
// testsecrets.ArtifactDir so `make leakcheck` greps them. A test passes when
// the attack is defeated. Everything is synthetic.
package config_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// atkArtifact writes content under the test's ArtifactDir.
func atkArtifact(t *testing.T, name, content string) {
	t.Helper()
	r, err := fsx.Open(testsecrets.ArtifactDir(t))
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, []byte(content)); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
}

// atkBomb is a billion-laughs document: nine levels of ten aliases, the last
// anchor aliased from every field that decodes a list or a mapping.
func atkBomb() string {
	var b strings.Builder
	b.WriteString("x0: &a0 [lol, lol, lol, lol, lol, lol, lol, lol, lol, lol]\n")
	for i := 1; i <= 9; i++ {
		fmt.Fprintf(&b, "x%d: &a%d [", i, i)
		for j := range 10 {
			if j > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "*a%d", i-1)
		}
		b.WriteString("]\n")
	}
	b.WriteString("manual: *a9\nconnectors: { edf: *a9 }\noutput: *a9\n")
	return b.String()
}

// TestAttack_ConfigYAMLBombsAreRefusedQuickly feeds an alias bomb, deep
// flow nesting and a huge number of tiny wrongly typed items, all under
// MaxFileSize. Load must refuse each with ErrInvalid in bounded time.
func TestAttack_ConfigYAMLBombsAreRefusedQuickly(t *testing.T) {
	t.Parallel()
	docs := map[string]string{
		"billion laughs":      atkBomb(),
		"deep flow nesting":   "manual: " + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + "\n",
		"deep block nesting":  "manual:\n" + strings.Repeat("- ", 15000) + "x\n",
		"many wrong items":    "manual: [" + strings.Repeat("1,", 30000) + "1]\n",
		"many aliases of one": "x: &a [1]\nmanual: [" + strings.Repeat("*a,", 20000) + "*a]\n",
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if len(doc) > config.MaxFileSize {
				t.Fatalf("setup: document is %d bytes, over MaxFileSize", len(doc))
			}
			p := writeConfig(t, []byte(doc))
			var cfg *config.Config
			var err error
			done := make(chan struct{})
			go func() { defer close(done); cfg, err = config.Load(t.Context(), p, opts(fakeHome(t))) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Load did not return within 5s")
			}
			if !errors.Is(err, config.ErrInvalid) || cfg != nil {
				t.Fatalf("Load = %v, %v; want nil config and ErrInvalid", cfg, err)
			}
		})
	}
}

// TestAttack_ConfigErrorsNeverEchoValueShapes puts a canary where YAML
// itself quotes values in its errors (explicit core tags that fail to
// resolve, timestamps, binary), in block scalars, merge keys, anchors in
// enums, unterminated quotes, tabs, a second document and duplicate keys.
// Every error must wrap ErrInvalid and quote nothing of the value.
func TestAttack_ConfigErrorsNeverEchoValueShapes(t *testing.T) {
	t.Parallel()
	c := testsecrets.Canary(t, testsecrets.Password)
	v := c[strings.LastIndex(c, "-")+1:] + "x" + c // random bytes first
	ref := "bw://3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90/password"
	docs := map[string]string{
		"!!int tag":                 "connectors:\n  edf:\n    password: !!int " + v + "\n",
		"!!float tag":               "notify: !!float " + v + "\n",
		"!!bool tag":                "connectors:\n  edf:\n    enabled: !!bool " + v + "\n",
		"!!timestamp tag":           "sessions: !!timestamp " + v + "\n",
		"!!binary tag":              "connectors:\n  edf:\n    password: !!binary " + v + "!\n",
		"!!null tag on bool":        "connectors:\n  edf:\n    enabled: !!map " + v + "\n",
		"!!seq tag":                 "state_dir: !!seq " + v + "\n",
		"verbatim tag":              "connectors:\n  edf:\n    enabled: !<tag:yaml.org,2002:" + v + "> x\n",
		"literal block scalar":      "connectors:\n  edf:\n    enabled: |\n      " + v + "\n      second line\n",
		"folded scalar in password": "connectors:\n  edf:\n    password: >\n      " + v + "\n",
		"multi-line plain password": "connectors:\n  edf:\n    password: first\n      " + v + "\n",
		"merge key":                 "base: &b { password: " + v + " }\nconnectors:\n  edf:\n    <<: *b\n",
		"anchored enum":             "sessions: &s " + v + "\nnotify: *s\n",
		"unterminated double quote": "connectors:\n  edf:\n    password: \"" + v + "\n",
		"unterminated single quote": "connectors:\n  edf:\n    password: '" + v + "\n",
		"tab indentation":           "connectors:\n\tedf:\n\t\tpassword: " + v + "\n",
		"colon inside value":        "connectors:\n  edf:\n    password: " + v + ": " + v + "\n",
		"value then second doc":     "notify: none\n---\npassword: " + v + "\n",
		"duplicate key":             "connectors:\n  edf:\n    password: " + ref + "\n    password: " + v + "\n",
		"flow mapping broken":       "connectors: { edf: { password: " + v + " }\n",
		"bad escape":                "connectors:\n  edf:\n    password: \"\\q" + v + "\"\n",
		"control character":         "connectors:\n  edf:\n    password: \"" + v + "\x01\"\n",
		"secrets.default":           "secrets:\n  default: " + v + "\n",
		"sessions":                  "sessions: " + v + "\n",
		"language":                  "naming:\n  language: " + v + "\n",
		"reminder":                  "manual:\n  - { id: edf, reminder: " + v + " }\n",
		"manual id":                 "manual:\n  - { id: " + v + " }\n",
		"category":                  "connectors:\n  edf:\n    category: " + v + "\n",
		"home of another user":      "state_dir: ~" + v + "/x\n",
		"relative state dir":        "state_dir: " + v + "/x\n",
	}
	var report strings.Builder
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(t.Context(), writeConfig(t, []byte(doc)), opts(fakeHome(t)))
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
			assertNoEcho(t, err, v)
		})
	}
	for name, doc := range docs {
		_, err := config.Load(t.Context(), writeConfig(t, []byte(doc)), opts(fakeHome(t)))
		fmt.Fprintf(&report, "%s\t%v\n", name, err)
	}
	atkArtifact(t, "config-errors.txt", report.String())
}

// TestAttack_ConfigNamingTemplateErrorsNeverEchoValue pastes a secret into
// naming.file and naming.dir (a password on the wrong line) so that the
// template is malformed. The package contract allows errors to name
// template placeholders, never to quote a scalar value: the literal text of
// the template is a value.
func TestAttack_ConfigNamingTemplateErrorsNeverEchoValue(t *testing.T) {
	t.Parallel()
	c := testsecrets.Canary(t, testsecrets.Password)
	v := c[strings.LastIndex(c, "-")+1:] + "x" + c
	docs := map[string]string{
		"file with stray brace":      "naming:\n  file: \"" + v + "}\"\n",
		"file with unclosed brace":   "naming:\n  file: \"{date}_" + v + "{\"\n",
		"file with forbidden char":   "naming:\n  file: \"" + v + "*\"\n",
		"dir with empty segment":     "naming:\n  dir: \"" + v + "//{year}\"\n",
		"dir with stray bracket":     "naming:\n  dir: \"{year}/" + v + "]\"\n",
		"file with nested brackets":  "naming:\n  file: \"[[" + v + "]]\"\n",
		"file with unclosed bracket": "naming:\n  file: \"[" + v + "\"\n",
	}
	var report strings.Builder
	for name, doc := range docs {
		err := parseErr(t, doc, fakeHome(t))
		fmt.Fprintf(&report, "%s\t%v\n", name, err)
		if !errors.Is(err, config.ErrInvalid) {
			t.Errorf("%s: error %v, want ErrInvalid", name, err)
		}
		if strings.Contains(err.Error(), v[:20]) {
			t.Errorf("%s: error quotes the template value: %q", name, err)
		}
	}
	atkArtifact(t, "naming-errors.txt", report.String())
}
