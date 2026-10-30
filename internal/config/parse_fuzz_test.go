package config_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// fuzzValueMarker is replaced by a canary in every fuzz document, so the
// fuzzer can move a would-be secret to any position of config.yaml.
const fuzzValueMarker = "@V@"

// FuzzParse (SEC-J0-24) feeds hostile documents to config.Parse:
//   - it never panics, and returns either a config or an error, never both;
//   - every error wraps ErrInvalid;
//   - an error never quotes a value: with the marker replaced by a canary
//     (random tail first, as in TestLoad_ErrorsNeverEchoValues), the error
//     holds no 7-byte piece of it unless the canary sits in a mapping key
//     (keys are named in errors by design);
//   - an accepted config re-validates, with absolute output.local and
//     state_dir.
func FuzzParse(f *testing.F) {
	const ref = "bw://3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90/password" // synthetic
	for _, s := range []string{
		// Accepted shapes (validate_test.go, load_test.go).
		"",
		"output:\n  local: '~/Google Drive/Invoices'\nstate_dir: '~/.facto'\n",
		"connectors:\n  edf:\n    enabled: true\n    category: housing\n    password: '" + ref + "'\n",
		"connectors:\n  edf:\n    enabled: true\n    category: housing\n    password: 'keyring://facto/edf/password'\n",
		"manual:\n  - { id: edf, name: EDF, category: housing, reminder: monthly }\n",
		"naming:\n  file: '{date}_{provider}_{amount}'\n  dir: '{year}/{category}'\n",
		// Refused shapes with the value marker (load_test.go, attack_test.go).
		"connectors:\n  edf:\n    enabled: " + fuzzValueMarker + "\n",
		"manual: " + fuzzValueMarker + "\n",
		"output: " + fuzzValueMarker + "\n",
		"connectors:\n  edf:\n    pasword: " + fuzzValueMarker + "\n",
		"connectors:\n  edf:\n    password: " + fuzzValueMarker + "\n",
		"connectors:\n  edf:\n    password: *" + fuzzValueMarker + "\n",
		"connectors:\n  edf:\n    enabled: !" + fuzzValueMarker + " x\n",
		"connectors:\n  edf:\n    password: !!int " + fuzzValueMarker + "\n",
		"connectors:\n  edf:\n    enabled: !<tag:yaml.org,2002:" + fuzzValueMarker + "> x\n",
		"connectors:\n  edf:\n    enabled: |\n      " + fuzzValueMarker + "\n      second line\n",
		"base: &b { password: " + fuzzValueMarker + " }\nconnectors:\n  edf:\n    <<: *b\n",
		"sessions: &s " + fuzzValueMarker + "\nnotify: *s\n",
		"connectors:\n  edf:\n    password: \"" + fuzzValueMarker + "\n",
		"connectors:\n\tedf:\n\t\tpassword: " + fuzzValueMarker + "\n",
		"notify: none\n---\npassword: " + fuzzValueMarker + "\n",
		"connectors:\n  edf:\n    password: " + ref + "\n    password: " + fuzzValueMarker + "\n",
		"connectors: { edf: { password: " + fuzzValueMarker + " }\n",
		"connectors:\n  edf:\n    password: \"\\q" + fuzzValueMarker + "\"\n",
		"connectors:\n  edf:\n    password: \"" + fuzzValueMarker + "\x01\"\n",
		"naming:\n  file: \"" + fuzzValueMarker + "}\"\n",
		"naming:\n  dir: \"{year}/" + fuzzValueMarker + "]\"\n",
		"manual:\n  - { id: " + fuzzValueMarker + " }\n",
		"state_dir: ~" + fuzzValueMarker + "/x\n",
		"state_dir: " + fuzzValueMarker + "/x\n",
		"state_dir: '~/Dropbox/" + fuzzValueMarker + "'\n",
		"browser:\n  path: '" + fuzzValueMarker + "\u202e'\n",
		"manual: [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]\n",
	} {
		f.Add(s)
	}
	c := testsecrets.Canary(f, testsecrets.Password)
	v := c[strings.LastIndex(c, "-")+1:] + "x" + c // random bytes first
	home := filepath.Join(f.TempDir(), "home", "synthetic")

	f.Fuzz(func(t *testing.T, doc string) {
		for _, d := range []string{doc, strings.ReplaceAll(doc, fuzzValueMarker, v)} {
			cfg, err := config.Parse([]byte(d), config.Options{Home: home})
			if err != nil {
				if cfg != nil {
					t.Fatalf("Parse(%q) returned a config along with error %v", d, err)
				}
				if !errors.Is(err, config.ErrInvalid) {
					t.Fatalf("Parse(%q) error = %v, want ErrInvalid", d, err)
				}
				if strings.Contains(d, v) && !canaryInKey(d, v) {
					assertNoEchoFuzz(t, d, err, v)
				}
				continue
			}
			if cfg == nil {
				t.Fatalf("Parse(%q) = nil, nil", d)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Parse(%q) accepted a config that does not re-validate: %v", d, err)
			}
			if !filepath.IsAbs(cfg.Output.Local) || !filepath.IsAbs(cfg.StateDir) {
				t.Fatalf("Parse(%q) accepted relative paths: output.local %q, state_dir %q", d, cfg.Output.Local, cfg.StateDir)
			}
		}
	})
}

// canaryInKey reports whether v occurs in a mapping key (value, tag or
// anchor) of doc. A doc that does not parse as YAML reports false: the echo
// check is kept, since parser errors keep only line numbers. Aliases are not
// followed (their targets are already in the tree; following them could
// expand an alias bomb).
func canaryInKey(doc, v string) bool {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		return false
	}
	var walk func(n *yaml.Node, depth int) bool
	walk = func(n *yaml.Node, depth int) bool {
		if n == nil || depth > 100 {
			return false
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if k := n.Content[i]; strings.Contains(k.Value, v) || strings.Contains(k.Tag, v) || strings.Contains(k.Anchor, v) {
					return true
				}
			}
		}
		for _, c := range n.Content {
			if walk(c, depth+1) {
				return true
			}
		}
		return false
	}
	return walk(&root, 0)
}

// assertNoEchoFuzz is assertNoEcho with the document in the failure message.
func assertNoEchoFuzz(t *testing.T, doc string, err error, value string) {
	t.Helper()
	msg := err.Error()
	tail := value[strings.LastIndex(value, "-")+1:]
	const window = 7
	if strings.Contains(msg, value) {
		t.Fatalf("Parse(%q) error %q echoes the value", doc, msg)
	}
	for i := 0; i+window <= len(tail); i++ {
		if strings.Contains(msg, tail[i:i+window]) {
			t.Fatalf("Parse(%q) error %q echoes part of the value (%q)", doc, msg, tail[i:i+window])
		}
	}
}
