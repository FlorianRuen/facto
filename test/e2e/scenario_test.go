//go:build e2e

package e2e

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// validScenario uses every field of the format once.
const validScenario = `name: full-example
description: every field once
state_dir: state
setup:
  - path: config.yaml
    mode: "0600"
    content: "home={{home}} secret={{canary:password}}\n"
  - path: Invoices/inbox/a.pdf
    fixture: edf-invoice.pdf
  - path: Invoices/inbox/sub
    dir: true
    mode: "0700"
  - path: Invoices/inbox/link.pdf
    symlink: ../../config.yaml
args: [collect, --config, "{{home}}/config.yaml"]
expect:
  exit: 0
  stdout: { prefix: "facto ", contains: [filed], not_contains: [panic] }
  stderr: { empty: true }
  files:
    - { path: Invoices/2026/a.pdf, mode: "0600", fixture: edf-invoice.pdf }
    - { path: notes.txt, content: "x\n" }
  absent: [Invoices/inbox/a.pdf]
  trees:
    - { path: Invoices, private: true, entries: [inbox/, inbox/sub/] }
repeat:
  expect: { exit: 0 }
  unchanged: [Invoices]
`

func TestScenarioParse(t *testing.T) {
	t.Parallel()
	// mutate replaces old with new in validScenario (old must be present).
	mutate := func(from, to string) string {
		if !strings.Contains(validScenario, from) {
			t.Fatalf("test bug: %q not in validScenario", from)
		}
		return strings.Replace(validScenario, from, to, 1)
	}
	tests := []struct {
		name    string
		in      string
		wantErr bool
		check   func(t *testing.T, s *Scenario)
	}{
		{name: "full example", in: validScenario, check: func(t *testing.T, s *Scenario) {
			if s.Name != "full-example" || s.StateDir != "state" {
				t.Errorf("name/state_dir = %q/%q", s.Name, s.StateDir)
			}
			if want := []string{"collect", "--config", "{{home}}/config.yaml"}; !slices.Equal(s.Args, want) {
				t.Errorf("args = %q, want %q", s.Args, want)
			}
			if len(s.Setup) != 4 || s.Setup[0].Content == nil || s.Setup[1].Fixture != "edf-invoice.pdf" ||
				!s.Setup[2].Dir || s.Setup[3].Symlink != "../../config.yaml" {
				t.Errorf("setup = %+v", s.Setup)
			}
			if s.Expect.Exit == nil || *s.Expect.Exit != 0 || s.Expect.Stdout.Prefix != "facto " || !s.Expect.Stderr.Empty {
				t.Errorf("expect = %+v", s.Expect)
			}
			if len(s.Expect.Files) != 2 || s.Expect.Files[0].Mode != "0600" || s.Expect.Files[1].Content == nil {
				t.Errorf("expect.files = %+v", s.Expect.Files)
			}
			if len(s.Expect.Trees) != 1 || !s.Expect.Trees[0].Private || len(s.Expect.Trees[0].Entries) != 2 {
				t.Errorf("expect.trees = %+v", s.Expect.Trees)
			}
			if s.Repeat == nil || s.Repeat.Expect.Exit == nil || !slices.Equal(s.Repeat.Unchanged, []string{"Invoices"}) {
				t.Errorf("repeat = %+v", s.Repeat)
			}
		}},
		{name: "state dir defaults to .facto", in: mutate("state_dir: state\n", ""), check: func(t *testing.T, s *Scenario) {
			if s.StateDir != DefaultStateDir {
				t.Errorf("state_dir = %q, want %q", s.StateDir, DefaultStateDir)
			}
		}},
		{name: "nonzero exit", in: mutate("  exit: 0\n  stdout", "  exit: 2\n  stdout"), check: func(t *testing.T, s *Scenario) {
			if *s.Expect.Exit != 2 {
				t.Errorf("exit = %d, want 2", *s.Expect.Exit)
			}
		}},

		// Format errors.
		{name: "unknown top-level key", in: validScenario + "timeout: 5s\n", wantErr: true},
		{name: "unknown nested key", in: mutate("    fixture: edf-invoice.pdf\n", "    fixture: edf-invoice.pdf\n    owner: root\n"), wantErr: true},
		{name: "second document", in: validScenario + "---\nname: other\n", wantErr: true},
		{name: "missing exit", in: mutate("  exit: 0\n  stdout", "  stdout"), wantErr: true},
		{name: "missing repeat exit", in: mutate("expect: { exit: 0 }", "expect: {}"), wantErr: true},
		{name: "empty args", in: mutate(`args: [collect, --config, "{{home}}/config.yaml"]`, "args: []"), wantErr: true},
		{name: "bad name", in: mutate("name: full-example", "name: Full_Example"), wantErr: true},
		{name: "unknown placeholder", in: mutate(`"{{home}}/config.yaml"]`, `"{{env:HOME}}/config.yaml"]`), wantErr: true},
		{name: "bad canary kind", in: mutate("{{canary:password}}", "{{canary:Pass word}}"), wantErr: true},
		{name: "two content sources", in: mutate("    fixture: edf-invoice.pdf\n", "    fixture: edf-invoice.pdf\n    content: x\n"), wantErr: true},
		{name: "no content source", in: mutate("  - path: Invoices/inbox/sub\n    dir: true\n", "  - path: Invoices/inbox/sub\n"), wantErr: true},
		{name: "mode not octal", in: mutate(`mode: "0600"`+"\n    content", `mode: "0800"`+"\n    content"), wantErr: true},
		{name: "mode with setuid", in: mutate(`mode: "0600"`+"\n    content", `mode: "4755"`+"\n    content"), wantErr: true},
		{name: "mode on a symlink", in: mutate("    symlink: ../../config.yaml\n", "    symlink: ../../config.yaml\n    mode: \"0600\"\n"), wantErr: true},
		{name: "expected file with fixture and content", in: mutate(`fixture: edf-invoice.pdf }`, `fixture: edf-invoice.pdf, content: x }`), wantErr: true},

		// Security negatives: nothing may point outside the sandboxed HOME.
		{name: "setup path traversal", in: mutate("path: Invoices/inbox/a.pdf", "path: ../escape.pdf"), wantErr: true},
		{name: "setup path traversal inside", in: mutate("path: Invoices/inbox/a.pdf", "path: Invoices/../../escape.pdf"), wantErr: true},
		{name: "setup absolute path", in: mutate("path: Invoices/inbox/a.pdf", "path: /tmp/escape.pdf"), wantErr: true},
		{name: "setup backslash path", in: mutate("path: Invoices/inbox/a.pdf", `path: 'Invoices\..\..\escape.pdf'`), wantErr: true},
		{name: "setup unclean path", in: mutate("path: Invoices/inbox/a.pdf", "path: Invoices//inbox/./a.pdf"), wantErr: true},
		{name: "fixture with separator", in: mutate("    fixture: edf-invoice.pdf\n", "    fixture: ../../../go.mod\n"), wantErr: true},
		{name: "hidden fixture", in: mutate("    fixture: edf-invoice.pdf\n", "    fixture: .env\n"), wantErr: true},
		{name: "symlink escaping home", in: mutate("symlink: ../../config.yaml", "symlink: ../../../outside"), wantErr: true},
		{name: "absolute symlink", in: mutate("symlink: ../../config.yaml", "symlink: /etc/passwd"), wantErr: true},
		{name: "state dir outside home", in: mutate("state_dir: state", "state_dir: ../state"), wantErr: true},
		{name: "expected file outside home", in: mutate("path: Invoices/2026/a.pdf", "path: ../a.pdf"), wantErr: true},
		{name: "absent outside home", in: mutate("absent: [Invoices/inbox/a.pdf]", "absent: [/etc]"), wantErr: true},
		{name: "tree outside home", in: mutate("{ path: Invoices, private", "{ path: .., private"), wantErr: true},
		{name: "unchanged outside home", in: mutate("unchanged: [Invoices]", "unchanged: [../Invoices]"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := Parse([]byte(tt.in))
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidScenario) {
					t.Fatalf("Parse err = %v, want ErrInvalidScenario", err)
				}
				t.Logf("rejected: %v", err)
				if s != nil {
					t.Errorf("Parse returned a scenario with an error: %+v", s)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if tt.check != nil {
				tt.check(t, s)
			}
		})
	}
}

func TestExpand(t *testing.T) {
	t.Parallel()
	calls := map[string]int{}
	canary := func(kind string) string { calls[kind]++; return "C-" + kind }
	got := Expand("{{home}}/c.yaml pw={{canary:password}} {{other}}", "/h", canary)
	if want := "/h/c.yaml pw=C-password {{other}}"; got != want {
		t.Errorf("Expand = %q, want %q", got, want)
	}
	if calls["password"] != 1 {
		t.Errorf("canary(password) called %d times, want 1", calls["password"])
	}
}

// TestScenarioFiles_Parse checks every checked-in scenario parses, is named
// after its file and uses only fixtures that exist.
func TestScenarioFiles_Parse(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		data, err := readIn(".", f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		s, err := Parse(data)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if stem := strings.TrimSuffix(f, ".yaml"); s.Name != stem {
			t.Errorf("%s: name %q, want %q", f, s.Name, stem)
		}
		var fixtures []string
		for _, sf := range s.Setup {
			fixtures = append(fixtures, sf.Fixture)
		}
		for _, e := range append([]Expect{s.Expect}, repeatExpect(s)...) {
			for _, ef := range e.Files {
				fixtures = append(fixtures, ef.Fixture)
			}
		}
		for _, fx := range fixtures {
			if fx == "" {
				continue
			}
			if _, err := readIn("testdata", fx); err != nil {
				t.Errorf("%s: fixture %s: %v", f, fx, err)
			}
		}
	}
}

func repeatExpect(s *Scenario) []Expect {
	if s.Repeat == nil {
		return nil
	}
	return []Expect{s.Repeat.Expect}
}
