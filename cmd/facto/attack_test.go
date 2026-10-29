//go:build unix

// Red-team attack tests for the CLI (J0 task T30): a state dir that sits
// inside the output folder (or its inbox) once symlinks are followed,
// secrets pasted in config fields that the CLI echoes on stderr, and
// terminal control sequences in inbox file names shown by the prompter.
// Uses newSandbox, validConfig, writeFile, invoke, regularFiles and
// syntheticPDF from main_test.go. CLI outputs are written under
// testsecrets.ArtifactDir so `make leakcheck` greps them. A test passes when
// the attack is defeated. Everything is synthetic.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestAttack_CLIStateDirInsideOutputThroughSymlinkRefused places the state
// dir (index, reports, later sessions) physically inside the output folder,
// which may be synced, while the two paths stay lexically apart: through a
// symlinked output.local (a supported setup, docs/spec.md), or through a
// symlinked parent of state_dir. docs/spec.md and ADR 0007 D1: the state dir
// is never inside the output folder. collect must refuse (exit 2, like the
// lexical case) and write no state file under the output folder.
func TestAttack_CLIStateDirInsideOutputThroughSymlinkRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// setup creates links in the sandbox and returns the config and the
		// physical output folder.
		setup func(t *testing.T, s *sandbox) (cfg, physOut string)
	}{
		{
			name: "output.local links to a folder holding state_dir",
			setup: func(t *testing.T, s *sandbox) (string, string) {
				if err := os.Symlink(s.home, filepath.Join(s.home, "Out")); err != nil {
					t.Fatalf("setup symlink: %v", err)
				}
				return strings.Replace(validConfig, "local: ~/Invoices", "local: ~/Out", 1), s.home
			},
		},
		{
			name: "state_dir parent links into the output folder",
			setup: func(t *testing.T, s *sandbox) (string, string) {
				if err := os.Symlink(s.out, filepath.Join(s.home, "st")); err != nil {
					t.Fatalf("setup symlink: %v", err)
				}
				return strings.Replace(validConfig, "state_dir: ~/.facto", "state_dir: ~/st/.facto", 1), s.out
			},
		},
		{
			name: "state_dir parent links into the inbox",
			setup: func(t *testing.T, s *sandbox) (string, string) {
				if err := os.Symlink(s.inbox, filepath.Join(s.home, "st")); err != nil {
					t.Fatalf("setup symlink: %v", err)
				}
				return strings.Replace(validConfig, "state_dir: ~/.facto", "state_dir: ~/st/state", 1), s.out
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			cfgText, physOut := tc.setup(t, s)
			cfg := s.writeConfig(t, cfgText)
			writeFile(t, s.inbox, compliantName, syntheticPDF(t))

			r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)

			var stateFiles []string
			for _, f := range regularFiles(t, physOut) {
				base := filepath.Base(f)
				if strings.HasPrefix(base, "index.db") || strings.HasPrefix(f, "reports/") || strings.Contains(f, "/reports/") {
					stateFiles = append(stateFiles, f)
				}
			}
			if r.code != 2 {
				t.Errorf("exit code = %d, want 2 (state dir inside the output folder)\nstderr:\n%s", r.code, r.stderr)
			}
			if len(stateFiles) > 0 {
				t.Errorf("state files written inside the physical output folder: %q", stateFiles)
			}
		})
	}
}

// TestAttack_CLIConfigSecretNeverOnStderr pastes a canary in config fields
// whose errors the CLI prints: naming templates (a password on the wrong
// line), YAML tags that fail to resolve, a block scalar in an enum. Exit 2,
// and neither stdout nor stderr may hold the canary.
func TestAttack_CLIConfigSecretNeverOnStderr(t *testing.T) {
	t.Parallel()
	cases := map[string]func(c string) string{
		"naming.file holding the password": func(c string) string {
			return validConfig + "naming:\n  file: \"" + c + "\"\n"
		},
		"naming.dir holding the password": func(c string) string {
			return validConfig + "naming:\n  dir: \"{year}/" + c + "\"\n"
		},
		"tagged password": func(c string) string {
			return validConfig + "connectors:\n  edf:\n    password: !!int " + c + "\n"
		},
		"block scalar in an enum": func(c string) string {
			return strings.Replace(validConfig, "notify: none", "notify: |\n  "+c, 1)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Password)
			s := newSandbox(t)
			cfg := s.writeConfig(t, mk(canary))
			r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
			writeFile(t, testsecrets.ArtifactDir(t), "stdout.txt", []byte(r.stdout))
			writeFile(t, testsecrets.ArtifactDir(t), "stderr.txt", []byte(r.stderr))
			if r.code != 2 {
				t.Errorf("exit code = %d, want 2", r.code)
			}
			for stream, out := range map[string]string{"stdout": r.stdout, "stderr": r.stderr} {
				if strings.Contains(out, canary) {
					t.Errorf("%s holds the canary: %s", stream, out)
				}
			}
		})
	}
}

// TestAttack_PrompterFileNameCannotDriveTerminal asks about inbox files
// whose names carry terminal control sequences (window title, screen clear,
// OSC 52 clipboard write, bidi override, carriage return). Nothing the
// prompter writes may contain a raw control byte.
func TestAttack_PrompterFileNameCannotDriveTerminal(t *testing.T) {
	t.Parallel()
	names := []string{
		"edf/\x1b]0;owned\x07.pdf",
		"\x1b[2J\x1b[Hfacture.pdf",
		"\x1b]52;c;ZWNobyBvd25lZA==\x07.pdf",
		"facture\u202egpj.pdf",
		"facture.pdf\rprovider [edf]: ",
		"\x9b31mred.pdf",
	}
	for _, name := range names {
		var out bytes.Buffer
		p := newLinePrompter(strings.NewReader("edf\n2026-03-14\n"), &out)
		if _, _, err := p.AskDoc(t.Context(), name, normalize.Doc{}); err != nil {
			t.Fatalf("AskDoc(%q): %v", name, err)
		}
		for _, r := range out.String() {
			if (r < 0x20 && r != '\n') || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '\u202e' {
				t.Errorf("prompt for %q writes control character %U:\n%q", name, r, out.String())
				break
			}
		}
	}
}
