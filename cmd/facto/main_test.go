// Tests for the facto CLI (J0 task T25; docs/spec.md "Configuration,
// commands and scheduling"; ADR 0002, ADR 0007 D1/D5). Every test injects
// its home directory, clock and environment through runEnv: none reads the
// real HOME, the real environment, the real keyring or runs the bw binary
// (no connector is configured, so no secret provider is ever called). All
// files are synthetic.
package main

import (
	"bytes"
	"context"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// runStart is the fake clock time of every run: reports are named after it.
var runStart = time.Date(2026, time.March, 20, 9, 0, 0, 0, time.UTC)

const (
	// compliantName is a synthetic EDF invoice name the inbox identifies
	// without Factur-X (date + provider from the name).
	compliantName = "2026-03-14_edf_invoice_84-12EUR_10234567.pdf"
	// filedPath is where it lands with the default templates and the
	// "energy" category configured for edf.
	filedPath = "2026/energy/edf/" + compliantName
	// reportBase is the report name for runStart (orchestrator.WriteReport).
	reportBase = "20260320T090000Z"
)

// sandbox is one synthetic user: home/ (injected HOME), home/Invoices
// (output.local, holding inbox/) and home/.facto (state_dir).
type sandbox struct {
	home, out, inbox, state string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	s := &sandbox{
		home:  home,
		out:   filepath.Join(home, "Invoices"),
		inbox: filepath.Join(home, "Invoices", "inbox"),
		state: filepath.Join(home, ".facto"),
	}
	root, err := fsx.Open(filepath.Dir(home))
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	for _, d := range []string{"home", "home/Invoices", "home/Invoices/inbox"} {
		if err := root.MkdirPrivate(d); err != nil {
			t.Fatalf("setup mkdir %s: %v", d, err)
		}
	}
	return s
}

// env returns the injected environment: the sandbox home, a fake clock, an
// empty process environment, no OS keyring (J1 T19: no test reaches the
// real keyring; sessions fall back to ephemeral with one warning) and no
// installed browser.
func (s *sandbox) env() env {
	return env{
		Home:             s.home,
		Clock:            clock.NewFake(runStart),
		LookupEnv:        func(string) (string, bool) { return "", false },
		KeyBackend:       noKeyring,
		InstalledBrowser: noInstalledBrowser,
	}
}

// validConfig is a minimal config: inbox only, no connector, no
// notification, edf filed under "energy" through a manual entry.
const validConfig = `output:
  local: ~/Invoices
state_dir: ~/.facto
notify: none
manual:
  - { id: edf, name: "EDF", category: energy }
`

// writeConfig writes data as a 0600 config.yaml under the sandbox home and
// returns its path.
func (s *sandbox) writeConfig(t *testing.T, data string) string {
	t.Helper()
	writeFile(t, s.home, "config.yaml", []byte(data))
	return filepath.Join(s.home, "config.yaml")
}

// writeFile creates rel (slash-separated, parents created 0700) under dir
// through fsx, mode 0600.
func writeFile(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	root, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if d := path.Dir(rel); d != "." {
		if err := root.MkdirPrivate(d); err != nil {
			t.Fatalf("setup mkdir %s: %v", d, err)
		}
	}
	if err := root.WriteAtomic(t.Context(), rel, data); err != nil {
		t.Fatalf("setup write %s: %v", rel, err)
	}
}

// syntheticPDF is the synthetic one-page PDF of the facturx tests (no
// embedded file: identification comes from the name).
func syntheticPDF(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "normalize", "facturx", "testdata", "minimal.pdf"))
	if err != nil {
		t.Fatalf("read synthetic pdf: %v", err)
	}
	return b
}

// result is the outcome of one CLI invocation.
type result struct {
	code           int
	stdout, stderr string
}

// invoke runs the CLI with e and args, stdin not a terminal (empty unless
// given).
func invoke(ctx context.Context, e env, stdin string, args ...string) result {
	var out, errOut bytes.Buffer
	code := runEnv(ctx, e, args, strings.NewReader(stdin), &out, &errOut)
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

// regularFiles lists regular files under dir (slash paths, sorted); a
// missing dir lists nothing.
func regularFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p == dir {
				return filepath.SkipDir
			}
			return err
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	slices.Sort(out)
	return out
}

func TestRun_CollectFilesInbox(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)
	doc := syntheticPDF(t)
	writeFile(t, s.inbox, compliantName, doc)

	r := invoke(t.Context(), s.env(), "", "collect", "--year", "2026", "--config", cfg)

	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	got, err := os.ReadFile(filepath.Join(s.out, filepath.FromSlash(filedPath)))
	if err != nil {
		t.Fatalf("filed document: %v (output files: %q)", err, regularFiles(t, s.out))
	}
	if !bytes.Equal(got, doc) {
		t.Fatal("filed document content differs from the inbox file")
	}
	if left := regularFiles(t, s.inbox); len(left) != 0 {
		t.Errorf("inbox after collect = %q, want empty (filed files are removed)", left)
	}
	if !strings.Contains(r.stdout, "filed 1") {
		t.Errorf("stdout = %q, want the report summary with \"filed 1\"", r.stdout)
	}
	// The index and the report live in the state dir, never in the output
	// folder (ADR 0007 D1); the report is named after the injected clock.
	for _, f := range []string{"index.db", "reports/" + reportBase + ".json", "reports/" + reportBase + ".txt"} {
		if _, err := os.Stat(filepath.Join(s.state, filepath.FromSlash(f))); err != nil {
			t.Errorf("state file %s: %v", f, err)
		}
	}
	for _, f := range regularFiles(t, s.out) {
		if f != filedPath {
			t.Errorf("unexpected file in the output folder: %s", f)
		}
	}
}

func TestRun_CollectSecondRunIdempotent(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)
	writeFile(t, s.inbox, compliantName, syntheticPDF(t))

	first := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if first.code != 0 {
		t.Fatalf("first run exit code = %d, want 0\nstderr:\n%s", first.code, first.stderr)
	}
	before := regularFiles(t, s.out)

	second := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if second.code != 0 {
		t.Fatalf("second run exit code = %d, want 0\nstderr:\n%s", second.code, second.stderr)
	}
	if after := regularFiles(t, s.out); !slices.Equal(after, before) {
		t.Errorf("output after second run = %q, want unchanged %q", after, before)
	}
}

// TestRun_CollectNonInteractiveWhenStdinNotTTY: stdin is not a terminal, so
// collect never prompts, even without --non-interactive: a file identified
// only by its subfolder (no date) stays in the inbox (ADR 0007 D2) and the
// answers waiting on stdin are never read as provider/date.
func TestRun_CollectNonInteractiveWhenStdinNotTTY(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "auto (stdin not a TTY)", args: []string{"collect"}},
		{name: "explicit flag", args: []string{"collect", "--non-interactive"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			cfg := s.writeConfig(t, validConfig)
			writeFile(t, s.inbox, "edf/scan.pdf", syntheticPDF(t))

			args := append(slices.Clone(tc.args), "--config", cfg)
			r := invoke(t.Context(), s.env(), "edf\n2026-03-14\n", args...)

			if r.code != 0 {
				t.Fatalf("exit code = %d, want 0 (leftovers are warnings)\nstderr:\n%s", r.code, r.stderr)
			}
			if got := regularFiles(t, s.inbox); !slices.Equal(got, []string{"edf/scan.pdf"}) {
				t.Errorf("inbox = %q, want the undated file left in place", got)
			}
			if got := regularFiles(t, filepath.Join(s.out, "2026")); len(got) != 0 {
				t.Errorf("filed = %q, want nothing (no prompt answered from stdin)", got)
			}
		})
	}
}

// TestRun_CollectZeroConnectorsExit0: inbox-only setup with an empty inbox
// exits 0 (ADR 0007 D5).
func TestRun_CollectZeroConnectorsExit0(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)

	r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", r.code, r.stderr)
	}
}

// TestRun_CollectCanceledExit1: a canceled run is exit 1, not a
// configuration error, and files nothing.
func TestRun_CollectCanceledExit1(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)
	writeFile(t, s.inbox, compliantName, syntheticPDF(t))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	r := invoke(ctx, s.env(), "", "collect", "--config", cfg)
	if r.code != 1 {
		t.Fatalf("exit code = %d, want 1\nstderr:\n%s", r.code, r.stderr)
	}
	if got := regularFiles(t, filepath.Join(s.out, "2026")); len(got) != 0 {
		t.Errorf("filed = %q, want nothing after cancellation", got)
	}
}

func TestRun_ConfigErrorExit2(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		// config is written to home/config.yaml unless empty.
		config string
		// args after "collect"; "{cfg}" is replaced by the config path.
		args []string
		// stderrHas is a fragment the error message must contain (the key
		// or flag at fault).
		stderrHas string
	}{
		{
			name:      "missing config file",
			args:      []string{"--config", "{home}/absent.yaml"},
			stderrHas: "config",
		},
		{
			name:      "unknown key",
			config:    validConfig + "outptu: {}\n",
			args:      []string{"--config", "{cfg}"},
			stderrHas: "outptu",
		},
		{
			name:      "unsupported value",
			config:    "notify: sometimes\n",
			args:      []string{"--config", "{cfg}"},
			stderrHas: "notify",
		},
		{
			name:      "state dir inside output",
			config:    "output: { local: ~/Invoices }\nstate_dir: ~/Invoices/.facto\nnotify: none\n",
			args:      []string{"--config", "{cfg}"},
			stderrHas: "state_dir",
		},
		{
			name:      "plaintext password",
			config:    validConfig + "connectors:\n  edf: { enabled: true, password: hunter-synthetic }\n",
			args:      []string{"--config", "{cfg}"},
			stderrHas: "connectors.edf.password",
		},
		{
			name:      "year not a number",
			config:    validConfig,
			args:      []string{"--config", "{cfg}", "--year", "twenty"},
			stderrHas: "year",
		},
		{
			name:      "year out of range",
			config:    validConfig,
			args:      []string{"--config", "{cfg}", "--year", "99999"},
			stderrHas: "year",
		},
		{
			name:      "year zero",
			config:    validConfig,
			args:      []string{"--config", "{cfg}", "--year", "0"},
			stderrHas: "year",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			cfg := filepath.Join(s.home, "config.yaml")
			if tc.config != "" {
				s.writeConfig(t, tc.config)
			}
			writeFile(t, s.inbox, compliantName, syntheticPDF(t))
			args := []string{"collect"}
			for _, a := range tc.args {
				a = strings.ReplaceAll(a, "{cfg}", cfg)
				args = append(args, strings.ReplaceAll(a, "{home}", s.home))
			}

			r := invoke(t.Context(), s.env(), "", args...)

			if r.code != 2 {
				t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
			}
			if !strings.Contains(r.stderr, tc.stderrHas) {
				t.Errorf("stderr = %q, want it to name %q", r.stderr, tc.stderrHas)
			}
			// A configuration error stops before anything is touched.
			if got := regularFiles(t, s.inbox); !slices.Equal(got, []string{compliantName}) {
				t.Errorf("inbox = %q, want untouched", got)
			}
			if got := regularFiles(t, filepath.Join(s.out, "2026")); len(got) != 0 {
				t.Errorf("filed = %q, want nothing on a configuration error", got)
			}
			if _, err := os.Stat(s.state); !os.IsNotExist(err) {
				t.Errorf("state dir created on a configuration error (stat err = %v)", err)
			}
		})
	}
}

// TestRun_ConfigErrorNeverPrintsSecret: a secret pasted in the config (in a
// secret field, a typo'd key or a wrongly typed value) never reaches stdout
// or stderr.
func TestRun_ConfigErrorNeverPrintsSecret(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		config func(canary string) string
	}{
		{
			name: "plaintext password field",
			config: func(c string) string {
				return validConfig + "connectors:\n  edf: { enabled: true, login: bw://3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90/username, password: " + c + " }\n"
			},
		},
		{
			name: "plaintext otp field",
			config: func(c string) string {
				return validConfig + "connectors:\n  edf: { enabled: true, otp: " + c + " }\n"
			},
		},
		{
			name: "secret under a misspelled key",
			config: func(c string) string {
				return validConfig + "connectors:\n  edf: { enabled: true, pasword: " + c + " }\n"
			},
		},
		{
			name: "secret as a wrongly typed value",
			config: func(c string) string {
				return validConfig + "connectors:\n  edf: { enabled: " + c + " }\n"
			},
		},
		{
			name: "secret as a relative path",
			config: func(c string) string {
				return "output: { local: " + c + " }\nnotify: none\n"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Password)
			s := newSandbox(t)
			cfg := s.writeConfig(t, tc.config(canary))

			r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)

			// Keep the outputs as artifacts: make leakcheck scans them too.
			writeFile(t, testsecrets.ArtifactDir(t), "stdout.txt", []byte(r.stdout))
			writeFile(t, testsecrets.ArtifactDir(t), "stderr.txt", []byte(r.stderr))

			if r.code != 2 {
				t.Errorf("exit code = %d, want 2", r.code)
			}
			if r.stderr == "" {
				t.Error("stderr is empty, want a configuration error message")
			}
			for name, out := range map[string]string{"stdout": r.stdout, "stderr": r.stderr} {
				if strings.Contains(out, canary) || strings.Contains(out, testsecrets.Prefix) {
					t.Errorf("%s leaks the canary secret:\n%s", name, out)
				}
			}
		})
	}
}

func TestRun_Version(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "subcommand", args: []string{"version"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out, errOut bytes.Buffer
			// version touches no file: the production entry point is safe here.
			code := run(t.Context(), tc.args, strings.NewReader(""), &out, &errOut)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0\nstderr:\n%s", code, errOut.String())
			}
			if version == "" {
				t.Fatal("version is empty, want a value (\"dev\" unless set by -ldflags)")
			}
			if want := "facto " + version; !strings.HasPrefix(out.String(), want) {
				t.Errorf("stdout = %q, want it to start with %q", out.String(), want)
			}
			if errOut.Len() != 0 {
				t.Errorf("stderr = %q, want empty", errOut.String())
			}
		})
	}
}

func TestRun_UnknownFlag(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		args      []string
		stderrHas string
	}{
		{name: "collect unknown flag", args: []string{"collect", "--bogus"}, stderrHas: "--bogus"},
		{name: "root unknown flag", args: []string{"--bogus"}, stderrHas: "--bogus"},
		{name: "version unknown flag", args: []string{"version", "--bogus"}, stderrHas: "--bogus"},
		{name: "unknown shorthand", args: []string{"collect", "-Z"}, stderrHas: "-Z"},
		{name: "unknown command", args: []string{"frobnicate"}, stderrHas: "frobnicate"},
		{name: "year without value", args: []string{"collect", "--year"}, stderrHas: "year"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newSandbox(t)
			s.writeConfig(t, validConfig)
			writeFile(t, s.inbox, compliantName, syntheticPDF(t))

			r := invoke(t.Context(), s.env(), "", tc.args...)

			if r.code != 2 {
				t.Fatalf("exit code = %d, want 2 (usage error)\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
			}
			if !strings.Contains(r.stderr, tc.stderrHas) {
				t.Errorf("stderr = %q, want it to name %q", r.stderr, tc.stderrHas)
			}
			if r.stdout != "" {
				t.Errorf("stdout = %q, want empty (errors go to stderr)", r.stdout)
			}
			if got := regularFiles(t, s.inbox); !slices.Equal(got, []string{compliantName}) {
				t.Errorf("inbox = %q, want untouched", got)
			}
			if _, err := os.Stat(s.state); !os.IsNotExist(err) {
				t.Errorf("state dir created on a usage error (stat err = %v)", err)
			}
		})
	}
}

// TestRun_DefaultConfigUnderInjectedHome: without --config the config path
// is resolved under the injected home, never the real one: an empty
// sandbox home is a configuration error (exit 2) and nothing is created.
func TestRun_DefaultConfigUnderInjectedHome(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)

	r := invoke(t.Context(), s.env(), "", "collect")

	if r.code != 2 {
		t.Fatalf("exit code = %d, want 2 (no config under the injected home)\nstderr:\n%s", r.code, r.stderr)
	}
	if got := regularFiles(t, s.home); len(got) != 0 {
		t.Errorf("files created under home = %q, want none", got)
	}
}
