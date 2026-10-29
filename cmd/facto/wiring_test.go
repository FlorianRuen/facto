// Tests for the CLI wiring details (J0 task T25) not pinned by
// main_test.go: the terminal prompter, the default config path, directory
// creation and the provider defaults. All files are synthetic.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

func TestLinePrompter_AskDoc(t *testing.T) {
	t.Parallel()
	day := time.Date(2026, time.March, 14, 0, 0, 0, 0, time.UTC)
	guess := normalize.Doc{Provider: "edf", Category: "energy", Kind: connector.Invoice, Ext: "pdf"}
	dated := guess
	dated.Date = day
	for _, tc := range []struct {
		name   string
		guess  normalize.Doc
		input  string
		want   normalize.Doc
		wantOK bool
	}{
		{
			name:   "keep provider, type date",
			guess:  guess,
			input:  "\n2026-03-14\n",
			want:   dated,
			wantOK: true,
		},
		{
			name:  "new provider clears category",
			guess: guess,
			input: "Ileo\n2026-03-14\n",
			want: normalize.Doc{
				Provider: "Ileo", Kind: connector.Invoice, Ext: "pdf", Date: day,
			},
			wantOK: true,
		},
		{name: "default date kept", guess: dated, input: "\n\n", want: dated, wantOK: true},
		{name: "no date skips", guess: guess, input: "\n\n"},
		{name: "invalid date skips", guess: guess, input: "\n14/03/2026\n"},
		{name: "dash skips provider", guess: guess, input: "-\n"},
		{name: "dash skips date", guess: guess, input: "\n-\n"},
		{name: "end of input skips", guess: guess, input: ""},
		{name: "end of input on date skips", guess: guess, input: "edf\n"},
		{name: "last line without newline", guess: guess, input: "\n2026-03-14", want: dated, wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			p := newLinePrompter(strings.NewReader(tc.input), &out)
			got, ok, err := p.AskDoc(t.Context(), "edf/scan\x1b[2J.pdf", tc.guess)
			if err != nil {
				t.Fatalf("AskDoc error = %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("doc = %+v, want %+v", got, tc.want)
			}
			if strings.Contains(out.String(), "\x1b") {
				t.Errorf("prompt output carries a raw control character: %q", out.String())
			}
		})
	}
}

func TestLinePrompter_Canceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out bytes.Buffer
	_, ok, err := newLinePrompter(strings.NewReader("edf\n2026-03-14\n"), &out).AskDoc(ctx, "a.pdf", normalize.Doc{})
	if !errors.Is(err, context.Canceled) || ok {
		t.Fatalf("AskDoc = ok %v, err %v; want context.Canceled", ok, err)
	}
	if out.Len() != 0 {
		t.Errorf("prompted after cancellation: %q", out.String())
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }

func TestLinePrompter_ReadError(t *testing.T) {
	t.Parallel()
	_, ok, err := newLinePrompter(failingReader{}, &bytes.Buffer{}).AskDoc(t.Context(), "a.pdf", normalize.Doc{})
	if err == nil || ok {
		t.Fatalf("AskDoc = ok %v, err %v; want a read error", ok, err)
	}
}

func TestConfigPathFor(t *testing.T) {
	t.Parallel()
	vars := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	// Synthetic absolute paths for the OS running the test: configPathFor
	// requires filepath.IsAbs, and on Windows "/home" has no drive letter.
	abs := filepath.FromSlash
	if runtime.GOOS == "windows" {
		abs = func(p string) string { return `C:` + filepath.FromSlash(p) }
	}
	home := abs("/home/synthetic")
	for _, tc := range []struct {
		name, goos, home string
		env              map[string]string
		want             string // "" = error
	}{
		{name: "linux default", goos: "linux", home: home, want: filepath.Join(home, ".config", "facto", "config.yaml")},
		{name: "linux xdg", goos: "linux", home: home, env: map[string]string{"XDG_CONFIG_HOME": abs("/xdg")}, want: filepath.Join(abs("/xdg"), "facto", "config.yaml")},
		{name: "linux relative xdg ignored", goos: "linux", home: home, env: map[string]string{"XDG_CONFIG_HOME": "rel"}, want: filepath.Join(home, ".config", "facto", "config.yaml")},
		{name: "darwin", goos: "darwin", home: home, want: filepath.Join(home, "Library", "Application Support", "facto", "config.yaml")},
		{name: "windows appdata", goos: "windows", home: home, env: map[string]string{"APPDATA": abs("/appdata")}, want: filepath.Join(abs("/appdata"), "facto", "config.yaml")},
		{name: "windows default", goos: "windows", home: home, want: filepath.Join(home, "AppData", "Roaming", "facto", "config.yaml")},
		{name: "no home", goos: "linux"},
		{name: "relative home", goos: "darwin", home: "rel"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := configPathFor(tc.goos, env{Home: tc.home, LookupEnv: vars(tc.env)})
			if tc.want == "" {
				if !errors.Is(err, errNoConfigDir) {
					t.Fatalf("configPathFor = %q, %v; want errNoConfigDir", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("configPathFor = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	if _, err := configPathFor("linux", env{Home: home}); err != nil {
		t.Errorf("nil LookupEnv: %v", err)
	}
}

func TestRun_CollectNoConfigDirExit2(t *testing.T) {
	t.Parallel()
	e := env{Clock: newSandbox(t).env().Clock, LookupEnv: func(string) (string, bool) { return "", false }}
	r := invoke(t.Context(), e, "", "collect")
	if r.code != 2 || !strings.Contains(r.stderr, "--config") {
		t.Fatalf("exit code = %d, stderr = %q; want 2 naming --config", r.code, r.stderr)
	}
}

// TestRun_CollectEnabledConnectorExit2: no supplier connector ships in J0,
// so an enabled one is a configuration error naming it, before anything is
// created.
func TestRun_CollectEnabledConnectorExit2(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig+"connectors:\n  ileo: { enabled: true, category: housing }\n")
	r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if r.code != 2 || !strings.Contains(r.stderr, "connectors.ileo") {
		t.Fatalf("exit code = %d, stderr = %q; want 2 naming connectors.ileo", r.code, r.stderr)
	}
	if _, err := os.Stat(s.state); !os.IsNotExist(err) {
		t.Errorf("state dir created on a configuration error (stat err = %v)", err)
	}
}

// TestRun_CollectCreatesMissingFolders: a missing output folder and inbox
// are created 0700 on the first run.
func TestRun_CollectCreatesMissingFolders(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, "output: { local: ~/Fresh }\nstate_dir: ~/.facto\nnotify: none\n")
	r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if r.code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr:\n%s", r.code, r.stderr)
	}
	for _, d := range []string{"Fresh", "Fresh/inbox"} {
		fi, err := os.Lstat(filepath.Join(s.home, filepath.FromSlash(d)))
		if err != nil {
			t.Fatalf("lstat %s: %v", d, err)
		}
		if !fi.IsDir() || (isUnix() && fi.Mode().Perm() != 0o700) {
			t.Errorf("%s mode = %v, want a 0700 directory", d, fi.Mode())
		}
	}
	if !strings.Contains(r.stdout, "no documents") {
		t.Errorf("stdout = %q, want the empty report summary", r.stdout)
	}
}

// TestRun_CollectOutputNotDirectoryExit1: an output.local that is a file is
// a failed run (exit 1) that writes no report.
func TestRun_CollectOutputNotDirectoryExit1(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	writeFile(t, s.home, "Blocked", []byte("synthetic"))
	cfg := s.writeConfig(t, "output: { local: ~/Blocked }\nstate_dir: ~/.facto\nnotify: none\n")
	r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stderr, "output folder") {
		t.Fatalf("exit code = %d, stderr = %q; want 1 naming the output folder", r.code, r.stderr)
	}
	if _, err := os.Stat(s.state); !os.IsNotExist(err) {
		t.Errorf("state dir created (stat err = %v)", err)
	}
}

// TestRun_CollectGDriveWarns: the Drive destination is not wired in J0; the
// run files locally and says so on stderr.
func TestRun_CollectGDriveWarns(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, strings.Replace(validConfig, "  local: ~/Invoices\n", "  local: ~/Invoices\n  gdrive: { enabled: true }\n", 1))
	r := invoke(t.Context(), s.env(), "", "collect", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stderr, "gdrive") {
		t.Fatalf("exit code = %d, stderr = %q; want 0 with a gdrive warning", r.code, r.stderr)
	}
}

func TestRun_Help(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	r := invoke(t.Context(), s.env(), "", "--help")
	if r.code != 0 || !strings.Contains(r.stdout, "collect") || !strings.Contains(r.stdout, "version") {
		t.Fatalf("exit code = %d, stdout = %q; want 0 listing collect and version", r.code, r.stdout)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic write failure") }

func TestRun_OutputWriteFailureExit1(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)
	for _, args := range [][]string{{"version"}, {"collect", "--config", cfg}} {
		var errOut bytes.Buffer
		code := runEnv(t.Context(), s.env(), args, strings.NewReader(""), failingWriter{}, &errOut)
		if code != 1 || !strings.Contains(errOut.String(), "synthetic write failure") {
			t.Errorf("%v: exit code = %d, stderr = %q; want 1 with the write error", args, code, errOut.String())
		}
	}
}

func TestExitError(t *testing.T) {
	t.Parallel()
	if got := (&exitError{code: 1}).Error(); got != "exit code 1" {
		t.Errorf("Error() = %q", got)
	}
	cause := errors.New("synthetic cause")
	if e := (&exitError{code: 2, err: cause}); e.Error() != "synthetic cause" || !errors.Is(e, cause) {
		t.Errorf("exitError does not expose its cause: %q", e.Error())
	}
}

func TestProviderDefaults(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Manual: []config.Manual{{ID: "impots", Category: "housing"}, {ID: "edf", Category: "manual-energy"}},
		Connectors: map[string]config.Connector{
			"edf":  {Category: "energy"},
			"ileo": {},
		},
	}
	got := providerDefaults(cfg)
	want := map[string]inbox.ProviderDefaults{
		"impots": {Category: "housing"},
		"edf":    {Category: "energy"},
	}
	if len(got) != len(want) {
		t.Fatalf("providerDefaults = %+v, want %+v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("providerDefaults[%s] = %+v, want %+v", k, got[k], v)
		}
	}
}

func TestIsTerminal(t *testing.T) {
	t.Parallel()
	if isTerminal(strings.NewReader("")) {
		t.Error("in-memory reader reported as a terminal")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if isTerminal(r) {
		t.Error("pipe reported as a terminal")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open null device: %v", err)
	}
	defer func() { _ = null.Close() }()
	if isTerminal(null) {
		t.Error("null device reported as a terminal")
	}
	closed, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open null device: %v", err)
	}
	_ = closed.Close()
	if isTerminal(closed) {
		t.Error("closed file reported as a terminal")
	}
}

func TestCloseErr(t *testing.T) {
	t.Parallel()
	if closeErr("x", nil) != nil {
		t.Error("closeErr(nil) != nil")
	}
	cause := errors.New("synthetic")
	if err := closeErr("index", cause); !errors.Is(err, cause) || !strings.Contains(err.Error(), "close index") {
		t.Errorf("closeErr = %v", err)
	}
}

func isUnix() bool {
	return !slices.Contains([]string{"windows", "plan9"}, runtimeGOOS)
}

// TestLinePrompter_LongAnswer: an answer line far longer than maxAnswerLen
// is cut to maxAnswerLen bytes, the rest of the line is discarded (the
// next answer is read from the next line), and a cut never splits a UTF-8
// rune.
func TestLinePrompter_LongAnswer(t *testing.T) {
	t.Parallel()
	day := time.Date(2026, time.March, 14, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, line, wantProvider string
	}{
		{
			name:         "4 MiB line",
			line:         strings.Repeat("x", 4<<20),
			wantProvider: strings.Repeat("x", maxAnswerLen),
		},
		{
			name:         "rune across the cap",
			line:         strings.Repeat("x", maxAnswerLen-1) + "é" + strings.Repeat("y", 10),
			wantProvider: strings.Repeat("x", maxAnswerLen-1),
		},
		{
			name:         "rune ending at the cap",
			line:         strings.Repeat("x", maxAnswerLen-2) + "é" + strings.Repeat("y", 10),
			wantProvider: strings.Repeat("x", maxAnswerLen-2) + "é",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newLinePrompter(strings.NewReader(tc.line+"\n2026-03-14\n"), &bytes.Buffer{})
			got, ok, err := p.AskDoc(t.Context(), "a.pdf", normalize.Doc{Provider: "edf"})
			if err != nil || !ok {
				t.Fatalf("AskDoc = ok %v, err %v; want ok", ok, err)
			}
			if got.Provider != tc.wantProvider {
				t.Errorf("provider = %d bytes %.12q…, want %d bytes", len(got.Provider), got.Provider, len(tc.wantProvider))
			}
			if !got.Date.Equal(day) {
				t.Errorf("date = %v, want %v (read from the line after the long one)", got.Date, day)
			}
		})
	}
}

// TestConfigError: a configuration error exits 2 and wraps
// orchestrator.ErrConfig and its cause.
func TestConfigError(t *testing.T) {
	t.Parallel()
	cause := errors.New("synthetic cause")
	err := configError(cause)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != orchestrator.ExitConfig {
		t.Fatalf("configError = %#v, want an exitError with code %d", err, orchestrator.ExitConfig)
	}
	if !errors.Is(err, orchestrator.ErrConfig) || !errors.Is(err, cause) {
		t.Errorf("configError(%v) = %v, want it to wrap orchestrator.ErrConfig and the cause", cause, err)
	}
	if !strings.Contains(err.Error(), "configuration error") || !strings.Contains(err.Error(), "synthetic cause") {
		t.Errorf("message = %q", err.Error())
	}
}

// cancelingPrompter cancels the run when asked about an inbox file, like
// a Ctrl-C at the prompt.
type cancelingPrompter struct{ cancel context.CancelFunc }

func (p cancelingPrompter) AskDoc(ctx context.Context, _ string, _ normalize.Doc) (normalize.Doc, bool, error) {
	p.cancel()
	return normalize.Doc{}, false, fmt.Errorf("prompt: %w", ctx.Err())
}

// TestCollect_CanceledMidRunWritesReport: a run canceled after the state dir
// exists is exit 1 and still writes its report (context.WithoutCancel).
func TestCollect_CanceledMidRunWritesReport(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)
	writeFile(t, s.inbox, "scan.pdf", syntheticPDF(t))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var stdout, stderr bytes.Buffer

	err := collect(ctx, s.env(), collectParams{
		configPath: cfg,
		period:     connector.Year(2026),
		prompter:   cancelingPrompter{cancel: cancel},
		stdout:     &stdout,
		stderr:     &stderr,
	})
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != orchestrator.ExitAttention {
		t.Fatalf("collect = %v, want exit %d\nstderr:\n%s", err, orchestrator.ExitAttention, stderr.String())
	}
	if ctx.Err() == nil {
		t.Fatal("the prompter was never called: the run was not canceled mid-run")
	}
	for _, f := range []string{reportBase + ".json", reportBase + ".txt"} {
		if _, err := os.Stat(filepath.Join(s.state, "reports", f)); err != nil {
			t.Errorf("report %s not written after cancellation: %v", f, err)
		}
	}
	if stdout.Len() == 0 {
		t.Error("stdout is empty, want the report summary")
	}
}

// TestShutdownSignals: collect stops cleanly on Ctrl-C and on SIGTERM
// (systemd stop, launchd unload).
func TestShutdownSignals(t *testing.T) {
	t.Parallel()
	got := shutdownSignals()
	for _, want := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		if !slices.Contains(got, want) {
			t.Errorf("shutdownSignals() = %v, want it to contain %v", got, want)
		}
	}
}
