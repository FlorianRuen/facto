// Tests for scripts/scanners-json (J0 task T29). `make audit` runs every
// scanner even when one fails, records each exit status, then runs this
// program, which writes security/scanners.json (the "scanners" part of
// security/score.schema.json) and exits non-zero if any scanner failed.
//
// Input format (the contract with the Makefile):
//
//	.cache/audit/<name>.status   one file per scanner, written by the Makefile
//	                             as `<scanner> ...; echo $$? > .cache/audit/<name>.status`.
//	                             Content: the decimal exit status; surrounding
//	                             ASCII whitespace is ignored.
//
// A scanner is "pass" only if its status file is a regular file (not a
// symlink) of at most 64 bytes whose trimmed content is exactly "0". Anything
// else is "fail": missing file, empty, non-zero, negative, non-numeric,
// oversized, symlink, directory. Status files for scanners not in the expected
// list are ignored.
//
// Expected API (implementer: follow exactly; package main):
//
//	// defaultScanners is the expected list when -scanners is not given.
//	var defaultScanners = []string{"govulncheck", "gosec", "gitleaks", "osv-scanner"}
//
//	// run is main without os.Exit. Flags:
//	//   -status-dir dir   default ".cache/audit"
//	//   -out file         default "security/scanners.json"
//	//   -scanners a,b,c   default strings.Join(defaultScanners, ",")
//	// Scanner names must match ^[a-z0-9]+(-[a-z0-9]+)*$ and be unique.
//	// It writes -out atomically through fsx (0600; its directory must exist)
//	// as json.MarshalIndent(map[name]"pass"|"fail", "", "  ") + "\n", prints
//	// one "<name>: pass|fail" line per scanner (sorted by name) to stdout, and
//	// returns:
//	//   0 every scanner passed,
//	//   1 at least one failed (the file is still written),
//	//   2 usage or I/O error: bad flag, invalid/duplicate/empty scanner list,
//	//     unwritable -out (nothing is written; message on stderr).
//	func run(ctx context.Context, args []string, stdout, stderr io.Writer) int
//
//	func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

var allScanners = []string{"govulncheck", "gosec", "gitleaks", "osv-scanner"}

type env struct {
	statusDir string
	out       string
	root      *fsx.Root // over statusDir
}

func newEnv(t *testing.T) env {
	t.Helper()
	statusDir := t.TempDir()
	r, err := fsx.Open(statusDir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return env{statusDir: statusDir, out: filepath.Join(t.TempDir(), "scanners.json"), root: r}
}

func (e env) status(t *testing.T, name, content string) {
	t.Helper()
	if err := e.root.WriteAtomic(context.Background(), name+".status", []byte(content)); err != nil {
		t.Fatalf("write status %s: %v", name, err)
	}
}

func (e env) run(t *testing.T, extra ...string) (code int, stdout, stderr string) {
	t.Helper()
	args := append([]string{"-status-dir", e.statusDir, "-out", e.out}, extra...)
	var o, x bytes.Buffer
	code = run(context.Background(), args, &o, &x)
	return code, o.String(), x.String()
}

func readJSON(t *testing.T, p string) (map[string]string, []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s is not a JSON object of strings: %v\n%s", p, err, b)
	}
	return m, b
}

func assertNoFile(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s exists (Lstat err = %v), want nothing written", p, err)
	}
}

func TestScannersJSON_AllPass(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, s := range allScanners {
		e.status(t, s, "0\n")
	}
	code, stdout, stderr := e.run(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	_, raw := readJSON(t, e.out)
	want := "{\n" +
		"  \"gitleaks\": \"pass\",\n" +
		"  \"gosec\": \"pass\",\n" +
		"  \"govulncheck\": \"pass\",\n" +
		"  \"osv-scanner\": \"pass\"\n" +
		"}\n"
	if string(raw) != want {
		t.Errorf("scanners.json =\n%s\nwant\n%s", raw, want)
	}
	wantOut := "gitleaks: pass\ngosec: pass\ngovulncheck: pass\nosv-scanner: pass\n"
	if !strings.Contains(stdout, wantOut) {
		t.Errorf("stdout = %q, want it to contain %q", stdout, wantOut)
	}
}

func TestScannersJSON_OneFail(t *testing.T) {
	t.Parallel()
	for _, failing := range allScanners {
		t.Run(failing, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			for _, s := range allScanners {
				st := "0\n"
				if s == failing {
					st = "1\n"
				}
				e.status(t, s, st)
			}
			code, stdout, _ := e.run(t)
			if code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			got, _ := readJSON(t, e.out)
			for _, s := range allScanners {
				want := "pass"
				if s == failing {
					want = "fail"
				}
				if got[s] != want {
					t.Errorf("%s = %q, want %q", s, got[s], want)
				}
			}
			if len(got) != len(allScanners) {
				t.Errorf("got %d scanners %v, want %d", len(got), got, len(allScanners))
			}
			if !strings.Contains(stdout, failing+": fail\n") {
				t.Errorf("stdout %q does not report %s as failed", stdout, failing)
			}
		})
	}
}

func TestScannersJSON_MissingStatusIsFail(t *testing.T) {
	t.Parallel()

	t.Run("one missing", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		for _, s := range allScanners {
			if s != "gitleaks" {
				e.status(t, s, "0\n")
			}
		}
		code, _, _ := e.run(t)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		got, _ := readJSON(t, e.out)
		if got["gitleaks"] != "fail" {
			t.Errorf("gitleaks = %q, want fail (no status recorded)", got["gitleaks"])
		}
		if got["gosec"] != "pass" {
			t.Errorf("gosec = %q, want pass", got["gosec"])
		}
	})

	t.Run("status dir missing", func(t *testing.T) {
		t.Parallel()
		out := filepath.Join(t.TempDir(), "scanners.json")
		var o, x bytes.Buffer
		code := run(context.Background(),
			[]string{"-status-dir", filepath.Join(t.TempDir(), "absent"), "-out", out}, &o, &x)
		if code != 1 {
			t.Fatalf("exit = %d, want 1 (every scanner fails)", code)
		}
		got, _ := readJSON(t, out)
		for _, s := range allScanners {
			if got[s] != "fail" {
				t.Errorf("%s = %q, want fail", s, got[s])
			}
		}
	})
}

func TestScannersJSON_StatusParsing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"zero", "0", "pass"},
		{"zero newline", "0\n", "pass"},
		{"zero crlf and spaces", "  0 \r\n", "pass"},
		{"one", "1\n", "fail"},
		{"gosec style non-zero", "3\n", "fail"},
		{"signal", "137\n", "fail"},
		{"negative", "-1\n", "fail"},
		{"empty", "", "fail"},
		{"whitespace only", " \n", "fail"},
		{"leading zeros", "00\n", "fail"},
		{"plus sign", "+0\n", "fail"},
		{"word", "ok\n", "fail"},
		{"keyword", "pass\n", "fail"},
		{"two lines", "0\n1\n", "fail"},
		{"oversized", "0" + strings.Repeat(" ", 100), "fail"},
		{"NUL", "0\x00", "fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.status(t, "gosec", tt.content)
			code, _, stderr := e.run(t, "-scanners", "gosec")
			wantCode := 0
			if tt.want == "fail" {
				wantCode = 1
			}
			if code != wantCode {
				t.Fatalf("exit = %d, want %d (stderr %q)", code, wantCode, stderr)
			}
			got, _ := readJSON(t, e.out)
			if got["gosec"] != tt.want || len(got) != 1 {
				t.Errorf("scanners.json = %v, want {gosec: %s}", got, tt.want)
			}
		})
	}
}

func TestScannersJSON_OnlyExpectedScannersReported(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, s := range allScanners {
		e.status(t, s, "0\n")
	}
	e.status(t, "trivy", "1\n") // not expected: ignored, cannot fail the audit
	code, _, _ := e.run(t)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	got, _ := readJSON(t, e.out)
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := slices.Sorted(slices.Values(allScanners))
	if !slices.Equal(keys, want) {
		t.Errorf("scanners = %v, want %v", keys, want)
	}
}

func TestScannersJSON_CustomList(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.status(t, "gosec", "0\n")
	e.status(t, "actionlint", "0\n")
	code, _, _ := e.run(t, "-scanners", "gosec,actionlint")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	got, _ := readJSON(t, e.out)
	if len(got) != 2 || got["gosec"] != "pass" || got["actionlint"] != "pass" {
		t.Errorf("scanners.json = %v, want gosec and actionlint pass only", got)
	}
}

// TestScannersJSON_OutputMatchesScoreSchema checks the "scanners" shape of
// security/score.schema.json: an object whose values are "pass" or "fail".
func TestScannersJSON_OutputMatchesScoreSchema(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "security", "score.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Properties struct {
			Scanners struct {
				Type                 string `json:"type"`
				AdditionalProperties struct {
					Enum []string `json:"enum"`
				} `json:"additionalProperties"`
			} `json:"scanners"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	sc := schema.Properties.Scanners
	if sc.Type != "object" || len(sc.AdditionalProperties.Enum) == 0 {
		t.Fatalf("schema scanners = %+v, test out of date", sc)
	}

	e := newEnv(t)
	e.status(t, "gosec", "0\n")
	e.status(t, "gitleaks", "2\n")
	e.run(t)
	got, _ := readJSON(t, e.out)
	for k, v := range got {
		if !slices.Contains(sc.AdditionalProperties.Enum, v) {
			t.Errorf("%s = %q, not in schema enum %v", k, v, sc.AdditionalProperties.Enum)
		}
	}
}

func TestScannersJSON_UsageErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"-nope"}},
		{"positional argument", []string{"extra"}},
		{"empty list", []string{"-scanners", ""}},
		{"empty item", []string{"-scanners", "gosec,,gitleaks"}},
		{"duplicate", []string{"-scanners", "gosec,gosec"}},
		{"traversal", []string{"-scanners", "../../etc/passwd"}},
		{"separator", []string{"-scanners", "a/b"}},
		{"uppercase", []string{"-scanners", "GoSec"}},
		{"dot", []string{"-scanners", "gosec.status"}},
		{"leading dash", []string{"-scanners", "-gosec"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			for _, s := range allScanners {
				e.status(t, s, "0\n")
			}
			code, _, stderr := e.run(t, tt.args...)
			if code != 2 {
				t.Errorf("exit = %d, want 2", code)
			}
			if strings.TrimSpace(stderr) == "" {
				t.Error("stderr is empty, want a usage error message")
			}
			assertNoFile(t, e.out)
		})
	}
}

func TestScannersJSON_UnwritableOutput(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, s := range allScanners {
		e.status(t, s, "0\n")
	}
	out := filepath.Join(t.TempDir(), "missing-dir", "scanners.json")
	var o, x bytes.Buffer
	code := run(context.Background(), []string{"-status-dir", e.statusDir, "-out", out}, &o, &x)
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if strings.TrimSpace(x.String()) == "" {
		t.Error("stderr is empty, want an I/O error message")
	}
	assertNoFile(t, out)
}

func TestScannersJSON_SymlinkAndDirStatusAreFail(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		// Symlinks need privileges on Windows; the directory case still runs.
		t.Log("symlink case not exercised on windows")
	}
	e := newEnv(t)
	outside := t.TempDir()
	r, err := fsx.Open(outside)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(context.Background(), "forged.status", []byte("0\n")); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(outside, "forged.status"), filepath.Join(e.statusDir, "gosec.status")); err != nil {
			t.Fatalf("setup Symlink: %v", err)
		}
	}
	if err := e.root.MkdirPrivate("gitleaks.status"); err != nil {
		t.Fatalf("setup Mkdir: %v", err)
	}
	code, _, _ := e.run(t, "-scanners", "gosec,gitleaks")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	got, _ := readJSON(t, e.out)
	if runtime.GOOS != "windows" && got["gosec"] != "fail" {
		t.Errorf("gosec (symlinked status) = %q, want fail", got["gosec"])
	}
	if got["gitleaks"] != "fail" {
		t.Errorf("gitleaks (directory status) = %q, want fail", got["gitleaks"])
	}
}

func TestScannersJSON_ReplacesExistingOutput(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	outRoot, err := fsx.Open(filepath.Dir(e.out))
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = outRoot.Close() }()
	if err := outRoot.WriteAtomic(context.Background(), filepath.Base(e.out), []byte(`{"stale":"pass"}`)); err != nil {
		t.Fatalf("setup: %v", err)
	}
	e.status(t, "gosec", "0\n")
	if code, _, _ := e.run(t, "-scanners", "gosec"); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	got, _ := readJSON(t, e.out)
	if _, ok := got["stale"]; ok || got["gosec"] != "pass" {
		t.Errorf("scanners.json = %v, want only the new result", got)
	}
}

func TestScannersJSON_DefaultFlags(t *testing.T) {
	t.Parallel()
	if !slices.Equal(defaultScanners, allScanners) {
		t.Errorf("defaultScanners = %v, want %v", defaultScanners, allScanners)
	}
}

// TestMakefileAudit_RecordsEveryScanner pins the other half of the contract:
// `make audit` keeps going after a failing scanner, records each status where
// this program reads it, and lets the program write scanners.json itself
// (through fsx) instead of redirecting stdout into it.
func TestMakefileAudit_RecordsEveryScanner(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	recipe := targetRecipe(t, string(b), "audit")
	for _, s := range allScanners {
		if !strings.Contains(recipe, ".cache/audit/"+s+".status") {
			t.Errorf("audit recipe does not record %s into .cache/audit/%s.status", s, s)
		}
	}
	if !strings.Contains(recipe, "./scripts/scanners-json") {
		t.Error("audit recipe does not run ./scripts/scanners-json")
	}
	if regexp.MustCompile(`>\s*security/scanners\.json`).MatchString(recipe) {
		t.Error("audit recipe redirects stdout into security/scanners.json; the program writes it through fsx")
	}
}

// targetRecipe returns the tab-indented recipe lines of target in a Makefile.
func targetRecipe(t *testing.T, makefile, target string) string {
	t.Helper()
	var out []string
	in := false
	for line := range strings.Lines(makefile) {
		switch {
		case strings.HasPrefix(line, target+":"):
			in = true
		case in && strings.HasPrefix(line, "\t"):
			out = append(out, line)
		case in && strings.TrimSpace(line) == "":
		case in:
			return strings.Join(out, "")
		}
	}
	if !in {
		t.Fatalf("Makefile has no %s target", target)
	}
	return strings.Join(out, "")
}
