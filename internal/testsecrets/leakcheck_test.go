//go:build !windows

// TestLeakcheckScript drives scripts/leakcheck.sh (J0 task T3) with a constant
// argv and an environment pointing at temp CANARY_FILE / ART_DIR.
//
// Expected script behaviour:
//   - CANARY_FILE missing or empty: exit 1, "no canaries recorded".
//   - otherwise greps every file (text AND binary: SQLite DBs, PDFs) under
//     ART_DIR and ./testdata for any canary, as fixed strings;
//   - a missing ./testdata is tolerated (the script runs from the package dir
//     here, which has no testdata/);
//   - prints "<n> canary hits" (n = number of files with a hit), exit 0 when
//     n == 0, exit 1 otherwise;
//   - any real grep error (e.g. missing ART_DIR) fails (non-zero exit) and
//     never prints "0 canary hits".
package testsecrets_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	leakCanaryA = "FACTO-CANARY-token-leakcheckfixtureAAAAAAAA"
	leakCanaryB = "FACTO-CANARY-cookie-leakcheckfixtureBBBBBBBB"
)

func TestLeakcheckScript(t *testing.T) {
	// The "missing testdata/ tolerated" contract relies on this.
	if _, err := os.Stat("testdata"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("internal/testsecrets/testdata must not exist (stat err = %v)", err)
	}

	tests := []struct {
		name      string
		canaries  []string          // nil: no canary file at all
		artifacts map[string]string // relative path under ART_DIR -> content
		noArtDir  bool
		wantExit  int // -1: any non-zero
		wantOut   string
		notOut    string
	}{
		{
			name:      "no hits",
			canaries:  []string{leakCanaryA},
			artifacts: map[string]string{"logx/TestX/log.txt": "level=INFO msg=synthetic token=***\n"},
			wantExit:  0,
			wantOut:   "0 canary hits",
		},
		{
			name:     "empty artifact dir",
			canaries: []string{leakCanaryA},
			wantExit: 0,
			wantOut:  "0 canary hits",
		},
		{
			name:     "planted hit",
			canaries: []string{leakCanaryA},
			artifacts: map[string]string{
				"logx/TestX/log.txt":   "level=INFO msg=login cookie=" + leakCanaryA + "\n",
				"logx/TestX/clean.txt": "nothing to see\n",
			},
			wantExit: 1,
			wantOut:  "1 canary hits",
		},
		{
			name:     "hits in two files",
			canaries: []string{leakCanaryA, leakCanaryB},
			artifacts: map[string]string{
				"a/report.json": `{"error":"` + leakCanaryA + `"}`,
				"b/c/log.txt":   leakCanaryB,
			},
			wantExit: 1,
			wantOut:  "2 canary hits",
		},
		{
			name:      "second canary of the list matches",
			canaries:  []string{leakCanaryA, leakCanaryB},
			artifacts: map[string]string{"x/log.txt": "set-cookie: " + leakCanaryB + "; Secure\n"},
			wantExit:  1,
			wantOut:   "1 canary hits",
		},
		{
			name:      "hit inside a binary file",
			canaries:  []string{leakCanaryA},
			artifacts: map[string]string{"store/index.db": "SQLite format 3\x00\x00\x01\x02" + leakCanaryA + "\x00\xff"},
			wantExit:  1,
			wantOut:   "1 canary hits",
		},
		{
			name:      "canaries are fixed strings not regexps",
			canaries:  []string{"FACTO.CANARY.*"},
			artifacts: map[string]string{"x/log.txt": "FACTOXCANARYXanything\n"},
			wantExit:  0,
			wantOut:   "0 canary hits",
		},
		{
			name:     "empty canary file",
			canaries: []string{},
			wantExit: 1,
			wantOut:  "no canaries recorded",
			notOut:   "0 canary hits",
		},
		{
			name:     "missing canary file",
			canaries: nil,
			wantExit: 1,
			wantOut:  "no canaries recorded",
			notOut:   "0 canary hits",
		},
		{
			name:     "missing artifact dir is a real error",
			canaries: []string{leakCanaryA},
			noArtDir: true,
			wantExit: -1,
			notOut:   "0 canary hits",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			canaryFile := filepath.Join(base, "canaries.txt")
			artDir := filepath.Join(base, "art")

			if tt.canaries != nil {
				content := ""
				if len(tt.canaries) > 0 {
					content = strings.Join(tt.canaries, "\n") + "\n"
				}
				writePrivate(t, canaryFile, []byte(content))
			}
			if !tt.noArtDir {
				mkdirPrivate(t, base, "art")
				for rel, content := range tt.artifacts {
					mkdirPrivate(t, artDir, filepath.ToSlash(filepath.Dir(rel)))
					writePrivate(t, filepath.Join(artDir, filepath.FromSlash(rel)), []byte(content))
				}
			}

			cmd := exec.CommandContext(t.Context(), "bash", "../../scripts/leakcheck.sh")
			cmd.Env = []string{
				"PATH=" + os.Getenv("PATH"),
				"LC_ALL=C",
				"CANARY_FILE=" + canaryFile,
				"ART_DIR=" + artDir,
			}
			out, err := cmd.CombinedOutput()

			exit := 0
			var ee *exec.ExitError
			switch {
			case errors.As(err, &ee):
				exit = ee.ExitCode()
			case err != nil:
				t.Fatalf("run leakcheck.sh: %v", err)
			}
			switch {
			case tt.wantExit == -1 && exit == 0:
				t.Errorf("exit = 0, want non-zero\noutput:\n%s", out)
			case tt.wantExit != -1 && exit != tt.wantExit:
				t.Errorf("exit = %d, want %d\noutput:\n%s", exit, tt.wantExit, out)
			}
			if tt.wantOut != "" && !strings.Contains(string(out), tt.wantOut) {
				t.Errorf("output does not contain %q\noutput:\n%s", tt.wantOut, out)
			}
			if tt.notOut != "" && strings.Contains(string(out), tt.notOut) {
				t.Errorf("output contains %q\noutput:\n%s", tt.notOut, out)
			}
		})
	}
}
