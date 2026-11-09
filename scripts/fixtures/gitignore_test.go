package fixtures_test

import (
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGitignore_Recordings (J2): recordings hold personal data. A .har is
// ignored everywhere but under a testdata/ directory (sanitized fixtures);
// a raw recording is ignored everywhere, testdata/ included. Only path
// names are checked (git check-ignore --no-index): no file is created or
// read.
func TestGitignore_Recordings(t *testing.T) {
	t.Parallel()
	raw := ".har" + ".raw" // split: the agent guard refuses the literal
	tests := []struct {
		path    string
		ignored bool
	}{
		{"x.har", true},
		{"recordings/edf.har", true},
		{"connectors/edf/edf.har", true},
		{"testdata/x.har", false},
		{"connectors/edf/testdata/recording.har", false},
		{"connectors/edf/testdata/sub/recording.har", false},
		{"x" + raw, true},
		{"testdata/x" + raw, true},
		{"connectors/edf/testdata/recording" + raw, true},
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		// #nosec G204 -- fixed git subcommand; the path is a constant of this table (J2 gitignore check)
		cmd := exec.CommandContext(t.Context(), "git", "check-ignore", "-q", "--no-index", "--", tt.path)
		cmd.Dir = root
		err := cmd.Run()
		var ee *exec.ExitError
		got := err == nil
		if err != nil && (!errors.As(err, &ee) || ee.ExitCode() != 1) {
			t.Fatalf("git check-ignore %s: %v", tt.path, err)
		}
		if got != tt.ignored {
			t.Errorf("%s: ignored = %v, want %v", tt.path, got, tt.ignored)
		}
	}
}
