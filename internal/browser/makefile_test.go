package browser_test

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// windowsCICommand is the command of the T32 browser-windows CI job
// (docs/agentic/plans/J1.md T32); make e2e-browser-windows runs exactly it.
const windowsCICommand = "go test -tags e2e,chrome -count=1 -v -run '^TestChromeWindows_' ./internal/browser/..."

// mkTargets reads the targets of the module Makefile: recipe lines (tabs
// stripped, one per line) per target, and the .PHONY list.
func mkTargets(t *testing.T) (recipes map[string][]string, prereqs map[string][]string, phony []string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	recipes, prereqs = map[string][]string{}, map[string][]string{}
	var current, cont string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if cont != "" || strings.HasPrefix(line, "\t") {
			// A recipe line, joined with its backslash continuations.
			joined := cont + strings.TrimSpace(line)
			if strings.HasSuffix(joined, "\\") {
				cont = strings.TrimSuffix(joined, "\\") + " "
				continue
			}
			cont = ""
			if current != "" {
				recipes[current] = append(recipes[current], joined)
			}
			continue
		}
		current = ""
		if strings.HasPrefix(line, "#") || strings.Contains(line, ":=") || strings.Contains(line, "?=") {
			continue
		}
		target, rest, ok := strings.Cut(line, ":")
		if !ok || target == "" || strings.ContainsAny(target, " \t$") {
			continue
		}
		rest, _, _ = strings.Cut(rest, "#")
		if target == ".PHONY" {
			phony = append(phony, strings.Fields(rest)...)
			continue
		}
		prereqs[target] = strings.Fields(rest)
		current = target
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan Makefile: %v", err)
	}
	return recipes, prereqs, phony
}

// TestMakefile_E2ERunsRealChromeBrowserTests (J1 T13): make e2e installs
// the pinned Chrome (prerequisite chrome) and runs the internal/browser
// tests with -tags e2e,chrome and FACTO_E2E_CHROME pointing into
// .cache/chrome.
func TestMakefile_E2ERunsRealChromeBrowserTests(t *testing.T) {
	t.Parallel()
	recipes, prereqs, _ := mkTargets(t)
	if !slices.Contains(prereqs["e2e"], "chrome") {
		t.Errorf("e2e prerequisites = %q, want chrome (make chrome installs the pinned build)", prereqs["e2e"])
	}
	var found bool
	for _, l := range recipes["e2e"] {
		cmd := strings.ReplaceAll(l, "$(GO)", "go")
		if !strings.Contains(cmd, "go test") || !strings.Contains(cmd, "-tags e2e") || !strings.Contains(cmd, "./internal/browser/...") {
			continue
		}
		found = true
		if !strings.Contains(cmd, "-tags e2e,chrome ") {
			t.Errorf("e2e browser line %q: want -tags e2e,chrome (the real-Chrome files need both tags)", l)
		}
		if !strings.Contains(cmd, "FACTO_E2E_CHROME=") {
			t.Errorf("e2e browser line %q does not set FACTO_E2E_CHROME", l)
		}
		if !strings.Contains(cmd, "$(CHROME_DIR)") && !strings.Contains(cmd, ".cache/chrome") {
			t.Errorf("e2e browser line %q: FACTO_E2E_CHROME must point at the make chrome install (.cache/chrome)", l)
		}
	}
	if !found {
		t.Errorf("e2e recipe %q has no `go test -tags e2e ./internal/browser/...` line", recipes["e2e"])
	}
}

// TestMakefile_E2EBrowserWindowsMatchesCI (J1 T13/T32): the target exists,
// is phony and runs exactly the command of the browser-windows CI job.
func TestMakefile_E2EBrowserWindowsMatchesCI(t *testing.T) {
	t.Parallel()
	recipes, _, phony := mkTargets(t)
	if !slices.Contains(phony, "e2e-browser-windows") {
		t.Errorf(".PHONY = %q, want e2e-browser-windows", phony)
	}
	lines, ok := recipes["e2e-browser-windows"]
	if !ok {
		t.Fatal("no e2e-browser-windows target in the Makefile")
	}
	var cmds []string
	for _, l := range lines {
		cmds = append(cmds, strings.TrimPrefix(strings.ReplaceAll(l, "$(GO)", "go"), "@"))
	}
	if !slices.Equal(cmds, []string{windowsCICommand}) {
		t.Errorf("e2e-browser-windows recipe = %q, want exactly %q", cmds, windowsCICommand)
	}
}
