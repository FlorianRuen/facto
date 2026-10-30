package main

import (
	"slices"
	"strings"
	"testing"
)

// TestInspect_E2EOnlySymbols (J1 T22): the -tags e2e binary carries every
// selfTestFuncs entry and the release-flags binary none of e2eOnlySymbols,
// so the symbol check is live for the browser and httpx e2e hooks.
func TestInspect_E2EOnlySymbols(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	root := repoRoot(t)
	b := realRelease(t)
	mod := "github.com/FlorianRuen/facto/"
	e2e, err := inspect(ctx, root, b, []string{"e2e"}, t.TempDir())
	if err != nil {
		t.Fatalf("inspect(e2e): %v", err)
	}
	for _, f := range selfTestFuncs {
		sym := mod + f
		if !slices.ContainsFunc(e2e.Symbols, func(s string) bool { return s == sym || strings.HasPrefix(s, sym+".") }) {
			t.Errorf("-tags e2e symbols lack %s: %q", sym, e2e.Symbols)
		}
	}
	rel, err := inspect(ctx, root, b, nil, t.TempDir())
	if err != nil {
		t.Fatalf("inspect(release): %v", err)
	}
	if len(rel.Symbols) != 0 {
		t.Errorf("release binary has e2e-only symbols: %q", rel.Symbols)
	}
	for _, s := range e2eOnlySymbols {
		if !forbiddenSymbol(strings.TrimSuffix(mod, "/"), mod+s) {
			t.Errorf("forbiddenSymbol does not flag %s", s)
		}
	}
}
