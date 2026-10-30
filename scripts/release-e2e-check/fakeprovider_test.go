package main

import (
	"slices"
	"testing"
)

// TestForbiddenPkg_FakeproviderDetected: the real connectors/fakeprovider
// package (and only e2e-only packages) is classified forbidden when go list
// reports it with the release flags, and its e2e registration file is seen
// in a -tags e2e build. Proves the fakeprovider rule is not vacuous.
func TestForbiddenPkg_FakeproviderDetected(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	root := repoRoot(t)
	b := realRelease(t)
	pkgs, err := goList(ctx, root, b, b.listPkgsArgs(nil, "./connectors/fakeprovider"))
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var forbidden []string
	for _, p := range pkgs {
		if forbiddenPkg(modPath, p.importPath) {
			forbidden = append(forbidden, p.importPath)
		}
	}
	if want := []string{modPath + "/connectors/fakeprovider"}; !slices.Equal(forbidden, want) {
		t.Fatalf("forbidden packages = %q, want %q", forbidden, want)
	}
	if !forbiddenSymbol(modPath, modPath+"/connectors/fakeprovider.(*Connector).Info") {
		t.Error("a fakeprovider symbol is not classified forbidden")
	}
	if forbiddenSymbol(modPath, modPath+"/internal/connector.(*Registry).Register") {
		t.Error("an internal/connector symbol is classified forbidden")
	}
	got, err := e2eFiles(ctx, root, b, []string{"e2e"}, "./connectors/fakeprovider")
	if err != nil {
		t.Fatalf("e2eFiles: %v", err)
	}
	if !slices.Contains(got, "connectors/fakeprovider/register_e2e.go") {
		t.Errorf("e2eFiles(-tags e2e, fakeprovider) = %q, want connectors/fakeprovider/register_e2e.go", got)
	}
}
