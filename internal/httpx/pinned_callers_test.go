// Caller restriction for NewPinned (J1 task T11, ADR 0008 "Chrome for
// Testing (A10)"): the exact-host, path-prefix client exists for the Chrome
// for Testing download from shared storage, which ParseAllowlist refuses on
// purpose. Only internal/browser/cft (and internal/httpx itself) may call
// it. This backs the forbidigo rule on httpx.NewPinned and catches what
// that text match can miss: renamed and dot imports, build-tagged and
// GOOS-specific files (the parser ignores build constraints). Production
// files only; forbidigo also covers test files.
package httpx_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const httpxImportPath = "github.com/FlorianRuen/facto/internal/httpx"

// pinnedAllowed are the module-relative slash directories whose production
// files may call httpx.NewPinned.
var pinnedAllowed = []string{"internal/browser/cft/", "internal/httpx/"}

// pinnedCallAllowed reports whether the module-relative file rel may call
// NewPinned.
func pinnedCallAllowed(rel string) bool {
	for _, d := range pinnedAllowed {
		if strings.HasPrefix(rel, d) {
			return true
		}
	}
	return false
}

// pinnedViolations returns one line per reference to httpx.NewPinned in the
// Go source src of the module-relative file rel, when rel may not call it.
// A dot import of httpx is a violation by itself (NewPinned would be
// callable unqualified).
func pinnedViolations(rel string, src []byte) ([]string, error) {
	if strings.HasSuffix(rel, "_test.go") || pinnedCallAllowed(rel) {
		return nil, nil
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var names []string
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, err
		}
		if p != httpxImportPath {
			continue
		}
		switch {
		case imp.Name == nil:
			names = append(names, "httpx")
		case imp.Name.Name == ".":
			out = append(out, rel+": dot import of internal/httpx")
		case imp.Name.Name != "_":
			names = append(names, imp.Name.Name)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NewPinned" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && slices.Contains(names, id.Name) {
			out = append(out, rel+":"+strconv.Itoa(fset.Position(sel.Pos()).Line)+": httpx.NewPinned")
		}
		return true
	})
	return out, nil
}

func TestPinnedViolations_Detector(t *testing.T) {
	t.Parallel()
	const imp = `"github.com/FlorianRuen/facto/internal/httpx"`
	tests := []struct {
		name, rel, src string
		want           int
	}{
		{"connector call", "connectors/edf/edf.go", `package edf; import ` + imp + `; var c, _ = httpx.NewPinned("a.example", "/p/", httpx.Options{})`, 1},
		{"function value", "cmd/facto/x.go", `package main; import ` + imp + `; var f = httpx.NewPinned`, 1},
		{"renamed import", "internal/orchestrator/x.go", `package orchestrator; import h ` + imp + `; var f = h.NewPinned`, 1},
		{"dot import", "internal/store/x.go", `package store; import . ` + imp + `; var o Options`, 1},
		{"build-tagged file", "internal/browser/x_windows.go", "//go:build windows\n\npackage browser; import " + imp + "; var f = httpx.NewPinned", 1},
		{"sibling of cft", "internal/browser/cftx/x.go", `package cftx; import ` + imp + `; var f = httpx.NewPinned`, 1},
		{"other selector named NewPinned", "internal/store/x.go", `package store; type t struct{}; func (t) NewPinned() {}; var _ = t{}.NewPinned`, 0},
		{"httpx.New only", "connectors/edf/edf.go", `package edf; import ` + imp + `; var f = httpx.New`, 0},
		{"cft may call it", "internal/browser/cft/install.go", `package cft; import ` + imp + `; var f = httpx.NewPinned`, 0},
		{"httpx itself", "internal/httpx/pinned.go", `package httpx; func NewPinned() {}`, 0},
		{"test file", "connectors/edf/edf_test.go", `package edf; import ` + imp + `; var f = httpx.NewPinned`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := pinnedViolations(tt.rel, []byte(tt.src))
			if err != nil {
				t.Fatalf("pinnedViolations: %v", err)
			}
			if len(got) != tt.want {
				t.Fatalf("pinnedViolations(%s) = %q, want %d", tt.rel, got, tt.want)
			}
		})
	}
}

// TestNewPinned_CalledOnlyFromCft scans every production .go file of the
// module, whatever its build constraints.
func TestNewPinned_CalledOnlyFromCft(t *testing.T) {
	t.Parallel()
	fsys := os.DirFS(moduleRoot(t))
	var offenders []string
	sawCft := false
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == "." {
				return nil
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" {
				return fs.SkipDir
			}
			if _, err := fs.Stat(fsys, path.Join(p, "go.mod")); err == nil {
				return fs.SkipDir // another module
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		if strings.HasPrefix(p, "internal/browser/cft/") && !strings.HasSuffix(p, "_test.go") && strings.Contains(string(src), "httpx.NewPinned(") {
			sawCft = true
		}
		v, err := pinnedViolations(p, src)
		if err != nil {
			return err
		}
		offenders = append(offenders, v...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if !sawCft {
		t.Fatal("internal/browser/cft does not call httpx.NewPinned: the scan is vacuous")
	}
	if len(offenders) != 0 {
		t.Fatalf("httpx.NewPinned referenced outside internal/browser/cft: %q", offenders)
	}
}
