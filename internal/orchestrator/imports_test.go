// Architecture guard (CLAUDE.md "Architecture in one screen" and hard rule
// 5): the orchestrator never imports a concrete connector or destination, and
// does no network I/O of its own.
package orchestrator_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestPackage_NoConcreteConnectorOrDestinationImport(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	forbidden := []struct {
		match func(string) bool
		why   string
	}{
		{func(p string) bool { return strings.Contains(p, "/connectors/") || strings.HasSuffix(p, "/connectors") }, "concrete connector"},
		{func(p string) bool { return strings.HasPrefix(p, "github.com/FlorianRuen/facto/internal/dest/") }, "concrete destination (wired by cmd/)"},
		{func(p string) bool { return p == "net/http" || p == "net" || strings.HasPrefix(p, "net/http/") }, "network I/O (internal/httpx only)"},
		{func(p string) bool { return p == "log" }, "unredacted logging"},
		// J1 T18: the browser and the session store are consumer-side
		// interfaces (connector.BrowserPool, SessionStore) wired by cmd/.
		{func(p string) bool {
			return p == "github.com/FlorianRuen/facto/internal/browser" || strings.HasPrefix(p, "github.com/FlorianRuen/facto/internal/browser/")
		}, "concrete browser (connector.BrowserPool only)"},
		{func(p string) bool { return strings.HasPrefix(p, "github.com/FlorianRuen/facto/internal/vault/") }, "vault key sources (SessionStore only)"},
		{func(p string) bool { return strings.HasPrefix(p, "github.com/FlorianRuen/facto/internal/secret/") }, "concrete secret provider (connector.SecretResolver only)"},
		{func(p string) bool {
			return strings.HasPrefix(p, "github.com/go-rod/") || strings.HasPrefix(p, "github.com/chromedp/")
		}, "browser library"},
	}
	parsed := 0
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: bad import %s", name, imp.Path.Value)
			}
			for _, fb := range forbidden {
				if fb.match(p) {
					t.Errorf("%s imports %q: %s is forbidden in the orchestrator", name, p, fb.why)
				}
			}
		}
	}
	if parsed == 0 {
		t.Fatal("no production file in internal/orchestrator")
	}
}

// vaultPath is the only vault import allowed, for its sentinels.
const vaultPath = "github.com/FlorianRuen/facto/internal/vault"

// TestPackage_VaultOnlyForSentinels: the orchestrator reaches the session
// store through SessionStore; from internal/vault it may only name the
// sentinels it branches on, never *vault.Store, NewStore or a key.
func TestPackage_VaultOnlyForSentinels(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{"ErrNoSession": true, "ErrKeyring": true}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		local := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == vaultPath {
				local = "vault"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		if local == "" {
			continue
		}
		if local == "." || local == "_" {
			t.Errorf("%s imports vault as %q: name its sentinels explicitly", name, local)
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && !allowed[sel.Sel.Name] {
				t.Errorf("%s: uses %s.%s; only vault.ErrNoSession and vault.ErrKeyring are allowed (SessionStore for the rest)", fset.Position(sel.Pos()), local, sel.Sel.Name)
			}
			return true
		})
	}
}
