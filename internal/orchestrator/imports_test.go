// Architecture guard (CLAUDE.md "Architecture in one screen" and hard rule
// 5): the orchestrator never imports a concrete connector or destination, and
// does no network I/O of its own.
package orchestrator_test

import (
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
