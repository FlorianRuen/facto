//go:build !e2e

package fakeprovider_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Plan J1 T17: the release build must not contain fakeprovider. The package
// itself compiles in every build (its unit tests run under make test), so
// the guard is twofold: its registration entry point exists only behind
// //go:build e2e, and the release dependency graph of cmd/facto never
// reaches the package.

const (
	modulePath = "github.com/FlorianRuen/facto"
	fakePkg    = modulePath + "/connectors/fakeprovider"
)

// e2eOnly reports whether f's //go:build line makes it compile only with
// the e2e tag (every other tag assumed set).
func e2eOnly(t *testing.T, f *ast.File) bool {
	t.Helper()
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if !constraint.IsGoBuild(c.Text) {
				continue
			}
			expr, err := constraint.Parse(c.Text)
			if err != nil {
				t.Fatalf("parse build line %q: %v", c.Text, err)
			}
			return !expr.Eval(func(tag string) bool { return tag != "e2e" })
		}
	}
	return false
}

func TestRegistry_FakeproviderOnlyInE2EBuild(t *testing.T) {
	t.Parallel()

	t.Run("Register declared only in e2e files", func(t *testing.T) {
		t.Parallel()
		files, err := filepath.Glob("*.go")
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		var e2eDecl, sources int
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			sources++
			f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			tagged := e2eOnly(t, f)
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Recv != nil {
					continue
				}
				switch fd.Name.Name {
				case "Register":
					if !tagged {
						t.Errorf("%s declares Register without //go:build e2e: the release build would carry it", name)
					} else {
						e2eDecl++
					}
				case "init":
					if !tagged {
						t.Errorf("%s declares init() without //go:build e2e: no side effect may reach the release build", name)
					}
				}
			}
		}
		if sources == 0 {
			t.Fatal("no non-test source file in connectors/fakeprovider")
		}
		if e2eDecl != 1 {
			t.Fatalf("found %d e2e-only Register declarations, want exactly 1", e2eDecl)
		}
	})

	t.Run("release cmd/facto never depends on fakeprovider", func(t *testing.T) {
		t.Parallel()
		root := moduleRoot(t)
		for _, goos := range []string{"linux", "darwin", "windows"} {
			t.Run(goos, func(t *testing.T) {
				t.Parallel()
				cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "-json=ImportPath", "./cmd/facto")
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=")
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("go list (GOOS=%s): %v\n%s", goos, err, stderr.String())
				}
				dec := json.NewDecoder(bytes.NewReader(out))
				sawConnector := false
				for {
					var p struct{ ImportPath string }
					if err := dec.Decode(&p); errors.Is(err, io.EOF) {
						break
					} else if err != nil {
						t.Fatalf("decode go list: %v", err)
					}
					if p.ImportPath == modulePath+"/internal/connector" {
						sawConnector = true
					}
					if p.ImportPath == fakePkg || strings.HasPrefix(p.ImportPath, fakePkg+"/") {
						t.Fatalf("release cmd/facto depends on %s", p.ImportPath)
					}
				}
				if !sawConnector {
					t.Fatal("internal/connector not in the release dependency list: the scan is vacuous")
				}
			})
		}
	})
}

// moduleRoot walks up from the test's working directory to go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}
