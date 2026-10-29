package browser_test

import (
	"errors"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// e2eOnly reports whether the file's //go:build line makes it compile only
// with the e2e tag (every other tag assumed set).
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

// declaredNames lists the top-level type and function names of f.
func declaredNames(f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				out = append(out, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				if ts, ok := s.(*ast.TypeSpec); ok {
					out = append(out, ts.Name.Name)
				}
			}
		}
	}
	return out
}

// testOnlyNames are the identifiers that carry the loopback host mapping and
// the test CA SPKI. They must be declared only in e2e-tagged files.
var testOnlyNames = []string{"E2EOverrides", "FlagsE2E"}

func TestFlags_TestOnlyFlagsUnreachableFromReleaseOptions(t *testing.T) {
	t.Parallel()

	t.Run("test-only API lives in e2e files only", func(t *testing.T) {
		t.Parallel()
		files, err := filepath.Glob("*.go")
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		declaredInE2E := map[string]bool{}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			if e2eOnly(t, f) {
				for _, n := range declaredNames(f) {
					declaredInE2E[n] = true
				}
				continue
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && slices.Contains(testOnlyNames, id.Name) {
					t.Errorf("%s: %s referenced in a file built without the e2e tag", fset.Position(id.Pos()), id.Name)
				}
				return true
			})
		}
		for _, n := range testOnlyNames {
			if !declaredInE2E[n] {
				t.Errorf("%s is not declared in an e2e-only (//go:build e2e) file of internal/browser", n)
			}
		}
	})

	t.Run("release Options has no extra knob", func(t *testing.T) {
		t.Parallel()
		want := []string{"AllowProxy", "AllowedDomains", "GOOS", "ProfileDir", "Visible"}
		var got []string
		rt := reflect.TypeFor[browser.Options]()
		for i := range rt.NumField() {
			if f := rt.Field(i); f.IsExported() {
				got = append(got, f.Name)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("exported Options fields = %q, want exactly %q (no extra args, no test-only field)", got, want)
		}
	})

	t.Run("release check refuses loopback mapping and test CA", func(t *testing.T) {
		t.Parallel()
		for _, goos := range []string{"linux", "darwin", "windows"} {
			release := mustFlags(t, opts(goos))
			for _, f := range []string{
				"--host-resolver-rules=MAP * 127.0.0.1",
				"--host-resolver-rules=MAP login.supplier.example 127.0.0.1",
				"--host-resolver-rules=MAP login.supplier.example 127.0.0.1:8443",
				"--host-resolver-rules=MAP *.supplier.example 127.1.2.3",
				"--host-resolver-rules=MAP login.supplier.example localhost",
				"--host-resolver-rules=MAP login.supplier.example [::1]",
				"--host-resolver-rules=MAP login.supplier.example 192.0.2.10",
				"--ignore-certificate-errors-spki-list=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			} {
				// Replace the release resolver rules (so the duplicate rule
				// is not what fails), or append the CA flag.
				args := slices.DeleteFunc(slices.Clone(release), func(a string) bool {
					return strings.HasPrefix(a, "--host-resolver-rules=") && strings.HasPrefix(f, "--host-resolver-rules=")
				})
				args = append(args, f)
				if err := browser.CheckFlags(goos, args); !errors.Is(err, browser.ErrForbiddenFlag) {
					t.Errorf("CheckFlags(%s, %q) = %v, want ErrForbiddenFlag", goos, f, err)
				}
			}
			// The flag name itself stays allowed: Flags' own rules pass.
			if err := browser.CheckFlags(goos, release); err != nil {
				t.Errorf("CheckFlags(%s, release) = %v, want nil", goos, err)
			}
		}
	})

	t.Run("release Flags refuse loopback allowlist entries", func(t *testing.T) {
		t.Parallel()
		for _, d := range []string{"127.0.0.1", "localhost", "fake.localhost", "127.0.0.2", "0.0.0.0"} {
			o := opts("linux")
			o.AllowedDomains = []string{"login.supplier.example", d}
			if got, err := browser.Flags(o); !errors.Is(err, browser.ErrInvalidDomain) {
				t.Errorf("Flags(AllowedDomains+%q) = %q, %v; want ErrInvalidDomain", d, got, err)
			}
		}
	})
}
