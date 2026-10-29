// Architecture guard for CLAUDE.md hard rule 5 (SEC-J0-15): internal/httpx
// is the only production package that may do network I/O. This test parses
// every non-test Go file of the module (cmd/, internal/, connectors/,
// scripts/…) and fails when one outside internal/httpx imports a package
// that opens connections. It backs the depguard "network" rule in
// .golangci.yml, which enforces the same list at lint time.
package httpx_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// networkPkgs are the import paths (or path prefixes, when ending in "/")
// that open connections or build HTTP clients and servers. Parsing-only
// packages (net/url, net/netip, net/mail) are not listed.
var networkPkgs = []string{
	"net",
	"net/http",
	"net/http/",
	"net/rpc",
	"net/rpc/",
	"net/smtp",
	"net/textproto",
	"crypto/tls",
	"golang.org/x/net/",
	"google.golang.org/grpc",
	"google.golang.org/grpc/",
	"C", // cgo: native code can open sockets; not seen by depguard, this test only
}

// networkAllowed lists module-relative slash paths (a directory ending in
// "/", or one file) allowed to import a network package, with the reason.
var networkAllowed = map[string]string{
	"internal/httpx/": "the network boundary itself",
	// walk.go only names net/http and crypto/tls types with reflect so the
	// redacting logger can fail closed on them; it never calls into them.
	"internal/logx/walk.go": "type detection for redaction, no I/O",
}

// isNetworkImport reports whether p is one of networkPkgs.
func isNetworkImport(p string) bool {
	for _, n := range networkPkgs {
		if p == n || (strings.HasSuffix(n, "/") && strings.HasPrefix(p, n)) {
			return true
		}
	}
	return false
}

// networkAllowedFile reports whether the module-relative slash path rel may
// import a network package.
func networkAllowedFile(rel string) bool {
	for k := range networkAllowed {
		if rel == k || (strings.HasSuffix(k, "/") && strings.HasPrefix(rel, k)) {
			return true
		}
	}
	return false
}

// networkViolations returns "rel imports p" for every forbidden network
// import in the Go source src of the module-relative file rel.
func networkViolations(rel string, src []byte) ([]string, error) {
	if strings.HasSuffix(rel, "_test.go") || networkAllowedFile(rel) {
		return nil, nil
	}
	f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, err
		}
		if isNetworkImport(p) {
			out = append(out, rel+" imports "+strconv.Quote(p))
		}
	}
	return out, nil
}

// moduleRoot walks up from the package directory to the go.mod of the
// facto module.
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
			t.Fatal("go.mod not found above the package directory")
		}
		dir = parent
	}
}

func TestNetworkViolations_Detector(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, rel, src string
		want           int
	}{
		{"connector importing net/http", "connectors/edf/edf.go", `package edf; import "net/http"`, 1},
		{"cmd dialing with net", "cmd/facto/x.go", `package main; import "net"`, 1},
		{"httptest in production", "internal/store/x.go", `package store; import "net/http/httptest"`, 1},
		{"cookiejar", "internal/x/x.go", `package x; import "net/http/cookiejar"`, 1},
		{"tls dial", "internal/x/x.go", `package x; import "crypto/tls"`, 1},
		{"rpc and smtp", "internal/x/x.go", `package x; import ("net/rpc/jsonrpc"; "net/smtp")`, 2},
		{"x/net", "internal/x/x.go", `package x; import "golang.org/x/net/http2"`, 1},
		{"cgo", "internal/x/x.go", `package x; import "C"`, 1},
		{"C-prefixed path is not cgo", "internal/x/x.go", `package x; import "Codec/thing"`, 0},
		{"renamed import", "internal/x/x.go", `package x; import h "net/http"`, 1},
		{"net/url is parsing only", "internal/store/x.go", `package store; import "net/url"`, 0},
		{"net/netip is parsing only", "internal/x/x.go", `package x; import "net/netip"`, 0},
		{"netlike prefix is not net", "internal/x/x.go", `package x; import "network/thing"`, 0},
		{"httpx itself", "internal/httpx/httpx.go", `package httpx; import "net/http"`, 0},
		{"logx walk.go", "internal/logx/walk.go", `package logx; import "net/http"`, 0},
		{"other logx file", "internal/logx/logx.go", `package logx; import "net/http"`, 1},
		{"test file", "internal/x/x_test.go", `package x; import "net/http/httptest"`, 0},
		{"httpx lookalike dir", "internal/httpxevil/x.go", `package x; import "net"`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := networkViolations(tc.rel, []byte(tc.src))
			if err != nil {
				t.Fatalf("networkViolations: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("networkViolations(%s) = %q, want %d violation(s)", tc.rel, got, tc.want)
			}
		})
	}
}

// TestModule_NetworkOnlyThroughHTTPX walks the module (nested modules such
// as tools/, testdata and dot directories excluded) and checks every
// production Go file.
func TestModule_NetworkOnlyThroughHTTPX(t *testing.T) {
	t.Parallel()
	fsys := os.DirFS(moduleRoot(t))
	checked := 0
	var violations []string
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
				return filepath.SkipDir
			}
			if _, err := fs.Stat(fsys, path.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir // another module
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
		v, err := networkViolations(p, src)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		checked++
		violations = append(violations, v...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if checked < 20 {
		t.Fatalf("checked %d Go files, want the whole module (walk broken?)", checked)
	}
	for _, v := range violations {
		t.Errorf("%s: network I/O is allowed only in internal/httpx (CLAUDE.md rule 5)", v)
	}
}
