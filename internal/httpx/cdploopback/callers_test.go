package cdploopback_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Caller restriction (plan J1 T7.1, ADR 0008 A4): only internal/browser may
// import cdploopback. This backs the depguard rule "cdploopback" and catches
// what it can miss: renamed imports, build-tagged or GOOS-specific files.
// It checks non-test imports only (go list reports Imports without test
// files); the depguard rule covers test files.

const (
	modulePath    = "github.com/FlorianRuen/facto"
	cdpPkg        = modulePath + "/internal/httpx/cdploopback"
	browserPrefix = modulePath + "/internal/browser"
)

// listedPkg is the subset of `go list -json` output the guard needs.
type listedPkg struct {
	ImportPath string
	Imports    []string
}

// cdpImporters decodes a `go list -deps -json` stream and returns every
// package importing cdploopback from outside internal/browser, and whether
// cdploopback itself appeared (proving the scan is not vacuous).
func cdpImporters(r io.Reader) (offenders []string, sawPkg bool, err error) {
	dec := json.NewDecoder(r)
	for {
		var p listedPkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, false, fmt.Errorf("decode go list: %w", err)
		}
		if p.ImportPath == cdpPkg {
			sawPkg = true
		}
		if !slices.Contains(p.Imports, cdpPkg) {
			continue
		}
		if p.ImportPath == browserPrefix || strings.HasPrefix(p.ImportPath, browserPrefix+"/") {
			continue
		}
		offenders = append(offenders, p.ImportPath)
	}
	return offenders, sawPkg, nil
}

func TestCdpImporters_FlagsOutsiders(t *testing.T) {
	t.Parallel()
	stream := strings.Join([]string{
		`{"ImportPath":"` + cdpPkg + `","Imports":["net"]}`,
		`{"ImportPath":"` + browserPrefix + `","Imports":["` + cdpPkg + `"]}`,
		`{"ImportPath":"` + browserPrefix + `/winport","Imports":["` + cdpPkg + `"]}`,
		`{"ImportPath":"` + browserPrefix + `x","Imports":["` + cdpPkg + `"]}`,
		`{"ImportPath":"` + modulePath + `/connectors/edf","Imports":["` + cdpPkg + `"]}`,
		`{"ImportPath":"` + modulePath + `/cmd/facto","Imports":["fmt"]}`,
	}, "\n")
	got, saw, err := cdpImporters(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("cdpImporters: %v", err)
	}
	want := []string{browserPrefix + "x", modulePath + "/connectors/edf"}
	if !slices.Equal(got, want) || !saw {
		t.Fatalf("cdpImporters = %q, saw %v; want %q, true", got, saw, want)
	}
}

// moduleRootDir walks up from the test's working directory to go.mod.
func moduleRootDir(t *testing.T) string {
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

func TestCallers_OnlyInternalBrowser(t *testing.T) {
	t.Parallel()
	root := moduleRootDir(t)
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, tags := range []string{"", "e2e"} {
			t.Run(goos+"/"+tags, func(t *testing.T) {
				t.Parallel()
				args := []string{"list", "-deps", "-json=ImportPath,Imports"}
				if tags != "" {
					args = append(args, "-tags", tags)
				}
				args = append(args, "./...")
				cmd := exec.CommandContext(t.Context(), "go", args...)
				cmd.Dir = root
				cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0")
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("go %s (GOOS=%s): %v\n%s", strings.Join(args, " "), goos, err, stderr.String())
				}
				offenders, saw, err := cdpImporters(bytes.NewReader(out))
				if err != nil {
					t.Fatal(err)
				}
				if !saw {
					t.Fatalf("%s not in go list output: the scan is vacuous", cdpPkg)
				}
				if len(offenders) != 0 {
					t.Fatalf("cdploopback imported outside internal/browser: %q", offenders)
				}
			})
		}
	}
}
