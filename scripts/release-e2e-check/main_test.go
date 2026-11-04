// Tests for scripts/release-e2e-check (J1 task T17; ADR 0009 "Key source",
// decision A3). `make release-e2e-check`, run by `make verify`, proves the
// release build of facto contains no e2e-only code, and proves the check
// itself is not vacuous by running it on a -tags e2e build, which must hit.
// The J0 `release-check` target (docker goreleaser snapshot) stays separate.
//
// What "e2e-only code" means (the forbidden set):
//   - packages: any package of this module with an import path element
//     starting with "e2e" (internal/vault/e2ekey, internal/secret/e2efile)
//     or equal to "fakeprovider" (connectors/fakeprovider);
//   - files: any Go file compiled into a dependency of the main package
//     whose //go:build constraint mentions the "e2e" tag
//     (internal/browser/flags_e2e.go: FlagsE2E, E2EOverrides);
//   - symbols: any `go tool nm` symbol containing one of the forbidden
//     package paths followed by ".", or "internal/browser.FlagsE2E", or
//     "internal/browser.E2EOverrides".
//
// The release build flags are read from .goreleaser.yaml (builds[id=facto]),
// never hard-coded: main, env (CGO_ENABLED=0), flags (-trimpath), ldflags
// (the "{{ .Version }}" template replaced by checkVersion) and tags (none
// today). `go list -deps` runs with exactly those flags. A release binary is
// linked with -s, which drops the symbol table, so `go tool nm` on it lists
// nothing (vacuous): the nm binary is built with the same flags except that
// the single "-s" field is removed from ldflags (-s does not change what is
// linked, only whether the symbol table is kept). A run whose nm lists no
// symbol at all is an error, never a pass.
//
// Expected API (implementer: follow exactly; package main):
//
//	// okLine is printed on success, alone, followed by "\n".
//	const okLine = "release-check: release build has no e2e-only code"
//
//	// checkVersion replaces "{{ .Version }}" in the goreleaser ldflags.
//	const checkVersion = "0.0.0-release-e2e-check"
//
//	// releaseBuild is builds[id=facto] of .goreleaser.yaml.
//	type releaseBuild struct {
//		Main    string   // "./cmd/facto"
//		Env     []string // ["CGO_ENABLED=0"]
//		Flags   []string // ["-trimpath"]
//		Ldflags []string // templates expanded with checkVersion
//		Tags    []string // goreleaser "tags"; empty today
//	}
//
//	// errNoBuild: the file has no build with id "facto" (or no builds).
//	var errNoBuild = errors.New("release-e2e-check: no facto build in goreleaser config")
//
//	// loadRelease reads path (YAML, go.yaml.in/yaml/v3, unknown keys
//	// ignored). Missing file wraps fs.ErrNotExist; no facto build is
//	// errNoBuild; a build without main or with an e2e tag is an error.
//	func loadRelease(path string) (releaseBuild, error)
//
//	// listArgs returns the arguments after "go" for
//	// `go list -deps -f … <flags> <-ldflags=…> [-tags=…] <main>`: every
//	// entry of b.Flags, one "-ldflags=" + strings.Join(b.Ldflags, " "),
//	// and "-tags=" + strings.Join(b.Tags+extra, ",") only when non-empty.
//	func (b releaseBuild) listArgs(extraTags []string) []string
//
//	// nmBuildArgs returns the arguments after "go" for the `go build` of
//	// the nm binary written to out: as listArgs but "build -o out", and the
//	// ldflags with the single "-s" field removed (nothing else changes).
//	func (b releaseBuild) nmBuildArgs(extraTags []string, out string) []string
//
//	// report is what one inspection found. Each list is sorted, no dups.
//	type report struct {
//		Deps    []string // forbidden import paths among the deps of main
//		Files   []string // e2e-tagged Go files compiled in, module-relative slash paths
//		Symbols []string // forbidden nm symbols
//		NM      int      // number of symbols nm listed (0 = vacuous, an error)
//	}
//
//	// inspect runs go list and go build + go tool nm for b plus extraTags,
//	// from module root, with b.Env appended to the environment, binaries
//	// under tmp. It never modifies the tree.
//	func inspect(ctx context.Context, root string, b releaseBuild, extraTags []string, tmp string) (report, error)
//
//	// e2eFiles returns the e2e-tagged Go files compiled into pkgs (and their
//	// deps) with b's flags plus extraTags.
//	func e2eFiles(ctx context.Context, root string, b releaseBuild, extraTags []string, pkgs ...string) ([]string, error)
//
//	// run is main without os.Exit. Flags:
//	//   -root dir          module root (default ".")
//	//   -goreleaser file   default "<root>/.goreleaser.yaml"
//	//   -release-tags a,b  extra tags for the release side (test hook that
//	//                      must make the check fail; default none)
//	// It inspects the release build (must find nothing, NM > 0) and the
//	// -tags e2e build (self-test: must find internal/vault/e2ekey and
//	// internal/secret/e2efile in Deps and their ".Sentinel" symbols in
//	// Symbols). Exit 0: prints okLine + "\n" on stdout and nothing else.
//	// Exit 1: a check failed; one stderr line per finding, okLine never
//	// printed. Exit 2: usage or I/O error (bad flag, unreadable goreleaser
//	// file, go command failure).
//	func run(ctx context.Context, args []string, stdout, stderr io.Writer) int
//
//	func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }
//
// Makefile: target `release-e2e-check` runs `@$(GO) run ./scripts/release-e2e-check`,
// is listed in .PHONY and is a prerequisite of `verify`.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

const (
	modPath     = "github.com/FlorianRuen/facto"
	e2ekeyPkg   = modPath + "/internal/vault/e2ekey"
	e2efilePkg  = modPath + "/internal/secret/e2efile"
	wantOKLine  = "release-check: release build has no e2e-only code"
	releaseLdfl = "-s -w -buildid= -X main.version=0.0.0-release-e2e-check"
)

// repoRoot is the module root, two levels up from this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s: %v", root, err)
	}
	return root
}

func realRelease(t *testing.T) releaseBuild {
	t.Helper()
	b, err := loadRelease(filepath.Join(repoRoot(t), ".goreleaser.yaml"))
	if err != nil {
		t.Fatalf("loadRelease(.goreleaser.yaml): %v", err)
	}
	return b
}

// writeTemp writes a synthetic goreleaser file through fsx and returns its path.
func writeTemp(t *testing.T, name, data string) string {
	t.Helper()
	dir := t.TempDir()
	root, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("setup fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(t.Context(), name, []byte(data)); err != nil {
		t.Fatalf("setup write: %v", err)
	}
	return filepath.Join(dir, name)
}

func TestLoadRelease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    string // "" = use the real .goreleaser.yaml
		want    releaseBuild
		wantErr error // nil with wantAnyErr false = success
		anyErr  bool
	}{
		{
			name: "real goreleaser config",
			want: releaseBuild{
				Main:    "./cmd/facto",
				Env:     []string{"CGO_ENABLED=0"},
				Flags:   []string{"-trimpath"},
				Ldflags: []string{releaseLdfl},
			},
		},
		{
			name: "picks the facto build among several, reads tags",
			data: "version: 2\nbuilds:\n" +
				"  - id: other\n    main: ./cmd/other\n" +
				"  - id: facto\n    main: ./cmd/facto\n    env: [CGO_ENABLED=0]\n    flags: [-trimpath]\n" +
				"    tags: [netgo]\n    ldflags:\n      - -s -w -X main.version={{ .Version }}\n",
			want: releaseBuild{
				Main:    "./cmd/facto",
				Env:     []string{"CGO_ENABLED=0"},
				Flags:   []string{"-trimpath"},
				Ldflags: []string{"-s -w -X main.version=0.0.0-release-e2e-check"},
				Tags:    []string{"netgo"},
			},
		},
		{name: "no builds", data: "version: 2\nproject_name: facto\n", wantErr: errNoBuild},
		{name: "no facto build", data: "version: 2\nbuilds:\n  - id: other\n    main: ./cmd/other\n", wantErr: errNoBuild},
		{name: "facto build without main", data: "version: 2\nbuilds:\n  - id: facto\n    binary: facto\n", anyErr: true},
		{name: "release built with the e2e tag", data: "version: 2\nbuilds:\n  - id: facto\n    main: ./cmd/facto\n    tags: [e2e]\n", anyErr: true},
		{name: "not yaml", data: "builds: [\n", anyErr: true},
		// ADR 0008 release gate (issue #3, SEC-J1-11): no Windows release
		// until the browser runs in a Job object.
		{
			name:    "windows release before the Job object gate",
			data:    "version: 2\nbuilds:\n  - id: facto\n    main: ./cmd/facto\n    goos: [linux, windows]\n    goarch: [amd64]\n",
			wantErr: errWindowsGated,
		},
		{
			name:    "windows release, scalar goos",
			data:    "version: 2\nbuilds:\n  - id: facto\n    main: ./cmd/facto\n    goos: windows\n    goarch: [arm64]\n",
			wantErr: errWindowsGated,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(repoRoot(t), ".goreleaser.yaml")
			if tc.data != "" {
				path = writeTemp(t, "goreleaser.yaml", tc.data)
			}
			got, err := loadRelease(path)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("loadRelease = %+v, %v; want error %v", got, err, tc.wantErr)
				}
				return
			case tc.anyErr:
				if err == nil {
					t.Fatalf("loadRelease = %+v, nil; want an error", got)
				}
				return
			case err != nil:
				t.Fatalf("loadRelease: %v", err)
			}
			if got.Main != tc.want.Main || !slices.Equal(got.Env, tc.want.Env) || !slices.Equal(got.Flags, tc.want.Flags) ||
				!slices.Equal(got.Ldflags, tc.want.Ldflags) || !slices.Equal(got.Tags, tc.want.Tags) {
				t.Fatalf("loadRelease = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLoadRelease_MissingFile(t *testing.T) {
	t.Parallel()
	if _, err := loadRelease(filepath.Join(t.TempDir(), "absent.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("loadRelease(missing) = %v, want fs.ErrNotExist", err)
	}
}

// TestReleaseBuild_ExactFlags: go list runs with the exact goreleaser flags;
// the nm build differs only by the "-s" ldflag.
func TestReleaseBuild_ExactFlags(t *testing.T) {
	t.Parallel()
	b := realRelease(t)

	list := b.listArgs(nil)
	if len(list) == 0 || list[0] != "list" || !slices.Contains(list, "-deps") {
		t.Fatalf("listArgs = %q, want a go list -deps command", list)
	}
	for _, want := range []string{"-trimpath", "-ldflags=" + releaseLdfl, "./cmd/facto"} {
		if !slices.Contains(list, want) {
			t.Errorf("listArgs = %q, missing %q", list, want)
		}
	}
	for _, a := range list {
		if strings.HasPrefix(a, "-tags") {
			t.Errorf("listArgs(nil) = %q, want no -tags for the release build", list)
		}
	}
	if e2e := b.listArgs([]string{"e2e"}); !slices.Contains(e2e, "-tags=e2e") {
		t.Errorf("listArgs(e2e) = %q, want -tags=e2e", e2e)
	}

	out := filepath.Join(t.TempDir(), "facto-nm")
	nm := b.nmBuildArgs(nil, out)
	if len(nm) == 0 || nm[0] != "build" {
		t.Fatalf("nmBuildArgs = %q, want a go build command", nm)
	}
	for _, want := range []string{"-trimpath", "-ldflags=-w -buildid= -X main.version=0.0.0-release-e2e-check", "-o", out, "./cmd/facto"} {
		if !slices.Contains(nm, want) {
			t.Errorf("nmBuildArgs = %q, missing %q (only -s may differ from the release ldflags)", nm, want)
		}
	}
	if !slices.Contains(b.Env, "CGO_ENABLED=0") {
		t.Errorf("Env = %q, want CGO_ENABLED=0", b.Env)
	}
}

// TestReleaseBuild_HasNoE2EOnlyCode: the release build has no e2e-only
// package, file or symbol; the same inspection of a -tags e2e build finds
// them (non-vacuous).
func TestReleaseBuild_HasNoE2EOnlyCode(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	root := repoRoot(t)
	b := realRelease(t)

	rel, err := inspect(ctx, root, b, nil, t.TempDir())
	if err != nil {
		t.Fatalf("inspect(release): %v", err)
	}
	if len(rel.Deps) != 0 {
		t.Errorf("release deps include e2e-only packages: %q", rel.Deps)
	}
	if len(rel.Files) != 0 {
		t.Errorf("release build compiles e2e-tagged files: %q", rel.Files)
	}
	if len(rel.Symbols) != 0 {
		t.Errorf("release binary has e2e-only symbols: %q", rel.Symbols)
	}
	if rel.NM == 0 {
		t.Error("go tool nm listed no symbol on the release-flags binary: the symbol check is vacuous")
	}

	// Self-test: the same inspection with -tags e2e must hit.
	e2e, err := inspect(ctx, root, b, []string{"e2e"}, t.TempDir())
	if err != nil {
		t.Fatalf("inspect(e2e): %v", err)
	}
	for _, pkg := range []string{e2ekeyPkg, e2efilePkg} {
		if !slices.Contains(e2e.Deps, pkg) {
			t.Errorf("self-test: -tags e2e deps = %q, want %s (go list check is vacuous)", e2e.Deps, pkg)
		}
		if !slices.ContainsFunc(e2e.Symbols, func(s string) bool { return strings.HasSuffix(s, pkg+".Sentinel") }) {
			t.Errorf("self-test: -tags e2e symbols = %q, want %s.Sentinel (nm check is vacuous)", e2e.Symbols, pkg)
		}
	}
}

// TestReleaseBuild_E2EFilesDetected: the file-level check finds the browser's
// e2e-only flags file in a -tags e2e build and nothing in a release build.
// Proves the FlagsE2E/E2EOverrides guard is not vacuous even before
// cmd/facto imports internal/browser.
func TestReleaseBuild_E2EFilesDetected(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	root := repoRoot(t)
	b := realRelease(t)
	rel, err := e2eFiles(ctx, root, b, nil, "./internal/browser")
	if err != nil {
		t.Fatalf("e2eFiles(release): %v", err)
	}
	if len(rel) != 0 {
		t.Errorf("release browser build compiles e2e-tagged files: %q", rel)
	}
	got, err := e2eFiles(ctx, root, b, []string{"e2e"}, "./internal/browser")
	if err != nil {
		t.Fatalf("e2eFiles(e2e): %v", err)
	}
	if !slices.Contains(got, "internal/browser/flags_e2e.go") {
		t.Errorf("e2eFiles(-tags e2e, ./internal/browser) = %q, want internal/browser/flags_e2e.go", got)
	}
}

// TestRun_PrintsReleaseCheckLine: the gate passes on the tree and prints
// exactly the line the goal evaluator reads.
func TestRun_PrintsReleaseCheckLine(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"-root", repoRoot(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run = %d, want 0\nstderr:\n%s", code, stderr.String())
	}
	if got := stdout.String(); got != wantOKLine+"\n" {
		t.Fatalf("stdout = %q, want exactly %q", got, wantOKLine+"\n")
	}
}

// TestRun_FailsWhenReleaseHasE2ECode: a release build that would carry the
// e2e tag fails the gate, names what it found, and never prints the line.
func TestRun_FailsWhenReleaseHasE2ECode(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), []string{"-root", repoRoot(t), "-release-tags", "e2e"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run(-release-tags e2e) = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), wantOKLine) {
		t.Fatalf("the success line was printed for a failing build:\n%s", stdout.String())
	}
	for _, want := range []string{"internal/vault/e2ekey", "internal/secret/e2efile"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, want it to name %s", stderr.String(), want)
		}
	}
}

func TestRun_UsageAndIOErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args func(t *testing.T) []string
	}{
		{name: "unknown flag", args: func(*testing.T) []string { return []string{"-bogus"} }},
		{name: "missing goreleaser file", args: func(t *testing.T) []string {
			return []string{"-root", repoRoot(t), "-goreleaser", filepath.Join(t.TempDir(), "absent.yaml")}
		}},
		{name: "goreleaser without facto build", args: func(t *testing.T) []string {
			return []string{"-root", repoRoot(t), "-goreleaser", writeTemp(t, "g.yaml", "version: 2\n")}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), tc.args(t), &stdout, &stderr); code != 2 {
				t.Fatalf("run = %d, want 2\nstderr:\n%s", code, stderr.String())
			}
			if strings.Contains(stdout.String(), wantOKLine) {
				t.Fatal("the success line was printed on a usage/I-O error")
			}
		})
	}
}

// TestMakefile_ReleaseE2ECheck: the target exists, is phony, is part of
// verify, stays separate from the goreleaser release-check, and prints
// exactly the success line.
func TestMakefile_ReleaseE2ECheck(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	mk := readMakefile(t, filepath.Join(root, "Makefile"))
	if !slices.Contains(mk.phony, "release-e2e-check") {
		t.Errorf(".PHONY = %q, want release-e2e-check", mk.phony)
	}
	if !slices.Contains(mk.prereqs["verify"], "release-e2e-check") {
		t.Errorf("verify prerequisites = %q, want release-e2e-check", mk.prereqs["verify"])
	}
	if _, ok := mk.prereqs["release-e2e-check"]; !ok {
		t.Fatal("no release-e2e-check target in the Makefile")
	}
	if !strings.Contains(mk.recipes["release-check"], "goreleaser") {
		t.Errorf("release-check recipe = %q, want the goreleaser snapshot kept separate", mk.recipes["release-check"])
	}
	if strings.Contains(mk.recipes["release-check"], "release-e2e-check") {
		t.Error("release-check must stay the goreleaser snapshot, not call release-e2e-check")
	}

	if _, err := exec.LookPath("make"); err != nil {
		t.Fatalf("make not found: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), "make", "-s", "--no-print-directory", "release-e2e-check")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("make release-e2e-check: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if got := stdout.String(); got != wantOKLine+"\n" {
		t.Fatalf("make release-e2e-check stdout = %q, want exactly %q", got, wantOKLine+"\n")
	}
}

// makefile is the little of a Makefile the test needs: targets with their
// prerequisites and recipe text, and the .PHONY list.
type makefile struct {
	phony   []string
	prereqs map[string][]string
	recipes map[string]string
}

func readMakefile(t *testing.T, path string) makefile {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	mk := makefile{prereqs: map[string][]string{}, recipes: map[string]string{}}
	var current string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "\t") {
			if current != "" {
				mk.recipes[current] += strings.TrimSpace(line) + "\n"
			}
			continue
		}
		current = ""
		if strings.HasPrefix(line, "#") || strings.Contains(line, ":=") || strings.Contains(line, "?=") {
			continue
		}
		target, rest, ok := strings.Cut(line, ":")
		if !ok || strings.ContainsAny(target, " \t$") || target == "" {
			continue
		}
		rest, _, _ = strings.Cut(rest, "#")
		fields := strings.Fields(rest)
		if target == ".PHONY" {
			mk.phony = append(mk.phony, fields...)
			continue
		}
		mk.prereqs[target] = fields
		current = target
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan Makefile: %v", err)
	}
	return mk
}
