// Command release-e2e-check proves that the release build of facto
// contains no e2e-only code (J1 task T17; ADR 0009 "Key source", decision
// A3), and that the check itself is not vacuous.
//
// The release build is builds[id=facto] of .goreleaser.yaml: its main
// package, env, flags, ldflags ("{{ .Version }}" replaced by checkVersion)
// and tags are read from the file, never hard-coded. Three checks run on
// it, with exactly those flags:
//
//   - `go list -deps` of the main package lists no e2e-only package: a
//     package of this module with an import path element starting with
//     "e2e" (internal/vault/e2ekey, internal/secret/e2efile) or equal to
//     "fakeprovider" (connectors/fakeprovider);
//   - no Go file compiled into any dependency has a //go:build (or
//     // +build) constraint mentioning the "e2e" tag (internal/browser's
//     flags_e2e.go, internal/httpx's loopback_e2e.go);
//   - `go tool nm` on the binary lists no symbol of an e2e-only package and
//     none of e2eOnlySymbols (internal/browser FlagsE2E, E2EOverrides,
//     WithE2E, CheckFlagsE2E, PoolE2E; internal/httpx NewLoopback).
//     A release binary is linked with -s (no symbol table), so the nm
//     binary is built with the same flags minus the single "-s" ldflag,
//     which changes nothing about what is linked. An nm listing no symbol
//     at all is an error, never a pass.
//
// Self-test: the same inspection of the -tags e2e build must find
// internal/vault/e2ekey and internal/secret/e2efile among the deps and their
// Sentinel symbols in nm, and every selfTestFuncs entry in nm, otherwise
// the check is vacuous and fails.
//
// Exit status: 0 and exactly okLine on stdout when every check passed; 1
// when a check failed (one stderr line per finding); 2 on a usage or I/O
// error (bad flag, unreadable goreleaser file, go command failure). The
// tree is never modified: binaries go to a private temporary directory
// under <root>/.cache, removed on exit.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go/build/constraint"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// okLine is printed on success, alone, followed by "\n".
const okLine = "release-check: release build has no e2e-only code"

// checkVersion replaces "{{ .Version }}" in the goreleaser ldflags.
const checkVersion = "0.0.0-release-e2e-check"

// e2eTag is the build tag of e2e-only code.
const e2eTag = "e2e"

// Exit codes.
const (
	exitOK    = 0
	exitFound = 1
	exitError = 2
)

// errNoBuild: the file has no build with id "facto" (or no builds).
var errNoBuild = errors.New("release-e2e-check: no facto build in goreleaser config")

// selfTestPkgs are the module-relative packages the -tags e2e build must
// link, each with its Sentinel symbol.
var selfTestPkgs = []string{"internal/vault/e2ekey", "internal/secret/e2efile"}

// e2eOnlySymbols are the identifiers declared only in e2e-tagged files of
// packages the release build links (internal/browser's flags_e2e.go,
// internal/httpx's loopback_e2e.go).
var e2eOnlySymbols = []string{
	"internal/browser.FlagsE2E",
	"internal/browser.E2EOverrides",
	"internal/browser.WithE2E",
	"internal/browser.CheckFlagsE2E",
	"internal/browser.PoolE2E",
	"internal/httpx.NewLoopback",
}

// selfTestFuncs are the e2e-only functions cmd/facto calls in a -tags e2e
// build: the self-test requires each in that binary's nm listing, so the
// e2eOnlySymbols check is not vacuous.
var selfTestFuncs = []string{
	"internal/browser.WithE2E",
	"internal/browser.CheckFlagsE2E",
	"internal/httpx.NewLoopback",
}

// releaseBuild is builds[id=facto] of .goreleaser.yaml.
type releaseBuild struct {
	Main    string   // "./cmd/facto"
	Env     []string // ["CGO_ENABLED=0"]
	Flags   []string // ["-trimpath"]
	Ldflags []string // templates expanded with checkVersion
	Tags    []string // goreleaser "tags"; empty today
	// Targets are the "goos/goarch" pairs of goos x goarch; go list and the
	// tagged-file check run once per target. Empty means the host only.
	Targets []string
}

// stringList decodes a YAML scalar or sequence of scalars.
type stringList []string

// UnmarshalYAML accepts "x" as ["x"].
func (l *stringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = stringList{n.Value}
		return nil
	}
	var s []string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("decode list: %w", err)
	}
	*l = s
	return nil
}

// goreleaserConfig is the part of .goreleaser.yaml the check reads.
type goreleaserConfig struct {
	Builds []struct {
		ID      string     `yaml:"id"`
		Main    string     `yaml:"main"`
		Env     stringList `yaml:"env"`
		Flags   stringList `yaml:"flags"`
		Ldflags stringList `yaml:"ldflags"`
		Tags    stringList `yaml:"tags"`
		Goos    stringList `yaml:"goos"`
		Goarch  stringList `yaml:"goarch"`
	} `yaml:"builds"`
}

// loadRelease reads path (YAML, unknown keys ignored). A missing file wraps
// fs.ErrNotExist; no facto build is errNoBuild; a build without main, with
// an e2e tag or with a template other than {{ .Version }} is an error.
func loadRelease(path string) (releaseBuild, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return releaseBuild{}, fmt.Errorf("read goreleaser config: %w", err)
	}
	var cfg goreleaserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return releaseBuild{}, fmt.Errorf("parse goreleaser config: %w", err)
	}
	for _, b := range cfg.Builds {
		if b.ID != "facto" {
			continue
		}
		if b.Main == "" {
			return releaseBuild{}, errors.New("release-e2e-check: facto build has no main")
		}
		for _, tag := range b.Tags {
			if tag == e2eTag {
				return releaseBuild{}, errors.New("release-e2e-check: facto release build sets the e2e tag")
			}
		}
		rb := releaseBuild{Main: b.Main, Env: b.Env, Flags: b.Flags, Tags: b.Tags}
		for _, goos := range b.Goos {
			for _, goarch := range b.Goarch {
				rb.Targets = append(rb.Targets, goos+"/"+goarch)
			}
		}
		for _, l := range b.Ldflags {
			l = strings.ReplaceAll(l, "{{ .Version }}", checkVersion)
			if strings.Contains(l, "{{") {
				return releaseBuild{}, errors.New("release-e2e-check: unsupported template in facto ldflags")
			}
			rb.Ldflags = append(rb.Ldflags, l)
		}
		return rb, nil
	}
	return releaseBuild{}, errNoBuild
}

// listFormat prints one line per package: import path, directory, module
// path (empty for the standard library), then the compiled Go files.
const listFormat = `{{.ImportPath}}{{"\t"}}{{.Dir}}{{"\t"}}{{with .Module}}{{.Path}}{{end}}{{"\t"}}{{join .GoFiles "\t"}}{{"\t"}}{{join .CgoFiles "\t"}}`

// buildFlags returns b.Flags, -ldflags and -tags (b.Tags plus extraTags,
// only when non-empty), with ldflags as given.
func (b releaseBuild) buildFlags(extraTags, ldflags []string) []string {
	args := slices.Clone(b.Flags)
	args = append(args, "-ldflags="+strings.Join(ldflags, " "))
	if tags := slices.Concat(b.Tags, extraTags); len(tags) > 0 {
		args = append(args, "-tags="+strings.Join(tags, ","))
	}
	return args
}

// listArgs returns the arguments after "go" for
// `go list -deps -f … <flags> <-ldflags=…> [-tags=…] <main>`.
func (b releaseBuild) listArgs(extraTags []string) []string {
	return b.listPkgsArgs(extraTags, b.Main)
}

// listPkgsArgs is listArgs over pkgs instead of the main package.
func (b releaseBuild) listPkgsArgs(extraTags []string, pkgs ...string) []string {
	args := append([]string{"list", "-deps", "-f", listFormat}, b.buildFlags(extraTags, b.Ldflags)...)
	return append(args, pkgs...)
}

// nmBuildArgs returns the arguments after "go" for the `go build` of the nm
// binary written to out: as listArgs but "build -o out", and the ldflags
// with the single "-s" field removed (nothing else changes).
func (b releaseBuild) nmBuildArgs(extraTags []string, out string) []string {
	fields := strings.Fields(strings.Join(b.Ldflags, " "))
	fields = slices.DeleteFunc(fields, func(f string) bool { return f == "-s" })
	args := append([]string{"build", "-o", out}, b.buildFlags(extraTags, []string{strings.Join(fields, " ")})...)
	return append(args, b.Main)
}

// report is what one inspection found. Each list is sorted, no dups.
type report struct {
	Deps    []string // forbidden import paths among the deps of main
	Files   []string // e2e-tagged Go files compiled in, module-relative slash paths
	Symbols []string // forbidden nm symbols
	NM      int      // number of symbols nm listed (0 = vacuous, an error)
}

// listedPkg is one line of `go list -deps -f listFormat`.
type listedPkg struct {
	importPath string
	dir        string
	module     string
	files      []string
}

// inspect runs go list and go build + go tool nm for b plus extraTags, from
// module root, with b.Env appended to the environment, binaries under tmp.
// go list and the tagged-file check cover every release target (a
// windows- or darwin-only file could pull e2e code); the nm binary is built
// for the host only: go tool nm reads any target's binary, but the package
// set is already checked per target and one link is enough to prove the
// symbol check is not vacuous. It never modifies the tree.
func inspect(ctx context.Context, root string, b releaseBuild, extraTags []string, tmp string) (report, error) {
	mod, err := modulePath(root)
	if err != nil {
		return report{}, err
	}
	pkgs, err := goList(ctx, root, b, b.listArgs(extraTags))
	if err != nil {
		return report{}, err
	}
	var rep report
	for _, p := range pkgs {
		if forbiddenPkg(mod, p.importPath) {
			rep.Deps = append(rep.Deps, p.importPath)
		}
	}
	if rep.Files, err = taggedFiles(root, mod, pkgs); err != nil {
		return report{}, err
	}

	bin := filepath.Join(tmp, "facto-nm")
	if _, err := runGo(ctx, root, b.Env, b.nmBuildArgs(extraTags, bin)); err != nil {
		return report{}, err
	}
	out, err := runGo(ctx, root, b.Env, []string{"tool", "nm", bin})
	if err != nil {
		return report{}, err
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		name := symbolName(sc.Text())
		if name == "" {
			continue
		}
		rep.NM++
		if forbiddenSymbol(mod, name) {
			rep.Symbols = append(rep.Symbols, name)
		}
	}
	if err := sc.Err(); err != nil {
		return report{}, fmt.Errorf("read go tool nm output: %w", err)
	}
	rep.Deps = sortedUnique(rep.Deps)
	rep.Symbols = sortedUnique(rep.Symbols)
	return rep, nil
}

// e2eFiles returns the e2e-tagged Go files compiled into pkgs (and their
// deps) with b's flags plus extraTags.
func e2eFiles(ctx context.Context, root string, b releaseBuild, extraTags []string, pkgs ...string) ([]string, error) {
	mod, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	listed, err := goList(ctx, root, b, b.listPkgsArgs(extraTags, pkgs...))
	if err != nil {
		return nil, err
	}
	return taggedFiles(root, mod, listed)
}

// goList runs go list with args once per release target (b.Targets, or
// the host when empty) and returns every listed package once, with the
// union of its compiled files over the targets.
func goList(ctx context.Context, root string, b releaseBuild, args []string) ([]listedPkg, error) {
	targets := b.Targets
	if len(targets) == 0 {
		targets = []string{""}
	}
	var merged []listedPkg
	index := map[string]int{}
	for _, target := range targets {
		env := b.Env
		if target != "" {
			goos, goarch, ok := strings.Cut(target, "/")
			if !ok {
				return nil, fmt.Errorf("release target %q: want goos/goarch", target)
			}
			env = slices.Concat(b.Env, []string{"GOOS=" + goos, "GOARCH=" + goarch})
		}
		pkgs, err := goListOnce(ctx, root, env, args)
		if err != nil {
			return nil, fmt.Errorf("target %s: %w", target, err)
		}
		for _, p := range pkgs {
			i, seen := index[p.importPath]
			if !seen {
				index[p.importPath] = len(merged)
				merged = append(merged, p)
				continue
			}
			merged[i].files = sortedUnique(append(merged[i].files, p.files...))
		}
	}
	return merged, nil
}

// goListOnce runs go list with args and env and parses its listFormat
// output.
func goListOnce(ctx context.Context, root string, env, args []string) ([]listedPkg, error) {
	out, err := runGo(ctx, root, env, args)
	if err != nil {
		return nil, err
	}
	var pkgs []listedPkg
	for line := range strings.Lines(string(out)) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			return nil, fmt.Errorf("go list: unexpected line %q", line)
		}
		p := listedPkg{importPath: f[0], dir: f[1], module: f[2]}
		for _, name := range f[3:] {
			if name != "" {
				p.files = append(p.files, name)
			}
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// taggedFiles returns the files of pkgs whose build constraint mentions the
// e2e tag: module-relative slash paths for this module, import path plus
// file name for other modules. The standard library is skipped.
func taggedFiles(root, mod string, pkgs []listedPkg) ([]string, error) {
	var out []string
	for _, p := range pkgs {
		if p.module == "" {
			continue // standard library
		}
		for _, name := range p.files {
			tagged, err := mentionsE2E(filepath.Join(p.dir, name))
			if err != nil {
				return nil, err
			}
			if !tagged {
				continue
			}
			rel := path.Join(p.importPath, name)
			if p.module == mod {
				r, err := filepath.Rel(root, filepath.Join(p.dir, name))
				if err != nil {
					return nil, fmt.Errorf("relative path: %w", err)
				}
				rel = filepath.ToSlash(r)
			}
			out = append(out, rel)
		}
	}
	return sortedUnique(out), nil
}

// mentionsE2E reports whether the //go:build or // +build lines of the Go
// file at p mention the e2e tag, negated or not. Only the header before the
// package clause is read.
func mentionsE2E(p string) (bool, error) {
	f, err := os.Open(filepath.Clean(p))
	if err != nil {
		return false, fmt.Errorf("open go file: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "package ") {
			return false, nil
		}
		if !constraint.IsGoBuild(line) && !constraint.IsPlusBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			return false, fmt.Errorf("%s: build constraint: %w", p, err)
		}
		mentioned := false
		expr.Eval(func(tag string) bool {
			mentioned = mentioned || tag == e2eTag
			return true
		})
		if mentioned {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("read %s: %w", p, err)
	}
	return false, nil
}

// forbiddenPkg reports an e2e-only package of module mod: an import path
// element starting with "e2e" or equal to "fakeprovider".
func forbiddenPkg(mod, importPath string) bool {
	rest, ok := strings.CutPrefix(importPath, mod+"/")
	if !ok {
		return false
	}
	for _, el := range strings.Split(rest, "/") {
		if strings.HasPrefix(el, e2eTag) || el == "fakeprovider" {
			return true
		}
	}
	return false
}

// forbiddenSymbol reports a symbol naming an e2e-only package of mod, or an
// internal/browser e2e-only identifier.
func forbiddenSymbol(mod, sym string) bool {
	for _, s := range e2eOnlySymbols {
		if strings.Contains(sym, mod+"/"+s) {
			return true
		}
	}
	rest := sym
	for {
		i := strings.Index(rest, mod+"/")
		if i < 0 {
			return false
		}
		rest = rest[i:]
		// The package path ends at the first "." after the module path.
		pkg := rest
		if j := strings.IndexByte(rest[len(mod):], '.'); j >= 0 {
			pkg = rest[:len(mod)+j]
		}
		if forbiddenPkg(mod, pkg) {
			return true
		}
		rest = rest[len(mod):]
	}
}

// symbolName returns the name of one `go tool nm` line ("addr T name" or
// "U name"; names may hold spaces), or "" for a blank line.
func symbolName(line string) string {
	f := strings.Fields(line)
	switch {
	case len(f) == 0:
		return ""
	case len(f[0]) == 1 && len(f) >= 2: // undefined symbol: no address
		return strings.Join(f[1:], " ")
	case len(f) >= 3:
		return strings.Join(f[2:], " ")
	default:
		return strings.Join(f, " ")
	}
}

// modulePath reads the module path from <root>/go.mod.
func modulePath(root string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(filepath.Join(root, "go.mod")))
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	for line := range strings.Lines(string(data)) {
		if m, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(m), `"`), nil
		}
	}
	return "", errors.New("go.mod: no module line")
}

// runGo runs the go command in root with env appended to the environment
// (GOFLAGS cleared and GOENV=off, so neither the operator's environment
// nor their go env file can change the build)
// and returns its stdout. A failure carries go's stderr.
func runGo(ctx context.Context, root string, env, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- fixed go binary, argv from .goreleaser.yaml, no shell (J1-T17, SEC-J0-14 tracking issue (BLOCKED H1))
	cmd.Dir = root
	cmd.Env = slices.Concat(os.Environ(), []string{"GOFLAGS=", "GOENV=off"}, env)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func sortedUnique(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)) }

// run is main without os.Exit.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("release-e2e-check", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", ".", "module root")
	grFile := fl.String("goreleaser", "", `goreleaser config (default "<root>/.goreleaser.yaml")`)
	relTags := fl.String("release-tags", "", "extra tags for the release side (test hook; must make the check fail)")
	if err := fl.Parse(args); err != nil {
		return exitError // flag already printed the error and usage
	}
	if fl.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "release-e2e-check: unexpected arguments %q\n", fl.Args())
		return exitError
	}
	if *grFile == "" {
		*grFile = filepath.Join(*root, ".goreleaser.yaml")
	}
	var extra []string
	if *relTags != "" {
		extra = strings.Split(*relTags, ",")
	}
	findings, err := check(ctx, *root, *grFile, extra)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "release-e2e-check: %v\n", err)
		return exitError
	}
	if len(findings) > 0 {
		for _, f := range findings {
			_, _ = fmt.Fprintf(stderr, "release-check: %s\n", f)
		}
		return exitFound
	}
	if _, err := fmt.Fprintln(stdout, okLine); err != nil {
		return exitError
	}
	return exitOK
}

// check inspects the release build (plus extraTags) and the -tags e2e
// self-test build and returns one line per finding.
func check(ctx context.Context, root, grFile string, extraTags []string) (findings []string, err error) {
	b, err := loadRelease(grFile)
	if err != nil {
		return nil, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("module root: %w", err)
	}
	mod, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	tmp, cleanup, err := tempDir(root)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := cleanup(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	rel, err := inspect(ctx, root, b, extraTags, filepath.Join(tmp, "release"))
	if err != nil {
		return nil, fmt.Errorf("release build: %w", err)
	}
	for _, d := range rel.Deps {
		findings = append(findings, "release build depends on e2e-only package "+d)
	}
	for _, f := range rel.Files {
		findings = append(findings, "release build compiles e2e-tagged file "+f)
	}
	for _, s := range rel.Symbols {
		findings = append(findings, "release binary has e2e-only symbol "+s)
	}
	if rel.NM == 0 {
		findings = append(findings, "go tool nm listed no symbol on the release-flags binary: the symbol check is vacuous")
	}

	self, err := inspect(ctx, root, b, []string{e2eTag}, filepath.Join(tmp, "e2e"))
	if err != nil {
		return nil, fmt.Errorf("e2e self-test build: %w", err)
	}
	for _, p := range selfTestPkgs {
		pkg := mod + "/" + p
		if !slices.Contains(self.Deps, pkg) {
			findings = append(findings, "self-test: -tags e2e deps lack "+pkg+" (go list check is vacuous)")
		}
		if !slices.ContainsFunc(self.Symbols, func(s string) bool { return strings.HasSuffix(s, pkg+".Sentinel") }) {
			findings = append(findings, "self-test: -tags e2e binary lacks "+pkg+".Sentinel (nm check is vacuous)")
		}
	}
	for _, f := range selfTestFuncs {
		sym := mod + "/" + f
		if !slices.ContainsFunc(self.Symbols, func(s string) bool { return s == sym || strings.HasPrefix(s, sym+".") }) {
			findings = append(findings, "self-test: -tags e2e binary lacks "+sym+" (nm check is vacuous)")
		}
	}
	return findings, nil
}

// tempDir creates a private temporary directory under
// <root>/.cache/release-e2e-check (gitignored) with "release" and "e2e"
// subdirectories, and returns it with its cleanup.
func tempDir(root string) (string, func() error, error) {
	r, err := fsx.Open(root)
	if err != nil {
		return "", nil, fmt.Errorf("temp dir: %w", err)
	}
	const base = ".cache/release-e2e-check"
	err = r.MkdirPrivate(base)
	if cerr := r.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return "", nil, fmt.Errorf("temp dir: %w", err)
	}
	parent := filepath.Join(root, filepath.FromSlash(base))
	dir, err := fsx.MkdirTempPrivate(parent, "run-*")
	if err != nil {
		return "", nil, fmt.Errorf("temp dir: %w", err)
	}
	cleanup := func() error {
		if err := fsx.RemoveTree(parent, filepath.Base(dir)); err != nil {
			return fmt.Errorf("remove temp dir: %w", err)
		}
		return nil
	}
	sub, err := fsx.Open(dir)
	if err == nil {
		err = errors.Join(sub.MkdirPrivate("release"), sub.MkdirPrivate("e2e"), sub.Close())
	}
	if err != nil {
		return "", nil, errors.Join(fmt.Errorf("temp dir: %w", err), cleanup())
	}
	return dir, cleanup, nil
}
