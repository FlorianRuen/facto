//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

const (
	buildTimeout = 5 * time.Minute
	runTimeout   = 2 * time.Minute
)

// TestE2E builds ./cmd/facto once and runs every test/e2e/*.yaml scenario as
// the subtest TestE2E/<name>, each in its own sandboxed HOME.
func TestE2E(t *testing.T) {
	scenarios := loadScenarios(t)
	bin := buildFacto(t)
	for _, sc := range scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			t.Parallel()
			runScenario(t, bin, sc)
		})
	}
}

// loadScenarios parses every *.yaml next to this file; a scenario's name
// must equal its file stem.
func loadScenarios(t *testing.T) []*Scenario {
	t.Helper()
	files, err := filepath.Glob("*.yaml")
	if err != nil {
		t.Fatalf("glob scenarios: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no test/e2e/*.yaml scenario found")
	}
	slices.Sort(files)
	out := make([]*Scenario, 0, len(files))
	for _, f := range files {
		data, err := readIn(".", f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sc, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if stem := strings.TrimSuffix(f, ".yaml"); sc.Name != stem {
			t.Fatalf("%s: name %q, want the file stem %q", f, sc.Name, stem)
		}
		out = append(out, sc)
	}
	return out
}

// buildFacto compiles ./cmd/facto into a temp dir with fixed arguments.
func buildFacto(t *testing.T) string {
	t.Helper()
	mod, err := moduleRoot()
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "facto")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	ctx, cancel := context.WithTimeout(t.Context(), buildTimeout)
	defer cancel()
	// #nosec G204 -- fixed argv; bin is a path under t.TempDir() (J0-T27, no GitHub issue yet)
	// -tags e2e: fakeprovider, e2e:// secrets, stdin prompts and the
	// FACTO_E2E_* loopback/CA/Chrome wiring exist only in that build.
	cmd := exec.CommandContext(ctx, "go", "build", "-tags", "e2e", "-trimpath", "-o", bin, "./cmd/facto")
	cmd.Dir = mod
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/facto: %v\n%s", err, out)
	}
	return bin
}

// readIn reads the regular file rel inside dir through an os.Root: a
// symlink or ".." in rel cannot make the harness read outside dir.
func readIn(dir, rel string) ([]byte, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	defer func() { _ = r.Close() }()
	b, err := r.ReadFile(rel)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	return b, nil
}

func moduleRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	for dir := wd; ; {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod above %s", wd)
		}
		dir = parent
	}
}

// sandbox is one scenario's private world: HOME, TMPDIR and an empty PATH
// directory (the binary may not exec any host tool, bw included).
type sandbox struct {
	root, home, tmp, pathDir string
	canaries                 map[string]string // kind -> value
	canaryFiles              map[string]bool   // setup paths holding a canary

	site     *siteRun          // fake site of the scenario, nil without fakesite
	extraEnv map[string]string // FACTO_E2E_* variables; "" values are omitted
	stdin    []string          // lines fed to facto (scenario stdin key)
	pid      atomic.Int64      // facto's pid while a run is in progress

	mu          sync.Mutex
	totpSecrets []string // TOTP codes handed to facto (secrets, stdin)
}

// factoPID is facto's pid during a run, 0 otherwise.
func (s *sandbox) factoPID() int { return int(s.pid.Load()) }

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	// Not t.TempDir: its path embeds the test name, and the browser pool
	// base (the scenario state dir's tmp, under HOME) must stay short
	// enough for Chrome's private TMPDIR next to the profile
	// (SingletonSocket path <= 107 bytes, browser.ErrSocketPathTooLong).
	root, err := os.MkdirTemp("", "fe2e") // 0700
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	r, err := fsx.Open(root)
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	defer func() { _ = r.Close() }()
	for _, d := range []string{"home", "tmp", "path"} {
		if err := r.MkdirPrivate(d); err != nil {
			t.Fatalf("sandbox mkdir %s: %v", d, err)
		}
	}
	return &sandbox{
		root:        root,
		home:        filepath.Join(root, "home"),
		tmp:         filepath.Join(root, "tmp"),
		pathDir:     filepath.Join(root, "path"),
		canaries:    map[string]string{},
		canaryFiles: map[string]bool{},
	}
}

// env is built from scratch: nothing of the test process environment (no
// BW_SESSION, no real HOME, no CANARY_FILE) reaches the binary.
func (s *sandbox) env() []string {
	env := []string{
		"HOME=" + s.home,
		"USERPROFILE=" + s.home,
		"APPDATA=" + filepath.Join(s.home, "AppData", "Roaming"),
		"XDG_CONFIG_HOME=" + filepath.Join(s.home, ".config"),
		"XDG_CACHE_HOME=" + filepath.Join(s.home, ".cache"),
		"XDG_DATA_HOME=" + filepath.Join(s.home, ".local", "share"),
		"XDG_STATE_HOME=" + filepath.Join(s.home, ".local", "state"),
		"TMPDIR=" + s.tmp,
		"PATH=" + s.pathDir,
		"LANG=C.UTF-8",
		"TZ=UTC",
		// A socket that never exists, outside HOME: the keyring client
		// cannot fall back to the developer's /run/user/<uid>/bus.
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + filepath.Join(s.root, "no-session-bus"),
	}
	keys := make([]string, 0, len(s.extraEnv))
	for k := range s.extraEnv {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if v := s.extraEnv[k]; v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func (s *sandbox) canary(t *testing.T) func(string) string {
	return func(kind string) string {
		if v, ok := s.canaries[kind]; ok {
			return v
		}
		v := testsecrets.Canary(t, testsecrets.Kind(kind))
		s.canaries[kind] = v
		return v
	}
}

func (s *sandbox) abs(rel string) string { return filepath.Join(s.home, filepath.FromSlash(rel)) }

// setup creates every setup entry in order, parents 0700.
func (s *sandbox) setup(t *testing.T, sc *Scenario) {
	t.Helper()
	r, err := fsx.Open(s.home)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer func() { _ = r.Close() }()
	for _, f := range sc.Setup {
		if d := path.Dir(f.Path); d != "." {
			if err := r.MkdirPrivate(d); err != nil {
				t.Fatalf("setup %s: %v", f.Path, err)
			}
		}
		mode := uint32(0o600)
		switch {
		case f.Dir:
			mode = 0o700
			if err := r.MkdirPrivate(f.Path); err != nil {
				t.Fatalf("setup %s: %v", f.Path, err)
			}
		case f.Symlink != "":
			if err := os.Symlink(filepath.FromSlash(f.Symlink), s.abs(f.Path)); err != nil {
				t.Fatalf("setup %s: %v", f.Path, err)
			}
			continue
		case f.Fixture != "":
			if err := r.WriteAtomic(t.Context(), f.Path, readFixture(t, f.Fixture)); err != nil {
				t.Fatalf("setup %s: %v", f.Path, err)
			}
		default:
			content := Expand(*f.Content, s.home, s.canary(t))
			if strings.Contains(*f.Content, "{{canary:") {
				s.canaryFiles[f.Path] = true
			}
			if err := r.WriteAtomic(t.Context(), f.Path, []byte(content)); err != nil {
				t.Fatalf("setup %s: %v", f.Path, err)
			}
		}
		if f.Mode != "" {
			m, _ := ParseMode(f.Mode) // validated by Parse
			mode = m
		}
		if err := os.Chmod(s.abs(f.Path), fs.FileMode(mode)); err != nil {
			t.Fatalf("setup chmod %s: %v", f.Path, err)
		}
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := readIn("testdata", name)
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

// result is one run of the binary.
type result struct {
	code           int
	stdout, stderr []byte
}

func (s *sandbox) run(t *testing.T, bin string, args []string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), runTimeout)
	defer cancel()
	argv := make([]string, len(args))
	for i, a := range args {
		argv[i] = Expand(a, s.home, s.canary(t))
	}
	// #nosec G204 -- bin is the binary built by buildFacto; argv comes from the checked-in scenario (J0-T27, no GitHub issue yet)
	cmd := exec.CommandContext(ctx, bin, argv...)
	cmd.Dir = s.home
	cmd.Env = s.env()
	cmd.Stdin = nil // /dev/null: not a terminal, collect never prompts
	var feed sync.WaitGroup
	var feedErr error
	feedCtx, factoExited := context.WithCancel(ctx)
	defer factoExited()
	if len(s.stdin) > 0 {
		// Canaries are expanded now; {{totp}} and {{outbox}} when written.
		lines := make([]string, len(s.stdin))
		for i, l := range s.stdin {
			lines[i] = ExpandFunc(l, func(name string) string {
				if kind, ok := strings.CutPrefix(name, "canary:"); ok {
					return s.canary(t)(kind)
				}
				return "{{" + name + "}}"
			})
		}
		w, err := cmd.StdinPipe()
		if err != nil {
			t.Fatalf("stdin pipe: %v", err)
		}
		from := 0
		if s.site != nil {
			from = len(s.site.site.Outbox()) // {{outbox}}: codes of this run only
		}
		feed.Add(1)
		defer func() {
			_ = w.Close()
		}()
		go func() {
			defer feed.Done()
			feedErr = s.feedStdin(feedCtx, w, lines, from)
		}()
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	s.armProbes()
	err := cmd.Start()
	if err == nil {
		s.pid.Store(int64(cmd.Process.Pid))
		err = cmd.Wait()
		s.pid.Store(0)
	}
	factoExited()
	if len(s.stdin) > 0 {
		feed.Wait()
		if feedErr != nil {
			t.Errorf("%v", feedErr)
		}
	}
	res := result{code: 0, stdout: out.Bytes(), stderr: errOut.Bytes()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		res.code = ee.ExitCode()
	default:
		t.Fatalf("run facto %q: %v\nstderr:\n%s", args, err, errOut.Bytes())
	}
	return res
}

func runScenario(t *testing.T, bin string, sc *Scenario) {
	s := newSandbox(t)
	s.setup(t, sc)
	if sc.FakeSite != nil || len(sc.Secrets) > 0 || len(sc.Stdin) > 0 {
		s.startSite(t, sc)
	}
	s.stdin = sc.Stdin
	art := testsecrets.ArtifactDir(t)

	s.resetSite()
	r1 := s.run(t, bin, sc.Args)
	s.saveArtifacts(t, art, "run1", sc, r1)
	s.saveRequestLog(t, art, "run1")
	s.check(t, "run 1", sc.Expect, r1)
	s.checkSite(t, "run 1", sc.Expect)
	s.checkNoCanary(t, "run 1", r1)

	if sc.Repeat == nil {
		return
	}
	before := make(map[string]map[string]string, len(sc.Repeat.Unchanged))
	for _, p := range sc.Repeat.Unchanged {
		before[p] = s.snapshot(t, p)
	}
	s.resetSite()
	r2 := s.run(t, bin, sc.Args)
	s.saveArtifacts(t, art, "run2", sc, r2)
	s.saveRequestLog(t, art, "run2")
	s.check(t, "run 2", sc.Repeat.Expect, r2)
	s.checkSite(t, "run 2", sc.Repeat.Expect)
	s.checkNoCanary(t, "run 2", r2)
	for _, p := range sc.Repeat.Unchanged {
		after := s.snapshot(t, p)
		if diff := diffSnapshots(before[p], after); diff != "" {
			t.Errorf("run 2: %s changed after the second run (not idempotent):\n%s", p, diff)
		}
	}
}

// saveArtifacts copies stdout, stderr and the whole state dir (reports, logs,
// index) under the test's artifact dir, for make leakcheck. Setup files are
// never copied: they may hold canaries on purpose.
func (s *sandbox) saveArtifacts(t *testing.T, art, run string, sc *Scenario, r result) {
	t.Helper()
	root, err := fsx.Open(art)
	if err != nil {
		t.Fatalf("artifacts: %v", err)
	}
	defer func() { _ = root.Close() }()
	write := func(name string, data []byte) {
		if d := path.Dir(name); d != "." {
			if err := root.MkdirPrivate(d); err != nil {
				t.Fatalf("artifacts mkdir %s: %v", d, err)
			}
		}
		if err := root.WriteAtomic(t.Context(), name, data); err != nil {
			t.Fatalf("artifacts write %s: %v", name, err)
		}
	}
	write(run+".stdout", r.stdout)
	write(run+".stderr", r.stderr)
	state := s.abs(sc.StateDir)
	err = filepath.WalkDir(state, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == state {
				return filepath.SkipDir
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(state, p)
		if err != nil {
			return err
		}
		data, err := readIn(state, rel)
		if err != nil {
			return err
		}
		write(run+"-state/"+filepath.ToSlash(rel), data)
		return nil
	})
	if err != nil {
		t.Fatalf("artifacts: copy state dir: %v", err)
	}
}

func (s *sandbox) check(t *testing.T, run string, e Expect, r result) {
	t.Helper()
	if r.code != *e.Exit {
		t.Errorf("%s: exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", run, r.code, *e.Exit, r.stdout, r.stderr)
	}
	checkOutput(t, run+" stdout", e.Stdout, string(r.stdout))
	checkOutput(t, run+" stderr", e.Stderr, string(r.stderr))

	for _, f := range e.Files {
		s.checkFile(t, run, f)
	}
	for _, p := range e.Absent {
		if _, err := os.Lstat(s.abs(p)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %s exists (err %v), want absent", run, p, err)
		}
	}
	for _, tr := range e.Trees {
		s.checkTree(t, run, tr)
	}
}

func checkOutput(t *testing.T, what string, o Output, got string) {
	t.Helper()
	if o.Empty && got != "" {
		t.Errorf("%s = %q, want empty", what, got)
	}
	if o.Prefix != "" && !strings.HasPrefix(got, o.Prefix) {
		t.Errorf("%s = %q, want prefix %q", what, got, o.Prefix)
	}
	for _, sub := range o.Contains {
		if !strings.Contains(got, sub) {
			t.Errorf("%s does not contain %q:\n%s", what, sub, got)
		}
	}
	for _, sub := range o.NotContains {
		if strings.Contains(got, sub) {
			t.Errorf("%s contains %q, must not:\n%s", what, sub, got)
		}
	}
}

func (s *sandbox) checkFile(t *testing.T, run string, f ExpectFile) {
	t.Helper()
	fi, err := os.Lstat(s.abs(f.Path))
	if err != nil {
		t.Errorf("%s: expected file %s: %v (files under HOME: %q)", run, f.Path, err, s.listing(t, "."))
		return
	}
	if !fi.Mode().IsRegular() {
		t.Errorf("%s: %s is %v, want a regular file", run, f.Path, fi.Mode().Type())
		return
	}
	if f.Mode != "" && runtime.GOOS != "windows" {
		want, _ := ParseMode(f.Mode)
		if got := uint32(fi.Mode().Perm()); got != want {
			t.Errorf("%s: %s mode = %#o, want %#o", run, f.Path, got, want)
		}
	}
	var want []byte
	switch {
	case f.Fixture != "":
		want = readFixture(t, f.Fixture)
	case f.Content != nil:
		want = []byte(Expand(*f.Content, s.home, s.canary(t)))
	default:
		return
	}
	got, err := readIn(s.home, filepath.FromSlash(f.Path))
	if err != nil {
		t.Errorf("%s: read %s: %v", run, f.Path, err)
		return
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: %s content differs from the expected %d bytes (got %d bytes)", run, f.Path, len(want), len(got))
	}
}

func (s *sandbox) checkTree(t *testing.T, run string, tr Tree) {
	t.Helper()
	root := s.abs(tr.Path)
	fi, err := os.Lstat(root)
	if err != nil || !fi.IsDir() {
		t.Errorf("%s: tree %s: not a directory (err %v)", run, tr.Path, err)
		return
	}
	if tr.Entries != nil {
		want := slices.Clone(tr.Entries)
		slices.Sort(want)
		if got := s.listing(t, tr.Path); !slices.Equal(got, want) {
			t.Errorf("%s: entries under %s =\n  %q\nwant\n  %q", run, tr.Path, got, want)
		}
	}
	if !tr.Private || runtime.GOOS == "windows" {
		return
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(s.home, p)
		perm := info.Mode().Perm()
		switch {
		case info.IsDir() && perm != 0o700:
			t.Errorf("%s: directory %s mode = %#o, want 0700", run, filepath.ToSlash(rel), perm)
		case info.Mode().IsRegular() && perm != 0o600:
			t.Errorf("%s: file %s mode = %#o, want 0600", run, filepath.ToSlash(rel), perm)
		}
		return nil
	})
	if err != nil {
		t.Errorf("%s: walk %s: %v", run, tr.Path, err)
	}
}

// listing returns every entry below rel (HOME-relative), relative to it,
// sorted: directories end with "/", symlinks with "@". A missing rel lists
// nothing.
func (s *sandbox) listing(t *testing.T, rel string) []string {
	t.Helper()
	root := s.abs(rel)
	out := []string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == root {
				return filepath.SkipDir
			}
			return err
		}
		if p == root {
			return nil
		}
		r, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(r)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			name += "@"
		case d.IsDir():
			name += "/"
		}
		out = append(out, name)
		return nil
	})
	if err != nil {
		t.Fatalf("list %s: %v", rel, err)
	}
	slices.Sort(out)
	return out
}

// snapshot maps every entry below rel to its type, mode and content hash.
func (s *sandbox) snapshot(t *testing.T, rel string) map[string]string {
	t.Helper()
	root := s.abs(rel)
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		r, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		v := info.Mode().String()
		if info.Mode().IsRegular() {
			data, err := readIn(root, r)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			v += " " + hex.EncodeToString(sum[:])
		}
		out[filepath.ToSlash(r)] = v
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", rel, err)
	}
	return out
}

func diffSnapshots(before, after map[string]string) string {
	var lines []string
	for k, v := range before {
		if w, ok := after[k]; !ok {
			lines = append(lines, "- "+k+" (removed)")
		} else if w != v {
			lines = append(lines, "~ "+k+" ("+v+" -> "+w+")")
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			lines = append(lines, "+ "+k+" (added)")
		}
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// checkNoCanary fails if a canary of the scenario appears in stdout, stderr
// or any file under HOME other than the setup files that held it.
func (s *sandbox) checkNoCanary(t *testing.T, run string, r result) {
	t.Helper()
	if s.site != nil {
		for _, f := range s.siteLeaks(s.siteSecrets(), r) {
			t.Errorf("%s: %s", run, f)
		}
	}
	if len(s.canaries) == 0 {
		return
	}
	for kind, v := range s.canaries {
		if bytes.Contains(r.stdout, []byte(v)) {
			t.Errorf("%s: %s canary leaked to stdout", run, kind)
		}
		if bytes.Contains(r.stderr, []byte(v)) {
			t.Errorf("%s: %s canary leaked to stderr", run, kind)
		}
	}
	err := filepath.WalkDir(s.home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, err := filepath.Rel(s.home, p)
		if err != nil {
			return err
		}
		if s.canaryFiles[filepath.ToSlash(rel)] {
			return nil
		}
		data, err := readIn(s.home, rel)
		if err != nil {
			return err
		}
		for kind, v := range s.canaries {
			if bytes.Contains(data, []byte(v)) {
				t.Errorf("%s: %s canary leaked to %s", run, kind, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Errorf("%s: canary scan: %v", run, err)
	}
}
