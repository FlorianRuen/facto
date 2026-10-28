// Tests for package testsecrets (J0 task T3): canary secrets for leak tests
// and the artifact directory scanned by scripts/leakcheck.sh. Permission tests
// live in testsecrets_unix_test.go, the leakcheck script test in
// leakcheck_test.go.
//
// Expected API (implementer: follow exactly):
//
//	// Kind names what a canary impersonates. Must match ^[a-z0-9]+$.
//	type Kind string
//	const (
//	    Password Kind = "password"
//	    Cookie   Kind = "cookie"
//	    Token    Kind = "token"
//	    Session  Kind = "session"
//	)
//
//	// Prefix starts every canary value.
//	const Prefix = "FACTO-CANARY-"
//
//	// Canary returns a fresh synthetic secret: Prefix + kind + "-" + at least
//	// 16 random characters from crypto/rand. Values only use [A-Za-z0-9-], are
//	// at least 32 bytes long and are unique per call (safe for concurrent use).
//	// When FACTO_CANARY == "1" (exactly) the value is appended, followed by
//	// "\n", to CanaryFile() through fsx (file 0600, missing parent directories
//	// created 0700, an existing parent used as is). An existing canary file with
//	// group/world permissions is refused (t fails, file untouched). An invalid
//	// kind or any I/O error fails t (t.Fatalf). Otherwise nothing is written.
//	func Canary(t testing.TB, kind Kind) string
//
//	// ArtifactDir returns a directory, created 0700, under ArtifactRoot()
//	// (itself created 0700 if missing; an existing one, e.g. 0755 from
//	// `mkdir -p` in the Makefile, is accepted). Each test gets its own
//	// directory derived from t.Name(); the name is sanitized so that it always
//	// stays strictly inside ArtifactRoot() (subtest names may contain "/" and
//	// ".."). The directory is NOT removed at the end of the test: leakcheck
//	// greps it afterwards. Any error fails t.
//	func ArtifactDir(t testing.TB) string
//
//	// CanaryFile resolves $CANARY_FILE; unset or empty means
//	// <module root>/.cache/canaries.txt; a relative value is resolved against
//	// the module root (the directory holding go.mod, found by walking up from
//	// the working directory). The result is absolute and clean.
//	func CanaryFile() (string, error)
//
//	// ArtifactRoot resolves $ART_DIR the same way, defaulting to
//	// <module root>/.cache/test-artifacts.
//	func ArtifactRoot() (string, error)
package testsecrets_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

var canaryRe = regexp.MustCompile(`^[A-Za-z0-9-]{32,}$`)

// moduleRoot is computed independently of the package under test: tests run
// in internal/testsecrets, two levels below go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s has no go.mod: %v", root, err)
	}
	return root
}

// isolate points every testsecrets env var at a fresh temp dir and returns
// the canary file and artifact root paths (neither exists yet).
func isolate(t *testing.T, enabled string) (canaryFile, artRoot string) {
	t.Helper()
	dir := t.TempDir()
	canaryFile = filepath.Join(dir, "cache", "canaries.txt")
	artRoot = filepath.Join(dir, "cache", "test-artifacts")
	t.Setenv("FACTO_CANARY", enabled)
	t.Setenv("CANARY_FILE", canaryFile)
	t.Setenv("ART_DIR", artRoot)
	return canaryFile, artRoot
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		t.Fatalf("%s does not end with a newline: %q", path, b)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// writePrivate writes data to path through fsx (forbidigo bans os.WriteFile).
func writePrivate(t *testing.T, path string, data []byte) {
	t.Helper()
	dir, name := filepath.Split(path)
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open(%s): %v", dir, err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(context.Background(), name, data); err != nil {
		t.Fatalf("WriteAtomic(%s): %v", path, err)
	}
}

func mkdirPrivate(t *testing.T, base, rel string) {
	t.Helper()
	r, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open(%s): %v", base, err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate(rel); err != nil {
		t.Fatalf("MkdirPrivate(%s): %v", rel, err)
	}
}

func TestCanary_Format(t *testing.T) {
	isolate(t, "0")

	for _, kind := range []testsecrets.Kind{testsecrets.Password, testsecrets.Cookie, testsecrets.Token, testsecrets.Session} {
		v := testsecrets.Canary(t, kind)
		if !strings.HasPrefix(v, testsecrets.Prefix+string(kind)+"-") {
			t.Errorf("Canary(%s) = %q, want prefix %q", kind, v, testsecrets.Prefix+string(kind)+"-")
		}
		if !canaryRe.MatchString(v) {
			t.Errorf("Canary(%s) = %q, want ^[A-Za-z0-9-]{32,}$", kind, v)
		}
		if rnd := strings.TrimPrefix(v, testsecrets.Prefix+string(kind)+"-"); len(rnd) < 16 {
			t.Errorf("Canary(%s) random part %q shorter than 16", kind, rnd)
		}
	}
	if testsecrets.Prefix != "FACTO-CANARY-" {
		t.Fatalf("Prefix = %q", testsecrets.Prefix)
	}
}

func TestCanary_UniquePerCall(t *testing.T) {
	canaryFile, _ := isolate(t, "1")

	const workers, perWorker = 8, 50
	var (
		mu   sync.Mutex
		seen = map[string]bool{}
		wg   sync.WaitGroup
	)
	for range workers {
		wg.Go(func() {
			for range perWorker {
				v := testsecrets.Canary(t, testsecrets.Token)
				mu.Lock()
				if seen[v] {
					t.Errorf("duplicate canary %q", v)
				}
				seen[v] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(seen) != workers*perWorker {
		t.Fatalf("got %d distinct canaries, want %d", len(seen), workers*perWorker)
	}

	// Concurrent appends must not interleave: one whole value per line.
	lines := readLines(t, canaryFile)
	if len(lines) != workers*perWorker {
		t.Fatalf("canary file has %d lines, want %d", len(lines), workers*perWorker)
	}
	for _, l := range lines {
		if !seen[l] {
			t.Fatalf("canary file line %q is not a returned canary (interleaved write?)", l)
		}
	}
}

func TestCanary_RecordedWhenEnabled(t *testing.T) {
	canaryFile, _ := isolate(t, "1")

	a := testsecrets.Canary(t, testsecrets.Password)
	b := testsecrets.Canary(t, testsecrets.Cookie)
	// The parent directory did not exist: Canary created it.
	if got, want := readLines(t, canaryFile), []string{a, b}; !slices.Equal(got, want) {
		t.Fatalf("canary file lines = %q, want %q", got, want)
	}
}

func TestCanary_AppendsToExistingFile(t *testing.T) {
	canaryFile, _ := isolate(t, "1")
	mkdirPrivate(t, filepath.Dir(filepath.Dir(canaryFile)), filepath.Base(filepath.Dir(canaryFile)))
	const previous = "FACTO-CANARY-token-recordedbyanotherpackage"
	writePrivate(t, canaryFile, []byte(previous+"\n"))

	v := testsecrets.Canary(t, testsecrets.Session)
	if got, want := readLines(t, canaryFile), []string{previous, v}; !slices.Equal(got, want) {
		t.Fatalf("canary file lines = %q, want %q (previous content must be kept)", got, want)
	}
}

func TestCanary_NotRecordedWhenDisabled(t *testing.T) {
	for _, val := range []string{"", "0"} {
		t.Run("FACTO_CANARY="+val, func(t *testing.T) {
			canaryFile, _ := isolate(t, val)
			if v := testsecrets.Canary(t, testsecrets.Password); !canaryRe.MatchString(v) {
				t.Fatalf("Canary returned %q while disabled", v)
			}
			if _, err := os.Stat(canaryFile); !os.IsNotExist(err) {
				t.Fatalf("canary file written while FACTO_CANARY=%q (stat err = %v)", val, err)
			}
		})
	}
}

// fakeTB records failures instead of failing the real test. Fatal-like
// methods stop the calling goroutine like testing.T does.
type fakeTB struct {
	testing.TB
	mu     sync.Mutex
	failed bool
	msgs   []string
}

func (f *fakeTB) record(msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = true
	f.msgs = append(f.msgs, msg)
}

func (f *fakeTB) Helper()                        {}
func (f *fakeTB) Fail()                          { f.record("Fail") }
func (f *fakeTB) Error(_ ...any)                 { f.record("Error") }
func (f *fakeTB) Errorf(format string, _ ...any) { f.record(format) }
func (f *fakeTB) FailNow()                       { f.record("FailNow"); runtime.Goexit() }
func (f *fakeTB) Fatal(_ ...any)                 { f.record("Fatal"); runtime.Goexit() }
func (f *fakeTB) Fatalf(format string, _ ...any) { f.record(format); runtime.Goexit() }
func (f *fakeTB) Failed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.failed
}

// runFake calls fn with a fakeTB on its own goroutine (so Goexit is safe) and
// reports whether it failed.
func runFake(t *testing.T, fn func(tb testing.TB)) bool {
	t.Helper()
	ftb := &fakeTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(ftb)
	}()
	<-done
	return ftb.Failed()
}

func TestCanary_RejectsInvalidKind(t *testing.T) {
	canaryFile, _ := isolate(t, "1")

	for _, kind := range []testsecrets.Kind{"", "pass word", "token\nFACTO", "../x", "Token", "a/b"} {
		if !runFake(t, func(tb testing.TB) { testsecrets.Canary(tb, kind) }) {
			t.Errorf("Canary(%q) did not fail the test", kind)
		}
	}
	if _, err := os.Stat(canaryFile); !os.IsNotExist(err) {
		t.Fatalf("invalid kinds wrote to the canary file (stat err = %v)", err)
	}
}

func TestCanaryFile_Resolution(t *testing.T) {
	root := moduleRoot(t)
	abs := filepath.Join(t.TempDir(), "x", "canaries.txt")
	tests := []struct {
		name  string
		set   bool
		value string
		want  string
	}{
		{name: "unset", set: false, want: filepath.Join(root, ".cache", "canaries.txt")},
		{name: "empty", set: true, value: "", want: filepath.Join(root, ".cache", "canaries.txt")},
		{name: "absolute", set: true, value: abs, want: abs},
		{name: "absolute unclean", set: true, value: filepath.Dir(abs) + "/../x/./canaries.txt", want: abs},
		{name: "relative to module root", set: true, value: filepath.Join(".cache", "other.txt"), want: filepath.Join(root, ".cache", "other.txt")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CANARY_FILE", tt.value)
			if !tt.set {
				if err := os.Unsetenv("CANARY_FILE"); err != nil {
					t.Fatalf("Unsetenv: %v", err)
				}
			}
			got, err := testsecrets.CanaryFile()
			if err != nil {
				t.Fatalf("CanaryFile: %v", err)
			}
			if got != tt.want {
				t.Fatalf("CanaryFile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestArtifactRoot_Resolution(t *testing.T) {
	root := moduleRoot(t)
	abs := filepath.Join(t.TempDir(), "art")
	tests := []struct {
		name  string
		set   bool
		value string
		want  string
	}{
		{name: "unset", set: false, want: filepath.Join(root, ".cache", "test-artifacts")},
		{name: "empty", set: true, value: "", want: filepath.Join(root, ".cache", "test-artifacts")},
		{name: "absolute", set: true, value: abs, want: abs},
		{name: "relative to module root", set: true, value: "custom-art", want: filepath.Join(root, "custom-art")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ART_DIR", tt.value)
			if !tt.set {
				if err := os.Unsetenv("ART_DIR"); err != nil {
					t.Fatalf("Unsetenv: %v", err)
				}
			}
			got, err := testsecrets.ArtifactRoot()
			if err != nil {
				t.Fatalf("ArtifactRoot: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ArtifactRoot() = %q, want %q", got, tt.want)
			}
		})
	}
}

// within reports whether path is strictly inside root.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && filepath.IsLocal(rel)
}

func TestArtifactDir_UnderArtDir(t *testing.T) {
	_, artRoot := isolate(t, "0")

	dir := testsecrets.ArtifactDir(t)
	if !within(artRoot, dir) {
		t.Fatalf("ArtifactDir = %q, want strictly inside %q", dir, artRoot)
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		t.Fatalf("ArtifactDir %q is not a directory (err = %v)", dir, err)
	}
	if !strings.Contains(dir, "TestArtifactDir_UnderArtDir") {
		t.Fatalf("ArtifactDir %q does not identify the test", dir)
	}
	// Tests write their logs and reports there through fsx.
	writePrivate(t, filepath.Join(dir, "report.json"), []byte(`{"synthetic":true}`))
}

func TestArtifactDir_PerTestAndKept(t *testing.T) {
	_, artRoot := isolate(t, "0")

	var a, b string
	t.Run("first", func(t *testing.T) { a = testsecrets.ArtifactDir(t) })
	t.Run("second", func(t *testing.T) { b = testsecrets.ArtifactDir(t) })
	if a == b {
		t.Fatalf("two tests share ArtifactDir %q", a)
	}
	for _, d := range []string{a, b} {
		if !within(artRoot, d) {
			t.Fatalf("ArtifactDir = %q, want inside %q", d, artRoot)
		}
		// Kept after the subtest ended so that leakcheck can grep it.
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("ArtifactDir %q removed after its test: %v", d, err)
		}
	}
}

func TestArtifactDir_HostileTestNameStaysInside(t *testing.T) {
	_, artRoot := isolate(t, "0")
	outside := filepath.Dir(artRoot) // the temp "cache" dir

	for _, name := range []string{"../../../escape", "..", `..\..\escape`, "a/../../b", "/abs"} {
		t.Run(name, func(t *testing.T) {
			dir := testsecrets.ArtifactDir(t)
			if !within(artRoot, dir) {
				t.Fatalf("subtest %q: ArtifactDir = %q escapes %q", t.Name(), dir, artRoot)
			}
		})
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(artRoot) {
			t.Fatalf("ArtifactDir created %q next to the artifact root", e.Name())
		}
	}
}
