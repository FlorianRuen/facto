//go:build unix

// Red-team attack tests for fsx (J0 task T30): hostile names through
// SafeName and JoinWithin, escapes through "..", absolute names and
// symlinks, permission downgrades under a zero umask, FIFOs, and racing
// WriteNew calls. A test passes when the attack is defeated.
package fsx_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/fsx"
)

var atkReserved = []string{
	"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
	"COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM\u00b9", "COM\u00b2", "COM\u00b3",
	"LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT\u00b9", "LPT\u00b2", "LPT\u00b3",
}

// TestAttack_FsxSafeNameHostileInputs checks SafeName's invariants on
// supplier-style hostile strings, and that its result always joins strictly
// inside a root.
func TestAttack_FsxSafeNameHostileInputs(t *testing.T) {
	t.Parallel()
	inputs := []string{
		"../../.ssh/id_rsa", "..", ".", "...", ". .", " ", "", "/", "\\", "a/b", "a\\b",
		"CON", "con", "CoN .pdf", "con.txt", "nul.tar.gz", "COM\u00b9", "lpt9.x.y", "CONIN$", "AUX:",
		"CON" + strings.Repeat(" ", 250) + "x", "a\x00b", "\x00", "\xff\xfe", "a\x7fb", "a\u0085b",
		"\u202egnp.exe", "a\u200db", "\ufeffx", "C:\\Windows\\win.ini", "\\\\server\\share\\x", "C:",
		"x::$DATA", "a<b>c|d?e*f\"g", strings.Repeat("a", 300), strings.Repeat("a", 300) + ".pdf",
		strings.Repeat("\u00e9", 300), strings.Repeat("\U0001F600", 100) + ".pdf", strings.Repeat(".", 300),
		strings.Repeat("../", 100), "%2e%2e%2f", "~", "$HOME", ".facto", "  .. ", "a.", "a ",
		strings.Repeat("a", 199) + "\u00e9", "x" + strings.Repeat(".", 199) + "pdf",
	}
	root := t.TempDir()
	for _, in := range inputs {
		out := fsx.SafeName(in)
		bad := func(why string) { t.Errorf("SafeName(%q) = %q: %s", in, out, why) }
		switch {
		case out == "" || out == "." || out == "..":
			bad("empty or dot name")
		case strings.ContainsAny(out, "/\\<>:\"|?*\x00"):
			bad("separator or forbidden character")
		case strings.Contains(out, ".."):
			bad("contains ..")
		case len(out) > fsx.MaxNameLen:
			bad("too long")
		case !utf8.ValidString(out):
			bad("invalid UTF-8")
		case strings.HasPrefix(out, ".") || strings.HasPrefix(out, " ") || strings.HasSuffix(out, ".") || strings.HasSuffix(out, " "):
			bad("leading or trailing dot or space")
		case fsx.SafeName(out) != out:
			bad("not idempotent")
		}
		for _, r := range out {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				bad("control or format character")
			}
		}
		stem, _, _ := strings.Cut(out, ".")
		for _, r := range atkReserved {
			if strings.EqualFold(strings.TrimRight(stem, " "), r) {
				bad("Windows reserved device name")
			}
		}
		if _, err := fsx.JoinWithin(root, out); err != nil {
			bad("JoinWithin refuses it: " + err.Error())
		}
	}
}

// TestAttack_FsxJoinWithinEscapes tries to leave the root lexically.
func TestAttack_FsxJoinWithinEscapes(t *testing.T) {
	t.Parallel()
	root := "/srv/out"
	for _, parts := range [][]string{
		{".."},
		{"../x"},
		{"a/../../x"},
		{"a", "..", ".."},
		{"/etc/passwd"},
		{"a", "/etc"},
		{"a\x00b"},
		{""},
		{"."},
		{"a/.."},
		{"./"},
		{"a", "../../../b"},
	} {
		if p, err := fsx.JoinWithin(root, parts...); err == nil {
			t.Errorf("JoinWithin(%q, %q) = %q, want an error", root, parts, p)
		}
	}
}

// atkRootWithOutside returns an open Root on base/root, the outside dir
// base/outside holding sentinel.txt, and symlinks in the root:
// "dlink" -> outside dir, "flink" -> outside file, "dangling" -> outside
// missing file.
func atkRootWithOutside(t *testing.T) (*fsx.Root, string) {
	t.Helper()
	base := t.TempDir()
	b, err := fsx.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	for _, d := range []string{"root", "outside"} {
		if err := b.MkdirPrivate(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.WriteAtomic(t.Context(), "outside/sentinel.txt", []byte("sentinel")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	for link, target := range map[string]string{
		"dlink": outside, "flink": filepath.Join(outside, "sentinel.txt"), "dangling": filepath.Join(outside, "created"),
		"rel": "../outside",
	} {
		if err := os.Symlink(target, filepath.Join(base, "root", link)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fsx.Open(filepath.Join(base, "root"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, outside
}

func atkOutsideUnchanged(t *testing.T, outside string) {
	t.Helper()
	des, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 1 || des[0].Name() != "sentinel.txt" {
		var names []string
		for _, d := range des {
			names = append(names, d.Name())
		}
		t.Errorf("outside dir changed: %q", names)
	}
	b, err := os.ReadFile(filepath.Clean(filepath.Join(outside, "sentinel.txt")))
	if err != nil || string(b) != "sentinel" {
		t.Errorf("sentinel changed: %q %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(outside, "sentinel.txt")); err == nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("sentinel mode changed to %v", fi.Mode().Perm())
	}
}

// TestAttack_FsxRootEscapesThroughNamesAndSymlinks runs every Root
// operation on escaping names and through symlinks leading outside.
func TestAttack_FsxRootEscapesThroughNamesAndSymlinks(t *testing.T) {
	t.Parallel()
	r, outside := atkRootWithOutside(t)
	ctx := t.Context()
	escaping := []string{
		"../outside/x", "../../x", "/tmp/x", "a/../../outside/x", "dlink/x", "dlink/sentinel.txt",
		"rel/x", "rel/sentinel.txt", "dlink/sub/x", "flink/x", "dangling/x",
		"..", ".", "", "a\x00b",
	}
	for _, n := range escaping {
		if err := r.WriteAtomic(ctx, n, []byte("attack")); err == nil {
			t.Errorf("WriteAtomic(%q) succeeded", n)
		}
		if err := r.WriteNew(ctx, n, strings.NewReader("attack")); err == nil {
			t.Errorf("WriteNew(%q) succeeded", n)
		}
		if err := r.MkdirPrivate(n); err == nil {
			t.Errorf("MkdirPrivate(%q) succeeded", n)
		}
		if err := r.AppendPrivate(n, []byte("attack")); err == nil {
			t.Errorf("AppendPrivate(%q) succeeded", n)
		}
		if err := r.Remove(n); err == nil {
			t.Errorf("Remove(%q) succeeded", n)
		}
		if f, err := r.OpenRegular(n); err == nil {
			_ = f.Close()
			t.Errorf("OpenRegular(%q) succeeded", n)
		}
		if d, err := r.OpenDir(n); err == nil {
			_ = d.Close()
			t.Errorf("OpenDir(%q) succeeded", n)
		}
	}
	// A final symlink to an outside file or a missing outside file: append
	// and open must refuse it, WriteNew must not create through it.
	for _, n := range []string{"flink", "dangling"} {
		if err := r.AppendPrivate(n, []byte("attack")); err == nil {
			t.Errorf("AppendPrivate(%q) followed a symlink out of the root", n)
		}
		if err := r.WriteNew(ctx, n, strings.NewReader("attack")); !errors.Is(err, fs.ErrExist) {
			t.Errorf("WriteNew(%q) = %v, want fs.ErrExist", n, err)
		}
		if f, err := r.OpenRegular(n); err == nil {
			_ = f.Close()
			t.Errorf("OpenRegular(%q) followed a symlink", n)
		}
	}
	// WriteAtomic over a symlink replaces the link itself, never its target.
	if err := r.WriteAtomic(ctx, "flink", []byte("replaced")); err != nil {
		t.Errorf("WriteAtomic over a symlink: %v", err)
	}
	atkOutsideUnchanged(t, outside)
}

// TestAttack_FsxPermissionsUnderZeroUmask forces umask 0 and broad
// pre-existing modes: fsx must never produce or accept group/world bits.
// Not parallel: the umask is process-wide.
func TestAttack_FsxPermissionsUnderZeroUmask(t *testing.T) {
	// Broad modes an attacker or a careless tool leaves behind.
	broadFile, readableFile, broadDir := fs.FileMode(0o666), fs.FileMode(0o644), fs.FileMode(0o777)
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := t.TempDir()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	ctx := t.Context()
	mustMode := func(name string, want fs.FileMode) {
		t.Helper()
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("lstat %s: %v", name, err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", name, fi.Mode().Perm(), want)
		}
	}
	if err := r.MkdirPrivate("a/b/c"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"a", "a/b", "a/b/c"} {
		mustMode(d, 0o700)
	}
	if err := r.WriteAtomic(ctx, "a/b/c/f", []byte("x")); err != nil {
		t.Fatal(err)
	}
	mustMode("a/b/c/f", 0o600)
	if err := r.WriteNew(ctx, "a/b/c/g", strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	mustMode("a/b/c/g", 0o600)
	if err := r.AppendPrivate("a/b/c/h", []byte("x")); err != nil {
		t.Fatal(err)
	}
	mustMode("a/b/c/h", 0o600)

	// Broad pre-existing modes: replaced or refused, never kept or widened.
	if err := os.Chmod(filepath.Join(dir, "a/b/c/f"), broadFile); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteAtomic(ctx, "a/b/c/f", []byte("y")); err != nil {
		t.Fatal(err)
	}
	mustMode("a/b/c/f", 0o600)
	if err := os.Chmod(filepath.Join(dir, "a/b/c/h"), readableFile); err != nil {
		t.Fatal(err)
	}
	if err := r.AppendPrivate("a/b/c/h", []byte("secret")); !errors.Is(err, fsx.ErrInsecurePerms) {
		t.Errorf("AppendPrivate on a 0644 file = %v, want ErrInsecurePerms", err)
	}
	if b, _ := os.ReadFile(filepath.Clean(filepath.Join(dir, "a/b/c/h"))); string(b) != "x" {
		t.Errorf("0644 file was appended to: %q", b)
	}
	if err := os.Chmod(filepath.Join(dir, "a/b/c"), broadDir); err != nil {
		t.Fatal(err)
	}
	if err := r.MkdirPrivate("a/b/c"); !errors.Is(err, fsx.ErrInsecurePerms) {
		t.Errorf("MkdirPrivate on a 0777 dir = %v, want ErrInsecurePerms", err)
	}
	if err := fsx.CheckPrivate(filepath.Join(dir, "a/b/c")); !errors.Is(err, fsx.ErrInsecurePerms) {
		t.Errorf("CheckPrivate on a 0777 dir = %v, want ErrInsecurePerms", err)
	}
}

// TestAttack_FsxFIFOsNeverBlock plants FIFOs without a reader where fsx
// appends, opens or creates.
func TestAttack_FsxFIFOsNeverBlock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, n := range []string{"append.log", "open.pdf", "new.pdf"} {
		if err := syscall.Mkfifo(filepath.Join(dir, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := r.AppendPrivate("append.log", []byte("x")); err == nil {
			t.Error("AppendPrivate wrote into a FIFO")
		}
		if f, err := r.OpenRegular("open.pdf"); !errors.Is(err, fsx.ErrNotRegular) {
			if f != nil {
				_ = f.Close()
			}
			t.Errorf("OpenRegular(FIFO) = %v, want ErrNotRegular", err)
		}
		if err := r.WriteNew(context.Background(), "new.pdf", strings.NewReader("x")); !errors.Is(err, fs.ErrExist) {
			t.Errorf("WriteNew over a FIFO = %v, want fs.ErrExist", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("an fsx call blocked on a FIFO")
	}
}

// TestAttack_FsxWriteNewRaceHasOneWinner races 32 WriteNew calls on one
// name: exactly one wins, its content is intact, no temp file remains.
func TestAttack_FsxWriteNewRaceHasOneWinner(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	const n = 32
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins []int
	)
	payload := func(i int) []byte { return bytes.Repeat([]byte{byte('A' + i%26)}, 64<<10) }
	for i := range n {
		wg.Go(func() {
			if err := r.WriteNew(t.Context(), "same.pdf", bytes.NewReader(payload(i))); err == nil {
				mu.Lock()
				wins = append(wins, i)
				mu.Unlock()
			} else if !errors.Is(err, fs.ErrExist) {
				t.Errorf("writer %d: %v", i, err)
			}
		})
	}
	wg.Wait()
	if len(wins) != 1 {
		t.Fatalf("%d winners, want 1", len(wins))
	}
	got, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "same.pdf")))
	if err != nil || !bytes.Equal(got, payload(wins[0])) {
		t.Errorf("published content is not the winner's (err %v)", err)
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 1 {
		t.Errorf("leftover entries: %d", len(des))
	}
}
