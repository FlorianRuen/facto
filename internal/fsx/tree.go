package fsx

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// mkdirTempAttempts bounds MkdirTempPrivate's retries on a name collision.
// With 130 random bits per name a collision means something is wrong.
const mkdirTempAttempts = 10000

// removeTreeHook runs between the Lstat and the removal in RemoveTree. No-op
// in production; internal tests replace it to swap the entry in that window.
var removeTreeHook = func() {}

// MkdirTempPrivate creates a new directory in parent, like os.MkdirTemp
// (pattern: the last "*" is replaced by a random string, otherwise the
// random string is appended), with mode exactly 0700 whatever the umask, and
// returns its path (filepath.Join(parent, base)). Concurrent calls never
// return the same directory. parent must exist (fs.ErrNotExist), be a
// directory (ErrNotDir) and be private (ErrInsecurePerms, unix only); nothing
// is created otherwise. A pattern that is empty after removing "*" is
// allowed; a pattern holding a path separator ('/' everywhere, also '\\' on
// Windows), a ':' on Windows, or a NUL wraps ErrInvalidName.
func MkdirTempPrivate(parent, pattern string) (dir string, err error) {
	// On Windows ':' would make a drive-relative name or an alternate data
	// stream, so it is refused there too.
	if strings.ContainsRune(pattern, 0) || strings.ContainsFunc(pattern, isSeparator) ||
		(runtime.GOOS == "windows" && strings.ContainsRune(pattern, ':')) {
		return "", fmt.Errorf("fsx mkdir temp: pattern %q: %w", pattern, ErrInvalidName)
	}
	prefix, suffix := pattern, ""
	if i := strings.LastIndexByte(pattern, '*'); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}

	root, err := openDirRoot(parent)
	if err != nil {
		return "", fmt.Errorf("fsx mkdir temp in %q: %w", parent, err)
	}
	defer func() {
		if cerr := root.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("fsx mkdir temp in %q: close: %w", parent, cerr))
		}
	}()
	// Checked on the opened directory itself, not on the path, so a swap
	// of parent after the check cannot redirect the creation.
	fi, err := root.Stat(".")
	if err != nil {
		return "", fmt.Errorf("fsx mkdir temp in %q: %w", parent, err)
	}
	if insecure(fi.Mode()) {
		return "", fmt.Errorf("fsx mkdir temp in %q: mode %#o: %w", parent, fi.Mode().Perm(), ErrInsecurePerms)
	}

	for range mkdirTempAttempts {
		base := prefix + rand.Text() + suffix
		err := root.Mkdir(base, dirPerm)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("fsx mkdir temp in %q: %w", parent, err)
		}
		// The umask may have narrowed the mode; force exactly 0700.
		if err := root.Chmod(base, dirPerm); err != nil {
			return "", errors.Join(
				fmt.Errorf("fsx mkdir temp in %q: chmod: %w", parent, err),
				root.Remove(base),
			)
		}
		return filepath.Join(parent, base), nil
	}
	return "", fmt.Errorf("fsx mkdir temp in %q: too many collisions: %w", parent, fs.ErrExist)
}

// openDirRoot opens dir as an os.Root. A dir that exists but is not a
// directory wraps ErrNotDir; a missing one wraps fs.ErrNotExist.
func openDirRoot(dir string) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err == nil {
		return root, nil
	}
	// Diagnostic only: this Stat picks the error to report, nothing is
	// created or opened on the strength of it.
	if fi, serr := os.Stat(dir); serr == nil && !fi.IsDir() {
		return nil, fmt.Errorf("mode %v: %w", fi.Mode().Type(), ErrNotDir)
	}
	return nil, fmt.Errorf("open: %w", err)
}

// RemoveTree deletes the directory parent/name and everything below it,
// through os.Root opened on parent: symlinks found in the tree are removed,
// never followed, so nothing outside parent/name is touched; FIFOs are
// unlinked, never opened. name is one path component: empty, ".", "..",
// absolute, or holding a separator ('/' everywhere, also '\\' and a volume on
// Windows) or a NUL wraps ErrInvalidName before touching the disk. When
// parent/name is not a real directory (regular file, symlink to anything) the
// error wraps ErrNotDir and nothing is removed. A missing parent or
// parent/name wraps fs.ErrNotExist.
//
// Race: if parent/name is swapped for a symlink between the check and the
// removal, os.Root.RemoveAll unlinks that symlink (unlinkat succeeds on it)
// and never follows it: its target survives. Inside the tree, directories
// are opened with O_NOFOLLOW|O_DIRECTORY relative to their parent's
// descriptor, so swaps below parent/name cannot escape either.
func RemoveTree(parent, name string) (err error) {
	if err := checkComponent(name); err != nil {
		return err
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return fmt.Errorf("fsx remove tree %q: %w", name, err)
	}
	defer func() {
		if cerr := root.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("fsx remove tree %q: close: %w", name, cerr))
		}
	}()
	fi, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("fsx remove tree %q: %w", name, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("fsx remove tree %q: mode %v: %w", name, fi.Mode().Type(), ErrNotDir)
	}
	removeTreeHook()
	if err := root.RemoveAll(name); err != nil {
		return fmt.Errorf("fsx remove tree %q: %w", name, err)
	}
	return nil
}

// checkComponent accepts exactly one local path component.
func checkComponent(name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsRune(name, 0) || strings.ContainsFunc(name, isSeparator) ||
		filepath.VolumeName(name) != "" || !filepath.IsLocal(name) {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return nil
}

// isSeparator reports a path separator of the running OS ('/' everywhere,
// also '\\' on Windows).
func isSeparator(c rune) bool { return c == '/' || c == filepath.Separator }
