//go:build unix

package browser

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// checkModes applies the unix permission rules of CheckExecutable to the
// resolved binary and its ancestors.
func checkModes(resolved string, fi fs.FileInfo) error {
	m := fi.Mode()
	switch {
	case m.Perm()&0o100 == 0:
		return fmt.Errorf("%w: %s is not executable by its owner", ErrUnsafeExecutable, resolved)
	case m&(fs.ModeSetuid|fs.ModeSetgid) != 0:
		return fmt.Errorf("%w: %s is setuid or setgid", ErrUnsafeExecutable, resolved)
	case m.Perm()&0o022 != 0:
		return fmt.Errorf("%w: %s is group or world writable", ErrUnsafeExecutable, resolved)
	}
	parent := filepath.Dir(resolved)
	pm, err := dirMode(parent)
	if err != nil {
		return err
	}
	if pm.Perm()&0o022 != 0 {
		return fmt.Errorf("%w: directory %s is group or world writable", ErrUnsafeExecutable, parent)
	}
	for dir := filepath.Dir(parent); ; dir = filepath.Dir(dir) {
		dm, err := dirMode(dir)
		if err != nil {
			return err
		}
		if dm.Perm()&0o022 != 0 && dm&fs.ModeSticky == 0 {
			return fmt.Errorf("%w: ancestor %s is writable by others without the sticky bit", ErrUnsafeExecutable, dir)
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// dirMode returns the mode of dir, which comes from a fully resolved path
// and so is not a symlink.
func dirMode(dir string) (fs.FileMode, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnsafeExecutable, err)
	}
	return fi.Mode(), nil
}

// checkOwners requires the resolved binary and its parent directory to be
// owned by euid or root. Both paths come from a fully resolved path, so
// owner is never asked about a symlink.
func checkOwners(resolved string, euid int, owner func(string) (int, error)) error {
	if owner == nil {
		return fmt.Errorf("%w: no owner lookup", ErrUnsafeExecutable)
	}
	for _, p := range []string{resolved, filepath.Dir(resolved)} {
		uid, err := owner(p)
		if err != nil {
			return fmt.Errorf("%w: owner of %s: %w", ErrUnsafeExecutable, p, err)
		}
		if uid != euid && uid != 0 {
			return fmt.Errorf("%w: %s is owned by uid %d, neither the current user nor root", ErrUnsafeExecutable, p, uid)
		}
	}
	return nil
}

// statOwner returns the owner uid of path (already resolved).
func statOwner(path string) (int, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat %s: no owner information", path)
	}
	return int(st.Uid), nil
}
