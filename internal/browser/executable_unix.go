//go:build unix

package browser

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
