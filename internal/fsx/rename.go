package fsx

import (
	"errors"
	"fmt"
	"io/fs"
)

// Rename moves oldname to newname, both slash-separated and relative to the
// root, files and directories alike (used to swap a fully extracted staging
// tree into place). It never replaces: when newname already exists, whatever
// it is (even a dangling symlink), the error wraps fs.ErrExist and nothing
// changes. A missing oldname or parent of newname wraps fs.ErrNotExist;
// invalid names wrap ErrInvalidName. A final symlink at oldname is moved
// itself, never followed. Both names stay confined to the root.
//
// The no-replace check and the rename are two steps: a process of the same
// user can create newname in between, and the rename then replaces it if
// the OS allows (a file, or an empty directory). That process is inside the
// trust boundary (the user account).
func (r *Root) Rename(oldname, newname string) error {
	oldOS, err := cleanName(oldname)
	if err != nil {
		return err
	}
	newOS, err := cleanName(newname)
	if err != nil {
		return err
	}
	if _, err := r.root.Lstat(newOS); err == nil {
		return fmt.Errorf("fsx rename %q to %q: %w", oldname, newname, fs.ErrExist)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("fsx rename %q to %q: %w", oldname, newname, err)
	}
	if err := r.root.Rename(oldOS, newOS); err != nil {
		return fmt.Errorf("fsx rename %q to %q: %w", oldname, newname, err)
	}
	return nil
}
