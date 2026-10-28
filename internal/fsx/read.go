package fsx

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
)

var (
	// ErrNotRegular reports that OpenRegular found something other than a
	// regular file at name: a symlink (even one pointing to a regular file
	// inside the root), a directory, a FIFO, a device, a socket…
	ErrNotRegular = errors.New("fsx: not a regular file")
	// ErrNotDir reports that OpenDir found something other than a directory
	// at name, a symlink to a directory included.
	ErrNotDir = errors.New("fsx: not a directory")
)

// ReadDir lists the root directory itself, sorted by name. Entry types come
// from the directory listing without following anything: a symlink is
// reported as a symlink (fs.ModeSymlink), whatever it points to.
func (r *Root) ReadDir() ([]fs.DirEntry, error) {
	d, err := r.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("fsx read dir: %w", err)
	}
	des, err := d.ReadDir(-1)
	cerr := d.Close()
	if err != nil {
		return nil, fmt.Errorf("fsx read dir: %w", err)
	}
	if cerr != nil {
		return nil, fmt.Errorf("fsx read dir: close: %w", cerr)
	}
	slices.SortFunc(des, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return des, nil
}

// OpenDir opens the existing directory name as a new Root confined to it.
// Unlike os.Root, it refuses a symlink as the final component, even one
// pointing to a directory inside r (ErrNotDir): the directory is opened, then
// checked to be the very entry Lstat reports at name, so a swap between the
// two steps is detected. Intermediate components follow Lstat's rules. A
// missing name wraps fs.ErrNotExist. The caller closes the returned Root.
func (r *Root) OpenDir(name string) (*Root, error) {
	osName, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	li, err := r.root.Lstat(osName)
	if err != nil {
		return nil, fmt.Errorf("fsx open dir %q: %w", name, err)
	}
	if !li.IsDir() {
		return nil, fmt.Errorf("fsx open dir %q: mode %v: %w", name, li.Mode().Type(), ErrNotDir)
	}
	sub, err := r.root.OpenRoot(osName)
	if err != nil {
		return nil, fmt.Errorf("fsx open dir %q: %w", name, err)
	}
	fi, err := sub.Stat(".")
	if err == nil && !os.SameFile(li, fi) {
		err = fmt.Errorf("replaced while opening: %w", ErrNotDir)
	}
	if err != nil {
		_ = sub.Close() // the stat or identity error is the one reported
		return nil, fmt.Errorf("fsx open dir %q: %w", name, err)
	}
	return &Root{root: sub}, nil
}

// OpenRegular opens name read-only if, and only if, it is a regular file.
// Anything else (symlink, directory, FIFO, device, socket) is refused with
// ErrNotRegular before being opened, so a symlink is never followed and a
// FIFO never blocks; the open itself is non-blocking and the opened file is
// then checked to be the very regular file Lstat reported, so a swap between
// the two steps is refused too. A missing name wraps fs.ErrNotExist. The
// caller closes the file.
func (r *Root) OpenRegular(name string) (*os.File, error) {
	osName, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	li, err := r.root.Lstat(osName)
	if err != nil {
		return nil, fmt.Errorf("fsx open %q: %w", name, err)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("fsx open %q: mode %v: %w", name, li.Mode().Type(), ErrNotRegular)
	}
	f, err := r.root.OpenFile(osName, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, fmt.Errorf("fsx open %q: %w", name, err)
	}
	fi, err := f.Stat()
	if err == nil && (!fi.Mode().IsRegular() || !os.SameFile(li, fi)) {
		err = fmt.Errorf("replaced while opening: %w", ErrNotRegular)
	}
	if err != nil {
		_ = f.Close() // read-only; the stat or identity error is the one reported
		return nil, fmt.Errorf("fsx open %q: %w", name, err)
	}
	return f, nil
}
