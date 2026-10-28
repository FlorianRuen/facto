// Package fsx is the only way facto writes files. Every operation is confined
// to a directory through os.Root (neither ".." nor symlinks can reach outside
// it), files are created 0600, directories 0700, and whole-file writes are
// atomic (temp file, fsync, rename; or hard link for WriteNew, which never
// replaces). It also offers confined read access that never follows a final
// symlink and never blocks on a FIFO (ReadDir, OpenDir, OpenRegular), for
// directories facto reads but does not own, such as inbox/.
package fsx

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	filePerm = 0o600
	dirPerm  = 0o700
	// tempPrefix marks in-flight WriteAtomic temp files. The random suffix
	// (crypto/rand) makes concurrent writers on the same name independent.
	tempPrefix = ".fsx-tmp-"
	// copyBufSize is the WriteAtomicFrom read size.
	copyBufSize = 32 << 10
)

var (
	// ErrInvalidName reports a name that is empty, ".", absolute, or escapes
	// the root lexically.
	ErrInvalidName = errors.New("fsx: invalid name")
	// ErrInsecurePerms reports a file or directory with group or world
	// permission bits.
	ErrInsecurePerms = errors.New("fsx: insecure permissions")
	// ErrNotDurable reports that WriteAtomic renamed the new content into
	// place but could not fsync the parent directory: name already holds the
	// new data, which may not survive a crash.
	ErrNotDurable = errors.New("fsx: written but parent directory not synced")
	// ErrLinkUnsupported reports that the filesystem holding the target
	// directory refused to create a hard link (WriteNew needs one): FAT,
	// exFAT, some network or FUSE mounts.
	ErrLinkUnsupported = errors.New("fsx: filesystem does not support hard links")
)

// linkFunc is the hard-link primitive used by WriteNew and ProbeLink:
// (*os.Root).Link in production, replaced by internal tests only.
var linkFunc = (*os.Root).Link

// Root confines every operation to one directory, using os.Root, so that
// neither ".." nor symlinks can reach outside it. Safe for concurrent use.
type Root struct {
	root *os.Root
}

// Open opens an existing directory as a Root. It does not create it and does
// not check its permissions (use CheckPrivate). A missing dir wraps
// fs.ErrNotExist.
func Open(dir string) (*Root, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("fsx open root: %w", err)
	}
	return &Root{root: r}, nil
}

// Close releases the root. Later calls fail with an error wrapping
// os.ErrClosed.
func (r *Root) Close() error {
	if err := r.root.Close(); err != nil {
		return fmt.Errorf("fsx close root: %w", err)
	}
	return nil
}

// cleanName validates a slash-separated name relative to the root and returns
// it in OS form. It rejects empty, ".", absolute and lexically escaping names,
// and NUL bytes, before anything touches the disk.
func cleanName(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) || path.IsAbs(name) {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	clean := path.Clean(name)
	osName := filepath.FromSlash(clean)
	if clean == "." || !filepath.IsLocal(osName) {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return osName, nil
}

// WriteAtomic writes data to name (slash-separated, relative to the root):
// temp file in the same directory, created 0600, write, fsync, close, rename.
// The final file is 0600 even if it replaced a broader file. On any error
// before the rename the previous content of name is untouched and no temp file
// is left behind. If the rename succeeded but fsyncing the parent directory
// failed, the error wraps ErrNotDurable: name already holds the new content.
// The parent directory must exist: otherwise the error wraps fs.ErrNotExist.
func (r *Root) WriteAtomic(ctx context.Context, name string, data []byte) error {
	return r.writeAtomic(ctx, name, func(w io.Writer) error {
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		return nil
	}, r.rename)
}

// WriteAtomicFrom is WriteAtomic streaming from src (used for downloads). An
// error from the reader is wrapped (errors.Is works on it). The context is
// checked between reads.
func (r *Root) WriteAtomicFrom(ctx context.Context, name string, src io.Reader) error {
	return r.writeAtomic(ctx, name, func(w io.Writer) error {
		return copyCtx(ctx, w, src)
	}, r.rename)
}

// WriteNew is WriteAtomicFrom that never replaces anything: the fsynced temp
// file is published under name with a hard link (os.Root.Link), which fails
// when name already exists, whatever it is (regular file, directory, symlink,
// even dangling, FIFO), then the temp file is removed. Of several concurrent
// WriteNew calls on the same name exactly one succeeds. name is never visible
// before its content is complete. When something is already at name the
// error wraps fs.ErrExist and that entry is left untouched; on any error no
// temp file is left behind and name is not created. If fsyncing the parent
// directory failed after the link, the error wraps ErrNotDurable: name already
// holds the new content. The parent directory must exist (fs.ErrNotExist
// otherwise). The filesystem must support hard links: any other link failure
// wraps ErrLinkUnsupported (see ProbeLink to check at startup).
func (r *Root) WriteNew(ctx context.Context, name string, src io.Reader) error {
	osName, err := cleanName(name)
	if err != nil {
		return err
	}
	// Fail fast before streaming a whole download for nothing; the link
	// below is what actually enforces no-replace.
	if _, err := r.root.Lstat(osName); err == nil {
		return fmt.Errorf("fsx write new %q: %w", name, fs.ErrExist)
	}
	return r.writeAtomic(ctx, name, func(w io.Writer) error {
		return copyCtx(ctx, w, src)
	}, r.link)
}

// link publishes tmp as osName without replacing anything, then removes tmp.
// A link error other than fs.ErrExist means the filesystem cannot hard-link:
// it wraps ErrLinkUnsupported and names the target directory.
func (r *Root) link(tmp, osName string) error {
	if err := linkFunc(r.root, tmp, osName); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("link: %w", err)
		}
		dir := filepath.ToSlash(filepath.Dir(osName))
		return fmt.Errorf("link in %q: %w: %w", dir, ErrLinkUnsupported, err)
	}
	if err := r.root.Remove(tmp); err != nil {
		return fmt.Errorf("linked but remove temp: %w", err)
	}
	return nil
}

// ProbeLink checks that the root directory supports hard links, which
// WriteNew needs: it creates a 0600 temp file in the root, hard-links it to a
// second temp name, then removes both. On success the directory is left as
// it was. When the link fails the error wraps ErrLinkUnsupported and names
// the root directory; no temp file is left behind.
func (r *Root) ProbeLink(ctx context.Context) (err error) {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fsx probe link: %w", err)
	}
	src := tempPrefix + rand.Text()
	dst := tempPrefix + rand.Text()
	f, err := r.root.OpenFile(src, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return fmt.Errorf("fsx probe link in %q: create temp: %w", r.root.Name(), err)
	}
	defer func() {
		for _, n := range []string{src, dst} {
			if rmErr := r.root.Remove(n); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("fsx probe link: remove temp: %w", rmErr))
			}
		}
	}()
	if err := f.Close(); err != nil {
		return fmt.Errorf("fsx probe link in %q: close temp: %w", r.root.Name(), err)
	}
	if err := linkFunc(r.root, src, dst); err != nil {
		return fmt.Errorf("fsx probe link in %q: %w: %w", r.root.Name(), ErrLinkUnsupported, err)
	}
	return nil
}

// rename publishes tmp as osName, replacing whatever was there.
func (r *Root) rename(tmp, osName string) error {
	if err := r.root.Rename(tmp, osName); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// copyCtx copies src to w, checking ctx before every read.
func copyCtx(ctx context.Context, w io.Writer, src io.Reader) error {
	buf := make([]byte, copyBufSize)
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("copy: %w", err)
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}
		if errors.Is(rerr, io.EOF) {
			return nil
		}
		if rerr != nil {
			return fmt.Errorf("read: %w", rerr)
		}
	}
}

// writeAtomic writes a temp file next to name with fill, fsyncs it, then
// hands it to publish (rename or link) and fsyncs the parent directory.
func (r *Root) writeAtomic(ctx context.Context, name string, fill func(io.Writer) error, publish func(tmp, osName string) error) (err error) {
	osName, err := cleanName(name)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fsx write %q: %w", name, err)
	}

	tmp := filepath.Join(filepath.Dir(osName), tempPrefix+rand.Text())
	f, err := r.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return fmt.Errorf("fsx write %q: create temp: %w", name, err)
	}
	closed := false
	defer func() {
		if err == nil {
			return
		}
		if !closed {
			_ = f.Close() // already failing; the write error is the one reported
		}
		if rmErr := r.root.Remove(tmp); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temp: %w", rmErr))
		}
	}()

	// The umask may have narrowed the mode; force exactly 0600.
	if err := f.Chmod(filePerm); err != nil {
		return fmt.Errorf("fsx write %q: chmod temp: %w", name, err)
	}
	if err := fill(f); err != nil {
		return fmt.Errorf("fsx write %q: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsx write %q: sync: %w", name, err)
	}
	closed = true
	if err := f.Close(); err != nil {
		return fmt.Errorf("fsx write %q: close: %w", name, err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("fsx write %q: %w", name, err)
	}
	if err := publish(tmp, osName); err != nil {
		return fmt.Errorf("fsx write %q: %w", name, err)
	}
	if err := syncDir(r.root, filepath.Dir(osName)); err != nil {
		return fmt.Errorf("fsx write %q: %w: %w", name, ErrNotDurable, err)
	}
	return nil
}

// MkdirPrivate creates name and missing parents with mode 0700. It is
// idempotent on an existing private directory, fails with ErrInsecurePerms if
// the existing directory has group/world bits, and fails if name (or a parent)
// is not a directory. Only the final component's permissions are checked:
// existing parents are used as they are (they are inside the root, whose own
// permissions CheckPrivate verifies).
func (r *Root) MkdirPrivate(name string) error {
	osName, err := cleanName(name)
	if err != nil {
		return err
	}
	parts := strings.Split(osName, string(filepath.Separator))
	for i := range parts {
		p := filepath.Join(parts[:i+1]...)
		err := r.root.Mkdir(p, dirPerm)
		switch {
		case err == nil:
			// The umask may have narrowed the mode; force exactly 0700.
			if err := r.root.Chmod(p, dirPerm); err != nil {
				return fmt.Errorf("fsx mkdir %q: chmod: %w", name, err)
			}
		case errors.Is(err, fs.ErrExist):
			fi, serr := r.root.Stat(p)
			if serr != nil {
				return fmt.Errorf("fsx mkdir %q: %w", name, serr)
			}
			if !fi.IsDir() {
				return fmt.Errorf("fsx mkdir %q: %s is not a directory", name, filepath.ToSlash(p))
			}
			if i == len(parts)-1 && insecure(fi.Mode()) {
				return fmt.Errorf("fsx mkdir %q: mode %#o: %w", name, fi.Mode().Perm(), ErrInsecurePerms)
			}
		default:
			return fmt.Errorf("fsx mkdir %q: %w", name, err)
		}
	}
	return nil
}

// AppendPrivate appends data to name, creating it 0600 if missing. It refuses
// (ErrInsecurePerms) to append to an existing file with group/world bits and
// leaves it unchanged. A missing parent wraps fs.ErrNotExist.
func (r *Root) AppendPrivate(name string, data []byte) (err error) {
	osName, err := cleanName(name)
	if err != nil {
		return err
	}
	f, err := r.root.OpenFile(osName, os.O_WRONLY|os.O_APPEND|os.O_CREATE|nonBlock, filePerm)
	if err != nil {
		return fmt.Errorf("fsx append %q: %w", name, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("fsx append %q: close: %w", name, cerr))
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("fsx append %q: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("fsx append %q: not a regular file", name)
	}
	if insecure(fi.Mode()) {
		return fmt.Errorf("fsx append %q: mode %#o: %w", name, fi.Mode().Perm(), ErrInsecurePerms)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("fsx append %q: %w", name, err)
	}
	return nil
}

// Remove removes a file or an empty directory. A missing name wraps
// fs.ErrNotExist.
func (r *Root) Remove(name string) error {
	osName, err := cleanName(name)
	if err != nil {
		return err
	}
	if err := r.root.Remove(osName); err != nil {
		return fmt.Errorf("fsx remove %q: %w", name, err)
	}
	return nil
}

// Lstat describes name without following a final symlink; intermediate
// symlinks are followed only while they stay inside the root. A missing name
// wraps fs.ErrNotExist.
func (r *Root) Lstat(name string) (fs.FileInfo, error) {
	osName, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	fi, err := r.root.Lstat(osName)
	if err != nil {
		return nil, fmt.Errorf("fsx lstat %q: %w", name, err)
	}
	return fi, nil
}

// CheckPrivate reports ErrInsecurePerms when path (file or directory, symlinks
// followed) has any group or world permission bit. A missing path wraps
// fs.ErrNotExist.
func CheckPrivate(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("fsx check private: %w", err)
	}
	if insecure(fi.Mode()) {
		return fmt.Errorf("fsx check private %q: mode %#o: %w", p, fi.Mode().Perm(), ErrInsecurePerms)
	}
	return nil
}
