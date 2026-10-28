// Package store is the SQLite document index (spec, Normalization): one row per
// collected document version, keyed by (provider, provider id, version) and
// indexed by content hash. It implements normalize.Index.
//
// The database lives in a private state directory: the directory is 0700 and
// the database file 0600, both created through fsx before SQLite touches
// them. SQLite gives the files it creates next to the database (-wal, -shm,
// -journal) the database file's mode, so they are 0600 too. The driver,
// modernc.org/sqlite (ADR 0004), is hidden behind this package.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/fsx"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver (ADR 0004)
)

// FileName is the database file created inside the state directory.
const FileName = "index.db"

// sideSuffixes are the files SQLite may create next to the database.
var sideSuffixes = [...]string{"-wal", "-shm", "-journal"}

// busyTimeoutMS bounds how long a statement waits for another process holding
// the database lock before failing with SQLITE_BUSY.
const busyTimeoutMS = "5000"

var (
	// ErrDuplicate reports that (provider, provider id, version) is already
	// stored.
	ErrDuplicate = errors.New("store: duplicate document")
	// ErrInvalidDocument reports an Insert input that fails validation.
	ErrInvalidDocument = errors.New("store: invalid document")
	// ErrSchemaTooNew reports a database whose recorded schema version is
	// higher than the newest embedded migration: it was written by a newer
	// facto, and this binary must not read or write it.
	ErrSchemaTooNew = errors.New("store: database schema is newer than this binary")

	errClosed = errors.New("store: already closed")
)

// Store is the SQLite index. Safe for concurrent use. It implements
// normalize.Index.
type Store struct {
	db     *sql.DB
	clk    clock.Clock
	closed atomic.Bool
}

// Open creates dir (mode 0700, through fsx; its parent must exist) if it is
// missing, pre-creates dir/FileName 0600 through fsx before SQLite opens it,
// opens the database and runs Migrate. An existing dir or database file (or
// SQLite side file) with group/world bits is refused with an error wrapping
// fsx.ErrInsecurePerms and left unchanged; a database path that is a symlink
// or not a regular file is refused. A missing parent wraps fs.ErrNotExist.
func Open(ctx context.Context, dir string, clk clock.Clock) (*Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store open: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("store open: %w", err)
	}
	if err := prepareFiles(abs); err != nil {
		return nil, fmt.Errorf("store open: %w", err)
	}

	db, err := sql.Open("sqlite", dsn(filepath.Join(abs, FileName)))
	if err != nil {
		return nil, fmt.Errorf("store open: %w", err)
	}
	// One connection serializes every statement in this process: no
	// SQLITE_BUSY between our own goroutines, and the index is tiny.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, clk: clk}
	if err := s.Migrate(ctx); err != nil {
		_ = db.Close() // the migration error is the one worth reporting
		return nil, fmt.Errorf("store open: %w", err)
	}
	return s, nil
}

// prepareFiles creates the private state directory dir if needed, checks the
// database and its side files, and pre-creates the database file 0600.
func prepareFiles(dir string) error {
	parent, base := filepath.Dir(dir), filepath.Base(dir)
	if base == string(filepath.Separator) || base == "." || parent == dir {
		return fmt.Errorf("state dir %q: not a subdirectory", dir)
	}
	pr, err := fsx.Open(parent)
	if err != nil {
		return fmt.Errorf("state dir parent: %w", err)
	}
	defer func() { _ = pr.Close() }() // read-only handle, nothing to flush
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("state dir %q is a symlink", dir)
	}
	if err := pr.MkdirPrivate(base); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}

	for _, name := range []string{FileName, FileName + sideSuffixes[0], FileName + sideSuffixes[1], FileName + sideSuffixes[2]} {
		if err := checkExisting(filepath.Join(dir, name)); err != nil {
			return err
		}
	}

	dr, err := fsx.Open(dir)
	if err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	defer func() { _ = dr.Close() }() // read-only handle, nothing to flush
	// Appending nothing creates the file 0600 when missing and refuses an
	// existing file that is not regular or not private.
	if err := dr.AppendPrivate(FileName, nil); err != nil {
		return fmt.Errorf("database file: %w", err)
	}
	return nil
}

// checkExisting refuses p if it exists and is not a private regular file.
func checkExisting(p string) error {
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("check %s: %w", filepath.Base(p), err)
	case !fi.Mode().IsRegular():
		return fmt.Errorf("check %s: not a regular file (%v)", filepath.Base(p), fi.Mode().Type())
	}
	if err := fsx.CheckPrivate(p); err != nil {
		return fmt.Errorf("check %s: %w", filepath.Base(p), err)
	}
	return nil
}

// dsn builds a file: URI for path. mode=rw makes SQLite fail instead of
// creating the database itself if the pre-created file vanished.
func dsn(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows: file:///C:/...
	}
	q := url.Values{}
	q.Set("mode", "rw")
	q.Add("_pragma", "busy_timeout("+busyTimeoutMS+")")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Set("_txlock", "immediate")
	u := url.URL{Scheme: "file", Path: p, RawQuery: q.Encode()}
	return u.String()
}

// Close closes the database. Later calls, and every method called after it,
// return an error.
func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return errClosed
	}
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store close: %w", err)
	}
	return nil
}

// opErr wraps err for op, making sure a canceled or expired ctx is visible to
// errors.Is even when the driver reported the interruption its own way.
func opErr(ctx context.Context, op string, err error) error {
	if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
		return fmt.Errorf("store %s: %w (%w)", op, cerr, err)
	}
	return fmt.Errorf("store %s: %w", op, err)
}
