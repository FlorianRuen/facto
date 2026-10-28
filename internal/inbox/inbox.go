// Package inbox is the manual-import source (docs/spec.md "Manual import
// (inbox/)"): it lists the documents the user dropped in <output>/inbox and
// its provider subfolders, identifies each one (Factur-X, compliant name,
// subfolder, date in the name, or the interactive Prompter), and removes a
// file once the orchestrator has filed it.
//
// The inbox is untrusted input. Every access is confined to the inbox
// directory (fsx, os.Root), no symlink inside it is ever followed, FIFOs and
// devices are never opened, files are size-capped before being read, and a
// file is only read or removed if it is still the one that was scanned (same
// size, same SHA-256). Scan never modifies anything; Done is the only
// operation that removes a file, and it never removes a directory.
package inbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

// MaxFileSize is the default size cap of an inbox file (== facturx.MaxPDFSize).
const MaxFileSize = facturx.MaxPDFSize

// ErrChanged reports that the file at an Item's path is no longer the scanned
// one (other content, other size, or no longer a regular file).
var ErrChanged = errors.New("inbox: file changed since scan")

// doneRecheckHook runs in Done between the content verification and the
// identity recheck. No-op in production; internal tests replace it to rename
// another file over the item in that window.
var doneRecheckHook = func() {}

// Prompter is the consumer-side view of connector.Prompter used in
// interactive mode. file is the item path (slash-separated, relative to the
// inbox); guess holds what was inferred so far (Ext set, Kind set,
// Provider/Category/Date when known). ok=false means "skip this file".
type Prompter interface {
	AskDoc(ctx context.Context, file string, guess normalize.Doc) (normalize.Doc, bool, error)
}

// ProviderDefaults is the manual-provider configuration ("manual:" and
// connector entries of the config): Category for every document of that
// provider; Kind for documents identified only by subfolder (zero = Invoice).
type ProviderDefaults struct {
	Category string
	Kind     connector.DocKind
}

// Options configures an Inbox.
type Options struct {
	Prompter  Prompter                    // nil = non-interactive
	Providers map[string]ProviderDefaults // keyed by provider id (slug)
	MaxSize   int64                       // <= 0 means MaxFileSize
}

// Source names the highest-precedence source that identified an Item.
type Source string

// Identification sources, highest precedence first.
const (
	SourceFacturX   Source = "facturx"
	SourceName      Source = "name"
	SourceSubfolder Source = "subfolder"
	SourcePrompt    Source = "prompt"
)

// Reason says why a path is not (or not cleanly) an Item.
type Reason string

// Warning reasons. Every reason but ReasonInvalidFacturX means the path is
// not an Item and stays in the inbox untouched.
const (
	ReasonUnidentified     Reason = "unidentified"      // no provider+date; file stays
	ReasonSkipped          Reason = "skipped"           // prompter answered ok=false; file stays
	ReasonTooLarge         Reason = "too-large"         // > MaxSize; file stays, not read
	ReasonNotRegular       Reason = "not-regular"       // symlink (file or dir), FIFO, device…; never followed or opened
	ReasonInvalidSubfolder Reason = "invalid-subfolder" // subfolder name refused; its files stay
	ReasonNested           Reason = "nested"            // directory below a provider subfolder; not descended
	ReasonInvalidFacturX   Reason = "invalid-facturx"   // Factur-X present but refused (unsafe XML…); other sources used
)

// Warning carries no file content and no error text, only a path and a reason.
type Warning struct {
	Path   string // slash-separated, relative to the inbox
	Reason Reason
}

// Item is one identified inbox file.
type Item struct {
	Path   string // slash-separated, relative to the inbox ("impots/avis.pdf")
	Size   int64
	SHA256 [32]byte      // of the scanned content
	Doc    normalize.Doc // inferred; Version always 0 (dedup decides)
	Source Source
}

// Result is the outcome of a Scan. A path that is not an Item gets the
// reason it stays (unidentified, skipped, too-large…), never
// ReasonInvalidFacturX, which is only reported alongside an Item.
type Result struct {
	Items    []Item    // sorted by Path
	Warnings []Warning // sorted by Path, at most one per path
}

// Inbox reads one inbox directory. It is safe for concurrent use, but Scan
// may call the Prompter, which usually is not.
type Inbox struct {
	root      *fsx.Root
	prompter  Prompter
	providers map[string]ProviderDefaults
	maxSize   int64
}

// New opens the existing inbox directory dir (os.Root confinement, as fsx).
// It does not create it: a missing dir wraps fs.ErrNotExist. dir itself may
// be a symlink (e.g. into a synced folder); links inside it are refused.
func New(dir string, opts Options) (*Inbox, error) {
	root, err := fsx.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("inbox: %w", err)
	}
	maxSize := opts.MaxSize
	if maxSize <= 0 {
		maxSize = MaxFileSize
	}
	return &Inbox{
		root:      root,
		prompter:  opts.Prompter,
		providers: maps.Clone(opts.Providers),
		maxSize:   maxSize,
	}, nil
}

// Close releases the inbox directory; later calls fail.
func (ib *Inbox) Close() error {
	if err := ib.root.Close(); err != nil {
		return fmt.Errorf("inbox: %w", err)
	}
	return nil
}

// Open returns the item's content, read through the confined root without
// following symlinks. The whole file is read and checked against the scanned
// size and SHA-256 before Open returns, so the returned reader yields exactly
// the scanned bytes; a file that is no longer the scanned one fails with an
// error wrapping ErrChanged. Paths that are not local (absolute, "..") are
// refused.
func (ib *Inbox) Open(ctx context.Context, it Item) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("inbox open: %w", err)
	}
	var data []byte
	err := ib.withItem(it, func(dir *fsx.Root, name string) error {
		f, _, err := openVerified(dir, name)
		if err != nil {
			return err
		}
		data, err = ib.readVerified(f, it)
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("close: %w", cerr)
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("inbox open %q: %w", it.Path, err)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Done removes the item's file after successful filing, only if it is still
// the scanned regular file (else ErrChanged, nothing removed). Missing: wraps
// fs.ErrNotExist. Never removes a subfolder. Paths that are not local are
// refused.
//
// After the content check, Done re-Lstats name and compares it with the
// verified file (os.SameFile), so a file renamed over the item after the read
// is kept (ErrChanged). A window remains between that recheck and the
// Remove: a rename landing exactly there is removed in place of the verified
// file. Closing it needs a remove-if-same-inode primitive that os.Root does
// not offer; the window is a few syscalls wide and needs a concurrent writer
// in the inbox at that instant.
func (ib *Inbox) Done(ctx context.Context, it Item) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("inbox done: %w", err)
	}
	err := ib.withItem(it, func(dir *fsx.Root, name string) error {
		f, fi, err := openVerified(dir, name)
		if err != nil {
			return err
		}
		_, err = ib.readVerified(f, it)
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("close: %w", cerr)
		}
		if err != nil {
			return err
		}
		// The entry at name must still be the file just verified: a rename
		// over it after the read would otherwise lose the newer drop.
		doneRecheckHook()
		li, err := dir.Lstat(name)
		if err != nil {
			return fmt.Errorf("recheck: %w", err)
		}
		if !li.Mode().IsRegular() || !os.SameFile(fi, li) {
			return fmt.Errorf("replaced after verification: %w", ErrChanged)
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("before remove: %w", err)
		}
		if err := dir.Remove(name); err != nil {
			return fmt.Errorf("remove: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("inbox done %q: %w", it.Path, err)
	}
	return nil
}

// withItem validates it.Path and calls fn with the directory holding the
// file (the inbox root or a provider subfolder opened without following a
// symlink) and the file's base name.
func (ib *Inbox) withItem(it Item, fn func(dir *fsx.Root, name string) error) (err error) {
	sub, name, err := splitItemPath(it.Path)
	if err != nil {
		return err
	}
	if sub == "" {
		return fn(ib.root, name)
	}
	dir, err := ib.root.OpenDir(sub)
	if errors.Is(err, fsx.ErrNotDir) {
		return fmt.Errorf("%w: %w", ErrChanged, err)
	}
	if err != nil {
		return fmt.Errorf("open subfolder: %w", err)
	}
	defer func() {
		if cerr := dir.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close subfolder: %w", cerr))
		}
	}()
	return fn(dir, name)
}

// splitItemPath splits a slash-separated item path into an optional
// subfolder and a base name. Only the shapes Scan produces are accepted: one
// or two visible, local components.
func splitItemPath(p string) (sub, name string, err error) {
	invalid := fmt.Errorf("item path %q: %w", p, fsx.ErrInvalidName)
	if p == "." || strings.ContainsRune(p, 0) || !fs.ValidPath(p) {
		return "", "", invalid
	}
	parts := strings.Split(p, "/")
	if len(parts) > 2 {
		return "", "", invalid
	}
	for _, part := range parts {
		// On Windows '\' is a separator too: one component must stay one.
		if hidden(part) || !filepath.IsLocal(part) || strings.ContainsRune(part, filepath.Separator) {
			return "", "", invalid
		}
	}
	if len(parts) == 1 {
		return "", parts[0], nil
	}
	return parts[0], parts[1], nil
}

// openVerified opens name in dir if it is a regular file, mapping "not a
// regular file any more" to ErrChanged. It also returns the opened file's
// info, for identity checks.
func openVerified(dir *fsx.Root, name string) (*os.File, fs.FileInfo, error) {
	f, err := dir.OpenRegular(name)
	if errors.Is(err, fsx.ErrNotRegular) {
		return nil, nil, fmt.Errorf("%w: %w", ErrChanged, err)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("open: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close() // read-only; the stat error is the one reported
		return nil, nil, fmt.Errorf("stat: %w", err)
	}
	return f, fi, nil
}

// readVerified reads f whole and checks it is the scanned content of it.
func (ib *Inbox) readVerified(f *os.File, it Item) ([]byte, error) {
	if it.Size < 0 || it.Size > ib.maxSize {
		return nil, fmt.Errorf("size %d out of range: %w", it.Size, ErrChanged)
	}
	data, err := io.ReadAll(io.LimitReader(f, it.Size+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(data)) != it.Size || sha256.Sum256(data) != it.SHA256 {
		return nil, ErrChanged
	}
	return data, nil
}

// hidden reports whether an entry name is hidden (".git", ".DS_Store", fsx
// temp files…). Hidden entries are ignored silently.
func hidden(name string) bool { return strings.HasPrefix(name, ".") }
