package inbox

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

// Scan lists the inbox and its direct subfolders (one level), never
// following a symlink and never opening a non-regular file. Hidden entries
// (name starting with '.') are ignored silently. A subfolder is refused
// (ReasonInvalidSubfolder) when fsx.SafeName(name) != name or
// normalize.Slug(name) == ""; otherwise its provider id is Slug(name).
//
// Each regular file under the size cap is read once (size and SHA-256 kept
// in the Item) and identified field by field, in precedence order:
//  1. Factur-X (facturx.Extract): Provider = Slug(SellerName), Date =
//     IssueDate, AmountCents/Currency = GrandTotal, Ref = Slug(Number),
//     Kind = Invoice. A missing attachment or an unreadable PDF is silent; a
//     refused attachment adds ReasonInvalidFacturX and the other sources are
//     used.
//  2. a compliant name (normalize.ParseName of the base name).
//  3. the subfolder: Provider when still empty, Kind from ProviderDefaults.
//  4. a single ISO date (YYYY-MM-DD, valid calendar date, not adjacent to
//     other digits) in the base name, when Date is still empty; two different
//     dates are ambiguous and give no date. Never mtime or "today".
//
// Kind defaults to Invoice, Ext is the lowercased extension of the file,
// Category is Providers[Provider].Category ("" when unknown) and Version is
// 0. A file is identified when it has a Date and a Provider, or when its name
// is compliant. Otherwise it gets ReasonUnidentified when non-interactive;
// interactive mode asks the Prompter (see Options), and only for such files.
//
// A Prompter error or ctx cancellation aborts Scan with an error wrapping it.
// Unexpected I/O errors abort Scan too; an entry that vanishes during the
// scan is skipped. Scan never modifies, moves or removes anything.
func (ib *Inbox) Scan(ctx context.Context) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("inbox scan: %w", err)
	}
	des, err := ib.root.ReadDir()
	if err != nil {
		return Result{}, fmt.Errorf("inbox scan: %w", err)
	}
	s := &scanner{ib: ib}
	for _, de := range des {
		name := de.Name()
		if hidden(name) {
			continue
		}
		var err error
		switch entryKind(de) {
		case kindDir:
			err = s.subfolder(ctx, name)
		case kindFile:
			err = s.file(ctx, ib.root, de, "", name)
		case kindOther:
			s.warn(name, ReasonNotRegular)
		}
		if err != nil {
			return Result{}, fmt.Errorf("inbox scan: %w", err)
		}
	}
	slices.SortFunc(s.res.Items, func(a, b Item) int { return cmp.Compare(a.Path, b.Path) })
	slices.SortFunc(s.res.Warnings, func(a, b Warning) int { return cmp.Compare(a.Path, b.Path) })
	return s.res, nil
}

// scanner accumulates the Result of one Scan.
type scanner struct {
	ib  *Inbox
	res Result
}

func (s *scanner) warn(p string, r Reason) {
	s.res.Warnings = append(s.res.Warnings, Warning{Path: p, Reason: r})
}

type entryClass int

const (
	kindOther entryClass = iota // symlink, FIFO, device, socket…
	kindDir
	kindFile
)

// entryKind classifies a directory entry from the listing alone (lstat
// semantics: a symlink is kindOther whatever it points to).
func entryKind(de fs.DirEntry) entryClass {
	t := de.Type()
	switch {
	case t&fs.ModeSymlink != 0:
		return kindOther
	case t.IsDir():
		return kindDir
	case t.IsRegular():
		return kindFile
	default:
		return kindOther
	}
}

// subfolder scans one provider subfolder, without descending further.
func (s *scanner) subfolder(ctx context.Context, name string) (err error) {
	provider := normalize.Slug(name)
	if fsx.SafeName(name) != name || provider == "" {
		s.warn(name, ReasonInvalidSubfolder)
		return nil
	}
	dir, err := s.ib.root.OpenDir(name)
	switch {
	case errors.Is(err, fsx.ErrNotDir):
		s.warn(name, ReasonNotRegular) // swapped for a symlink since the listing
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("subfolder %q: %w", name, err)
	}
	defer func() {
		if cerr := dir.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("subfolder %q: close: %w", name, cerr))
		}
	}()
	des, err := dir.ReadDir()
	if err != nil {
		return fmt.Errorf("subfolder %q: %w", name, err)
	}
	for _, de := range des {
		base := de.Name()
		if hidden(base) {
			continue
		}
		rel := path.Join(name, base)
		switch entryKind(de) {
		case kindDir:
			s.warn(rel, ReasonNested)
		case kindFile:
			if err := s.file(ctx, dir, de, provider, rel); err != nil {
				return err
			}
		case kindOther:
			s.warn(rel, ReasonNotRegular)
		}
	}
	return nil
}

// file reads and identifies one regular file. dir holds it under de.Name();
// provider is the subfolder's provider id ("" at the inbox root); rel is
// its item path.
func (s *scanner) file(ctx context.Context, dir *fsx.Root, de fs.DirEntry, provider, rel string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%q: %w", rel, err)
	}
	base := de.Name()
	info, err := de.Info()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("%q: %w", rel, err)
	case info.Size() > s.ib.maxSize:
		s.warn(rel, ReasonTooLarge)
		return nil
	}

	data, reason, err := s.read(dir, base)
	switch {
	case err != nil:
		return fmt.Errorf("%q: %w", rel, err)
	case reason == reasonVanished:
		return nil
	case reason != "":
		s.warn(rel, reason)
		return nil
	}

	g, err := s.ib.infer(ctx, data, base, provider)
	if err != nil {
		return fmt.Errorf("%q: %w", rel, err)
	}
	if !g.identified {
		reason, err := s.ask(ctx, rel, &g)
		if err != nil {
			return err
		}
		if reason != "" {
			s.warn(rel, reason)
			return nil
		}
	}
	s.res.Items = append(s.res.Items, Item{
		Path:   rel,
		Size:   int64(len(data)),
		SHA256: sha256.Sum256(data),
		Doc:    g.doc,
		Source: g.source,
	})
	if g.invalidFacturX {
		s.warn(rel, ReasonInvalidFacturX)
	}
	return nil
}

// reasonVanished is read's internal reason for an entry removed since the
// listing: it is skipped without a warning, never reported.
const reasonVanished Reason = "vanished"

// read reads name in dir whole, refusing anything but a regular file and
// anything over the size cap. A non-empty reason means the file is not read.
func (s *scanner) read(dir *fsx.Root, name string) (data []byte, reason Reason, err error) {
	f, err := dir.OpenRegular(name)
	switch {
	case errors.Is(err, fsx.ErrNotRegular):
		return nil, ReasonNotRegular, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, reasonVanished, nil
	case err != nil:
		return nil, "", fmt.Errorf("open: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close: %w", cerr)
		}
	}()
	data, err = io.ReadAll(io.LimitReader(f, s.ib.maxSize+1))
	if err != nil {
		return nil, "", fmt.Errorf("read: %w", err)
	}
	if int64(len(data)) > s.ib.maxSize {
		return nil, ReasonTooLarge, nil
	}
	return data, "", nil
}

// ask completes an unidentified guess with the Prompter. It returns the
// reason the file stays, or "" with g updated to the answer.
func (s *scanner) ask(ctx context.Context, rel string, g *guess) (Reason, error) {
	if s.ib.prompter == nil {
		return ReasonUnidentified, nil
	}
	ans, ok, err := s.ib.prompter.AskDoc(ctx, rel, g.doc)
	if err != nil {
		return "", fmt.Errorf("ask about %q: %w", rel, err)
	}
	if !ok {
		return ReasonSkipped, nil
	}
	ans.Provider = normalize.Slug(ans.Provider)
	ans.Ext = g.doc.Ext
	ans.Version = 0
	if ans.Category == "" {
		ans.Category = s.ib.providers[ans.Provider].Category
	}
	if ans.Date.IsZero() || ans.Provider == "" || !validKind(ans.Kind) {
		return ReasonUnidentified, nil
	}
	g.doc, g.source = ans, SourcePrompt
	return "", nil
}
