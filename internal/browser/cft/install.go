package cft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/httpx"
)

const (
	// downloadTimeout bounds the whole download when Options.HTTP.Timeout
	// is zero: the archive is about 170 MB.
	downloadTimeout = 30 * time.Minute
	// workPattern names the private work directory created in Dir for one
	// install (archive, staging tree, previous version); always removed.
	workPattern = ".cft-work-*"
	archiveName = "archive.zip"
	stagingName = "staging"
	previousDir = "previous"
	rejectedDir = "rejected"
	// maxMarkerSize caps the marker read: it holds one hex digest.
	maxMarkerSize = 256
	// statusOK is the only HTTP status accepted for the archive.
	statusOK = 200
)

// errNoExecutable reports an archive that verified but holds no chrome
// executable where the manifest says it is.
var errNoExecutable = errors.New("cft: archive holds no chrome executable")

// Options configures an Installer.
type Options struct {
	Manifest Manifest
	Dir      string        // install root: must exist and be private (0700)
	HTTP     httpx.Options // test seam (RootCAs, DialContext); zero in production
	Log      *slog.Logger  // nil: discard
	Limits   Limits        // zero fields: DefaultLimits
}

// Installer installs one pinned Chrome for Testing build under a private
// directory. Safe for sequential use; concurrent installs into the same
// directory are not supported (each sweeps leftover work directories).
type Installer struct {
	m      Manifest
	dir    string
	client *httpx.Client
	log    *slog.Logger
	lim    Limits
}

// New validates opts.Manifest (ErrInvalidManifest), checks Dir with
// fsx.CheckPrivate (fs.ErrNotExist, fsx.ErrInsecurePerms), and builds an
// httpx client allowing only Manifest.Host on 443 and only paths under
// Manifest.PathPrefix, for every hop (httpx.NewPinned). It accepts the
// Pinned() manifest even though the real host is shared storage (the path
// prefix is what narrows it). New does no network I/O.
func New(opts Options) (*Installer, error) {
	if err := opts.Manifest.Validate(); err != nil {
		return nil, err
	}
	if opts.Dir == "" {
		return nil, errors.New("cft: install directory is empty")
	}
	dir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("cft: install directory: %w", err)
	}
	if err := fsx.CheckPrivate(dir); err != nil {
		return nil, fmt.Errorf("cft: install directory: %w", err)
	}
	h := opts.HTTP
	if h.Timeout <= 0 {
		h.Timeout = downloadTimeout
	}
	client, err := httpx.NewPinned(opts.Manifest.Host, opts.Manifest.PathPrefix, h)
	if err != nil {
		return nil, fmt.Errorf("cft: %w: %w", ErrInvalidManifest, err)
	}
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Installer{m: opts.Manifest, dir: dir, client: client, log: log, lim: opts.Limits.withDefaults()}, nil
}

// executable is the path of chrome inside an install of this manifest,
// relative to the version directory, slash-separated.
func (in *Installer) executable() string {
	return "chrome-" + in.m.Platform + "/chrome"
}

// Install makes sure the pinned build is extracted under <Dir>/<Version>/
// and returns the absolute path of the executable,
// filepath.Join(Dir, Version, "chrome-"+Platform, "chrome").
// It first removes the work directories an interrupted earlier install
// left in Dir (never following a symlink).
// If <Dir>/<Version>/MarkerName is a regular file holding Manifest.SHA256
// and the executable is a regular file, it returns at once with no network
// I/O. Otherwise it downloads Manifest.URL through httpx into a private
// temp location: a Content-Length different from Size is refused before
// reading the body, the stream is cut at Size+1 bytes, a streamed size
// different from Size wraps ErrSizeMismatch and is checked before the
// hash; a hash mismatch wraps ErrChecksumMismatch; only then is the archive
// unzipped (Unzip) into a staging directory, whose chrome must be a regular
// file executable by its owner, that replaces <Dir>/<Version>/ and gets the
// marker last. A refused redirect wraps ErrRedirectRefused
// and the httpx sentinel. On any error (including a canceled ctx or a cut
// connection) Dir is left as it was before the call: no temp file, no
// staging or version directory. Progress is logged through Log and never
// contains a URL query, a fragment, or a header value; neither does any
// returned error.
func (in *Installer) Install(ctx context.Context) (string, error) {
	exe := filepath.Join(in.dir, in.m.Version, filepath.FromSlash(in.executable()))
	root, err := fsx.Open(in.dir)
	if err != nil {
		return "", fmt.Errorf("cft install: %w", err)
	}
	defer func() { _ = root.Close() }() // read-side handle; nothing to flush
	if err := in.sweep(ctx, root); err != nil {
		return "", err
	}
	if in.verified(root) {
		in.log.InfoContext(ctx, "Chrome for Testing already installed and verified", slog.String("version", in.m.Version))
		return exe, nil
	}
	if err := in.install(ctx, root); err != nil {
		return "", err
	}
	in.log.InfoContext(ctx, "Chrome for Testing installed", slog.String("version", in.m.Version))
	return exe, nil
}

// sweep removes the work directories (workPattern) an interrupted earlier
// install left in Dir. A real directory is removed with fsx.RemoveTree,
// which never follows a symlink inside it; anything else carrying the
// prefix (a file, a symlink) is unlinked itself, never followed. Other
// entries are left alone. Concurrent installs into the same Dir are not
// supported: one would sweep the other's work directory.
func (in *Installer) sweep(ctx context.Context, root *fsx.Root) error {
	des, err := root.ReadDir()
	if err != nil {
		return fmt.Errorf("cft install: list install directory: %w", err)
	}
	prefix := strings.TrimSuffix(workPattern, "*")
	for _, de := range des {
		name := de.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if de.Type() == fs.ModeDir {
			err = fsx.RemoveTree(in.dir, name)
		} else {
			err = root.Remove(name)
		}
		if err != nil {
			return fmt.Errorf("cft install: remove leftover %q: %w", name, err)
		}
		in.log.InfoContext(ctx, "removed a leftover of an interrupted install", slog.String("entry", name))
	}
	return nil
}

// verified reports whether root holds a verified install of the pinned
// build (Verified).
func (in *Installer) verified(root *fsx.Root) bool {
	return Verified(root, in.m)
}

// Verified reports whether the install directory root holds a verified
// install of m: <Version>/ and <Version>/chrome-<Platform>/ real
// directories, <Version>/MarkerName a regular file holding m.SHA256
// (surrounding white space ignored) and the executable a regular file.
// Symlinks are never followed, and nothing is created or modified: any
// doubt means "not verified".
func Verified(root *fsx.Root, m Manifest) bool {
	vr, err := root.OpenDir(m.Version)
	if err != nil {
		return false
	}
	defer func() { _ = vr.Close() }() // read-side handle
	pr, err := vr.OpenDir("chrome-" + m.Platform)
	if err != nil {
		return false
	}
	defer func() { _ = pr.Close() }() // read-side handle
	fi, err := pr.Lstat("chrome")
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	f, err := vr.OpenRegular(MarkerName)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxMarkerSize))
	return err == nil && strings.TrimSpace(string(b)) == m.SHA256
}

// install downloads, verifies and extracts into a private work directory
// inside Dir, then swaps the staging tree in as <Version>/ and writes the
// marker. The work directory is always removed.
func (in *Installer) install(ctx context.Context, root *fsx.Root) (err error) {
	workPath, err := fsx.MkdirTempPrivate(in.dir, workPattern)
	if err != nil {
		return fmt.Errorf("cft install: %w", err)
	}
	work := filepath.Base(workPath)
	defer func() {
		if rmErr := fsx.RemoveTree(in.dir, work); rmErr != nil {
			err = errors.Join(err, fmt.Errorf("cft install: remove work directory: %w", rmErr))
		}
	}()
	wr, err := root.OpenDir(work)
	if err != nil {
		return fmt.Errorf("cft install: %w", err)
	}
	defer func() { _ = wr.Close() }() // directory handle; nothing to flush

	archive, err := in.download(ctx, wr)
	if err != nil {
		return err
	}
	defer func() { _ = archive.Close() }() // read-only
	if err := in.verifyHash(archive); err != nil {
		return err
	}
	if err := in.extract(ctx, wr, archive); err != nil {
		return err
	}
	return in.swap(ctx, root, work)
}

// download fetches the archive into <work>/archive.zip and returns it
// opened read-only, once its size is exactly Manifest.Size.
func (in *Installer) download(ctx context.Context, wr *fsx.Root) (*os.File, error) {
	in.log.InfoContext(ctx, "downloading Chrome for Testing",
		slog.String("version", in.m.Version), slog.String("host", in.m.Host), slog.Int64("bytes", in.m.Size))
	resp, err := in.client.Get(ctx, in.m.URL)
	if err != nil {
		return nil, in.netErr(err)
	}
	defer func() { _ = resp.Body.Close() }() // the read error, if any, is the one reported
	if resp.StatusCode != statusOK {
		return nil, fmt.Errorf("cft download from %s: unexpected status %d", in.m.Host, resp.StatusCode)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != in.m.Size {
		return nil, fmt.Errorf("cft download from %s: %w: Content-Length %d, pinned %d", in.m.Host, ErrSizeMismatch, resp.ContentLength, in.m.Size)
	}
	body := &countReader{r: httpx.LimitBody(resp.Body, in.m.Size)}
	if err := wr.WriteAtomicFrom(ctx, archiveName, body); err != nil {
		switch {
		case errors.Is(err, httpx.ErrBodyTooLarge):
			return nil, fmt.Errorf("cft download from %s: %w: more than %d bytes", in.m.Host, ErrSizeMismatch, in.m.Size)
		case ctx.Err() != nil && !errors.Is(err, ctx.Err()):
			return nil, fmt.Errorf("cft download from %s: %w: %w", in.m.Host, ctx.Err(), err)
		}
		return nil, fmt.Errorf("cft download from %s: %w", in.m.Host, err)
	}
	if body.n != in.m.Size {
		return nil, fmt.Errorf("cft download from %s: %w: %d bytes, pinned %d", in.m.Host, ErrSizeMismatch, body.n, in.m.Size)
	}
	f, err := wr.OpenRegular(archiveName)
	if err != nil {
		return nil, fmt.Errorf("cft download: %w", err)
	}
	if fi, err := f.Stat(); err != nil || fi.Size() != in.m.Size {
		_ = f.Close() // read-only
		return nil, fmt.Errorf("cft download: %w: stored archive changed size", ErrSizeMismatch)
	}
	in.log.InfoContext(ctx, "downloaded Chrome for Testing archive", slog.String("version", in.m.Version), slog.Int64("bytes", body.n))
	return f, nil
}

// netErr wraps a request error, adding ErrRedirectRefused when the pinned
// client refused a hop (the first URL is validated by the manifest, so a
// refusal comes from a redirect). httpx errors carry no query or fragment.
func (in *Installer) netErr(err error) error {
	if errors.Is(err, httpx.ErrDomainNotAllowed) || errors.Is(err, httpx.ErrInsecureScheme) || errors.Is(err, httpx.ErrPathNotAllowed) {
		return fmt.Errorf("cft download from %s: %w: %w", in.m.Host, ErrRedirectRefused, err)
	}
	return fmt.Errorf("cft download from %s: %w", in.m.Host, err)
}

// verifyHash hashes the stored archive, from the very file descriptor
// Unzip will read, and compares it with Manifest.SHA256.
func (in *Installer) verifyHash(f *os.File) error {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, in.m.Size)); err != nil {
		return fmt.Errorf("cft verify: read archive: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != in.m.SHA256 {
		return fmt.Errorf("cft verify %s: %w", in.m.Version, ErrChecksumMismatch)
	}
	return nil
}

// extract unzips the verified archive into <work>/staging and checks that
// the executable is there.
func (in *Installer) extract(ctx context.Context, wr *fsx.Root, archive *os.File) error {
	if err := wr.MkdirPrivate(stagingName); err != nil {
		return fmt.Errorf("cft install: %w", err)
	}
	st, err := wr.OpenDir(stagingName)
	if err != nil {
		return fmt.Errorf("cft install: %w", err)
	}
	defer func() { _ = st.Close() }() // directory handle
	if err := Unzip(ctx, archive, in.m.Size, st, in.lim); err != nil {
		return err
	}
	fi, err := st.Lstat(in.executable())
	if err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", errNoExecutable, in.executable())
	}
	// Unzip writes 0700 only for an entry with an execute bit: an archive
	// whose chrome entry has none (or no Unix mode at all) is not the
	// pinned build.
	if fi.Mode().Perm()&0o100 == 0 {
		return fmt.Errorf("%w: %s is not executable by its owner", errNoExecutable, in.executable())
	}
	return nil
}

// swap moves the staging tree in as <Version>/ (an existing one is moved
// into the work directory first) and writes the marker last. On failure it
// puts the previous <Version>/ back.
func (in *Installer) swap(ctx context.Context, root *fsx.Root, work string) error {
	version := in.m.Version
	previous := path.Join(work, previousDir)
	hadPrevious := false
	switch _, err := root.Lstat(version); {
	case err == nil:
		if err := root.Rename(version, previous); err != nil {
			return fmt.Errorf("cft install: set previous version aside: %w", err)
		}
		hadPrevious = true
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("cft install: %w", err)
	}
	restore := func(cause error) error {
		if hadPrevious {
			if err := root.Rename(previous, version); err != nil {
				cause = errors.Join(cause, fmt.Errorf("restore previous version: %w", err))
			}
		}
		return fmt.Errorf("cft install: %w", cause)
	}
	if err := root.Rename(path.Join(work, stagingName), version); err != nil {
		return restore(err)
	}
	if err := root.WriteAtomic(ctx, version+"/"+MarkerName, []byte(in.m.SHA256+"\n")); err != nil {
		if mvErr := root.Rename(version, path.Join(work, rejectedDir)); mvErr != nil {
			return restore(errors.Join(err, fmt.Errorf("set unmarked version aside: %w", mvErr)))
		}
		return restore(err)
	}
	return nil
}

// countReader counts the bytes read through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	switch {
	case errors.Is(err, io.EOF):
		return n, io.EOF
	case err != nil:
		return n, fmt.Errorf("read archive: %w", err)
	}
	return n, nil
}
