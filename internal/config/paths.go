package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

// expandHome resolves a path value of key: "~" and "~/…" are relative to
// home; any other value must already be absolute. "~user" and relative paths
// are refused. The result is cleaned.
func expandHome(v, home, key string) (string, error) {
	switch {
	case v == "~":
		return home, nil
	case strings.HasPrefix(v, "~/") || strings.HasPrefix(v, "~"+string(os.PathSeparator)):
		return filepath.Join(home, filepath.FromSlash(v[2:])), nil
	case strings.HasPrefix(v, "~"):
		return "", invalid(key, `only "~" or "~/…" (the current user's home) is supported`)
	case !filepath.IsAbs(v):
		return "", invalid(key, `must be an absolute path or start with "~/"`)
	}
	return filepath.Clean(v), nil
}

// browserPathKey is the key of the browser binary path.
const browserPathKey = "browser.path"

// expandBrowserPath resolves browser.path: empty stays empty (the installed
// copy is looked up at run time), a value holding a control character is
// refused, and so is a format character (bidi override, zero-width
// character, BOM: unicode.Cf), which would make the path display as
// another; anything else follows expandHome. The value is never quoted.
func expandBrowserPath(v, home string) (string, error) {
	if v == "" {
		return "", nil
	}
	if strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
		return "", invalid(browserPathKey, "must not contain control or format characters")
	}
	return expandHome(v, home, browserPathKey)
}

// validatePaths checks output.local and state_dir (ADR 0007 D1).
func (c *Config) validatePaths() error {
	if !filepath.IsAbs(c.Output.Local) {
		return invalid("output.local", "must be an absolute path")
	}
	if !filepath.IsAbs(c.StateDir) {
		return invalid("state_dir", "must be an absolute path")
	}
	if within(c.StateDir, c.Output.Local) {
		return fmt.Errorf("%w: state_dir: %w (keep it outside output.local, e.g. ~/.facto)", ErrInvalid, ErrStateDirInOutput)
	}
	if syncedFolder(c.StateDir, c.home) {
		return fmt.Errorf("%w: state_dir: %w (keep it in a folder no sync client uploads, e.g. ~/.facto)", ErrInvalid, ErrStateDirSynced)
	}
	return nil
}

// foldCase reports whether paths compare case-insensitively: the default
// file systems of macOS and Windows are.
var foldCase = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// within reports whether p equals dir or is inside it, lexically.
func within(p, dir string) bool {
	p, dir = filepath.Clean(p), filepath.Clean(dir)
	if foldCase {
		p, dir = strings.ToLower(p), strings.ToLower(dir)
	}
	if p == dir {
		return true
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && filepath.IsLocal(rel)
}

// SyncedFolder reports whether dir is inside a folder that a sync client
// uploads, with the rules of Validate's state_dir check (see syncedFolder).
// Lexical: a caller that resolved symlinks gives the resolved dir and the
// resolved home.
func SyncedFolder(dir, home string) bool { return syncedFolder(dir, home) }

// Home returns the home directory the config was parsed with
// (Options.Home, cleaned), against which "~" was expanded.
func (c *Config) Home() string { return c.home }

// syncedFolder reports whether dir is inside a folder that a sync client
// uploads, by looking for the folder names those clients create, on whole
// path components and case-insensitively. When dir is under home, the home
// directory's own components are not checked (a user may be named like a
// sync client). Lexical only: symlinks are not resolved.
func syncedFolder(dir, home string) bool {
	rest := filepath.Clean(dir)
	if home != "" && within(rest, home) {
		if rel, err := filepath.Rel(filepath.Clean(home), rest); err == nil {
			rest = rel
		}
	}
	rest = strings.TrimPrefix(rest, filepath.VolumeName(rest))
	parts := strings.FieldsFunc(strings.ToLower(rest), func(r rune) bool {
		return r == '/' || r == filepath.Separator
	})
	for i, p := range parts {
		if syncedName(p) {
			return true
		}
		// macOS File Provider: every ~/Library/CloudStorage/<provider>.
		if p == "cloudstorage" && i > 0 && parts[i-1] == "library" {
			return true
		}
	}
	return false
}

// syncedName reports whether a lowercase path component is the root folder
// of a known sync client.
func syncedName(p string) bool {
	switch p {
	case "google drive", // Backup and Sync, legacy Drive for desktop
		"googledrive", // common manual mount point
		"my drive",    // Drive for desktop (G:\My Drive, CloudStorage/…/My Drive)
		"dropbox",
		"onedrive",
		"icloud drive",
		"com~apple~clouddocs", // ~/Library/Mobile Documents/com~apple~CloudDocs
		"nextcloud",
		"owncloud",
		"pcloud drive",
		"box", "box sync":
		return true
	}
	return strings.HasPrefix(p, "googledrive-") || // CloudStorage/GoogleDrive-<account>
		strings.HasPrefix(p, "dropbox (") || // Dropbox (<team>)
		strings.HasPrefix(p, "onedrive - ") // OneDrive - <organization>
}
