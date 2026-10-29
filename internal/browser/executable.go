package browser

import (
	"fmt"
	"os"
	"path/filepath"
)

// CheckExecutable vets the browser binary before every launch. path must be
// absolute; it is resolved through every symlink (dangling refused), and the
// target must be a regular file. On unix the target must also be
// executable by its owner, without setuid/setgid, not group/world-writable,
// in a parent directory that is not group/world-writable (sticky or not),
// and every higher ancestor may be group/world-writable only with the
// sticky bit (/tmp). On windows only absoluteness and the regular-file
// check apply (ACLs deferred with SEC-J0-18).
//
// The check races with a concurrent rename by the same user; the boundary is
// the user account (ADR 0008 "Boundary"): it keeps other users and stray
// permissions out.
func CheckExecutable(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: path must be absolute", ErrUnsafeExecutable)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%w: resolve: %w", ErrUnsafeExecutable, err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeExecutable, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafeExecutable, resolved)
	}
	return checkModes(resolved, fi)
}
