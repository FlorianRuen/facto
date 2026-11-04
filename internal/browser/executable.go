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
// On unix the resolved binary and its parent directory must also be owned
// by the effective uid or by root (CheckExecutableAs).
//
// The check races with a concurrent rename by the same user; the boundary is
// the user account (ADR 0008 "Boundary"): it keeps other users and stray
// permissions out.
func CheckExecutable(path string) error {
	return CheckExecutableAs(path, os.Geteuid(), statOwner)
}

// CheckExecutableAs is CheckExecutable with the ownership check made
// injectable: on unix the resolved binary and its parent directory must each
// be owned by euid or by root (uid 0). owner returns the uid of a path that
// is already fully resolved (it is never asked about a symlink). A nil owner
// or an owner error fails closed with ErrUnsafeExecutable. Outside unix the
// ownership check does not apply (ACLs deferred with SEC-J0-18).
func CheckExecutableAs(path string, euid int, owner func(path string) (uid int, err error)) error {
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
	if err := checkModes(resolved, fi); err != nil {
		return err
	}
	return checkOwners(resolved, euid, owner)
}
