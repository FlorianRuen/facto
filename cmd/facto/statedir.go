package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/FlorianRuen/facto/internal/config"
)

// errDanglingStateLink reports a state_dir path component that is a symlink
// to nothing: where the state dir would land cannot be known.
var errDanglingStateLink = errors.New("state_dir goes through a dangling symlink")

// checkStateDirOutside refuses a state dir that is physically inside the
// output folder (docs/spec.md, ADR 0007 D1). config.Validate only compares
// the path text; output.local may be a symlink and so may any parent of
// state_dir, so both are resolved here, once the output folder exists and
// before anything is created in the state dir. The state dir itself may not
// exist yet: its nearest existing ancestor is resolved and the missing tail
// joined back. The resolved path and each of its ancestors are then compared
// with the output folder by file identity (os.SameFile), which also catches
// bind mounts and case-insensitive file systems.
//
// A refusal is a configuration error (exit 2) wrapping
// config.ErrStateDirInOutput; it names keys, never the paths.
func checkStateDirOutside(stateDir, outDir string) error {
	outInfo, err := os.Stat(outDir)
	if err != nil {
		return fmt.Errorf("output folder: %w", err)
	}
	realState, err := resolveMissing(stateDir)
	if err != nil {
		return err
	}
	refuse := &configLoadError{err: fmt.Errorf("%w: state_dir: %w once symlinks are followed (keep it outside output.local, e.g. ~/.facto)",
		config.ErrInvalid, config.ErrStateDirInOutput)}
	for p := realState; ; p = filepath.Dir(p) {
		fi, err := os.Stat(p)
		switch {
		case err == nil && os.SameFile(fi, outInfo):
			return refuse
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("state_dir: %w", err)
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// resolveMissing returns p with every symlink resolved, p itself possibly
// not existing yet: the nearest existing ancestor is resolved with
// filepath.EvalSymlinks and the missing components are joined back.
func resolveMissing(p string) (string, error) {
	p = filepath.Clean(p)
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(p)
		if err == nil {
			parts := append([]string{resolved}, tail...)
			return filepath.Join(parts...), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("state_dir: %w", err)
		}
		if _, lerr := os.Lstat(p); lerr == nil {
			// p exists as a link whose target does not.
			return "", errDanglingStateLink
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", fmt.Errorf("state_dir: %w", err)
		}
		tail = append([]string{filepath.Base(p)}, tail...)
		p = parent
	}
}
