//go:build !unix

package browser

import "io/fs"

// checkModes has no portable meaning outside unix: Windows ACL checks are
// deferred with SEC-J0-18, so only CheckExecutable's absoluteness and
// regular-file checks apply.
func checkModes(string, fs.FileInfo) error {
	return nil
}
