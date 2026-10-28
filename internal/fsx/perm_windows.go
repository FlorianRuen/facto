//go:build windows

package fsx

import (
	"io/fs"
	"os"
)

// nonBlock is unused on Windows (no FIFOs in the file namespace).
const nonBlock = 0

// insecure is always false on Windows: Go reports synthetic POSIX modes there
// (0666/0777) that say nothing about ACLs, so the check would refuse every file.
func insecure(fs.FileMode) bool { return false }

// syncDir is a no-op on Windows, where directories cannot be fsynced.
func syncDir(*os.Root, string) error { return nil }
