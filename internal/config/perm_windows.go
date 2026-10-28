//go:build windows

package config

import "io/fs"

// insecure is always false on Windows: Go reports synthetic POSIX modes there
// that say nothing about ACLs (same rule as fsx).
func insecure(fs.FileMode) bool { return false }
