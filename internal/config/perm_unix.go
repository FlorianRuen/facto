//go:build !windows

package config

import "io/fs"

// insecure reports a group or world permission bit (same rule as fsx).
func insecure(mode fs.FileMode) bool { return mode.Perm()&0o077 != 0 }
