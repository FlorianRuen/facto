//go:build !linux

package proc

// Harden is a no-op outside Linux.
func Harden() error { return nil }
