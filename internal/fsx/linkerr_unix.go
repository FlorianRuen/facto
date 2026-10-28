//go:build !windows

package fsx

import "syscall"

// linkKeepErrnos are link errnos that say nothing about hard-link support
// (full disk, quota, access, read-only, missing path, I/O, long name): they
// are reported as they are, never as ErrLinkUnsupported. EPERM is absent on
// purpose: it is what FAT and friends return when they cannot hard-link.
var linkKeepErrnos = []syscall.Errno{
	syscall.ENOSPC,
	syscall.EDQUOT,
	syscall.EACCES,
	syscall.EROFS,
	syscall.ENOENT,
	syscall.EIO,
	syscall.ENAMETOOLONG,
}
