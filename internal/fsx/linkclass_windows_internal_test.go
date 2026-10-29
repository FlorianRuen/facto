//go:build windows

package fsx

import "syscall"

type namedErrno struct {
	name  string
	errno syscall.Errno
}

// keptLinkErrnos must never be reported as ErrLinkUnsupported.
var keptLinkErrnos = []namedErrno{
	{"ERROR_DISK_FULL", syscall.Errno(112)},
	{"ERROR_ACCESS_DENIED", syscall.ERROR_ACCESS_DENIED},
	{"ERROR_WRITE_PROTECT", syscall.Errno(19)},
}

// unsupportedLinkErrnos are what filesystems without hard links return.
var unsupportedLinkErrnos = []namedErrno{
	{"ERROR_INVALID_FUNCTION", syscall.Errno(1)},
	{"ERROR_NOT_SUPPORTED", syscall.Errno(50)},
	{"ERROR_NOT_SAME_DEVICE", syscall.Errno(17)},
}
