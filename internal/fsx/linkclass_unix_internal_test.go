//go:build !windows

package fsx

import "syscall"

type namedErrno struct {
	name  string
	errno syscall.Errno
}

// keptLinkErrnos must never be reported as ErrLinkUnsupported.
var keptLinkErrnos = []namedErrno{
	{"ENOSPC", syscall.ENOSPC},
	{"EDQUOT", syscall.EDQUOT},
	{"EACCES", syscall.EACCES},
	{"EROFS", syscall.EROFS},
	{"ENOENT", syscall.ENOENT},
	{"EIO", syscall.EIO},
	{"ENAMETOOLONG", syscall.ENAMETOOLONG},
}

// unsupportedLinkErrnos are what filesystems without hard links return.
var unsupportedLinkErrnos = []namedErrno{
	{"EPERM", syscall.EPERM},
	{"EXDEV", syscall.EXDEV},
	{"EMLINK", syscall.EMLINK},
	{"ENOTSUP", syscall.ENOTSUP},
	{"ENOSYS", syscall.ENOSYS},
}
