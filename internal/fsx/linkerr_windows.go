//go:build windows

package fsx

import "syscall"

// Win32 error codes missing from package syscall.
const (
	errorPathNotFound    syscall.Errno = 3   // ERROR_PATH_NOT_FOUND
	errorWriteProtect    syscall.Errno = 19  // ERROR_WRITE_PROTECT
	errorHandleDiskFull  syscall.Errno = 39  // ERROR_HANDLE_DISK_FULL
	errorDiskFull        syscall.Errno = 112 // ERROR_DISK_FULL
	errorFilenameTooLong syscall.Errno = 206 // ERROR_FILENAME_EXCED_RANGE
)

// linkKeepErrnos are link errors that say nothing about hard-link support
// (full disk, access denied, write-protected media, missing path, long
// name): they are reported as they are, never as ErrLinkUnsupported.
var linkKeepErrnos = []syscall.Errno{
	errorDiskFull,
	errorHandleDiskFull,
	syscall.ERROR_ACCESS_DENIED,
	errorWriteProtect,
	syscall.ERROR_FILE_NOT_FOUND,
	errorPathNotFound,
	errorFilenameTooLong,
}
