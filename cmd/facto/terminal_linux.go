package main

import "golang.org/x/sys/unix"

// termios ioctl requests (Linux).
const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)
