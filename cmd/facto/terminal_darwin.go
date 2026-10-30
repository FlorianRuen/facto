package main

import "golang.org/x/sys/unix"

// termios ioctl requests (macOS).
const (
	ioctlGetTermios = unix.TIOCGETA
	ioctlSetTermios = unix.TIOCSETA
)
