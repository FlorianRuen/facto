//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// echoOff clears ECHO (and ECHONL) on the terminal f, keeping canonical
// line editing and signals, and returns the function that restores the
// previous settings.
func echoOff(f *os.File) (restore func(), err error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("terminal: %w", err)
	}
	var (
		old  *unix.Termios
		ierr error
	)
	cerr := rc.Control(func(fd uintptr) {
		old, ierr = unix.IoctlGetTermios(int(fd), ioctlGetTermios)
		if ierr != nil {
			return
		}
		raw := *old
		raw.Lflag &^= unix.ECHO | unix.ECHONL
		raw.Lflag |= unix.ICANON | unix.ISIG
		ierr = unix.IoctlSetTermios(int(fd), ioctlSetTermios, &raw)
	})
	if err := errors.Join(cerr, ierr); err != nil {
		return nil, fmt.Errorf("terminal: %w", err)
	}
	return func() {
		_ = rc.Control(func(fd uintptr) {
			_ = unix.IoctlSetTermios(int(fd), ioctlSetTermios, old)
		})
	}, nil
}
