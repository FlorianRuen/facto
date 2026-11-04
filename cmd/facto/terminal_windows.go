package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// echoOff clears ENABLE_ECHO_INPUT on the console f, keeping line input
// and Ctrl-C processing, and returns the function that restores the
// previous mode.
func echoOff(f *os.File) (restore func(), err error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("console: %w", err)
	}
	var (
		old  uint32
		merr error
	)
	cerr := rc.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if merr = windows.GetConsoleMode(h, &old); merr != nil {
			return
		}
		mode := old&^windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
		merr = windows.SetConsoleMode(h, mode)
	})
	if err := errors.Join(cerr, merr); err != nil {
		return nil, fmt.Errorf("console: %w", err)
	}
	return func() {
		_ = rc.Control(func(fd uintptr) {
			_ = windows.SetConsoleMode(windows.Handle(fd), old)
		})
	}, nil
}
