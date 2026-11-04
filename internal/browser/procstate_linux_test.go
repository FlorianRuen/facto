//go:build linux

package browser_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"strconv"
)

// processGone reports whether pid no longer runs: no /proc entry, or a
// zombie (exited, not yet reaped by its new parent).
func processGone(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 >= len(b) {
		return false
	}
	state := b[i+2]
	return state == 'Z' || state == 'X'
}
