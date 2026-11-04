//go:build windows

package browser

import "golang.org/x/sys/windows"

// defaultStarter is the windows Starter: Chrome on --remote-debugging-port=0,
// driven over cdploopback once the port file, the listener pid and the
// Browser.getVersion handshake are checked (ADR 0008 "Windows (A4)").
var defaultStarter = NewPortStarter(PortStarterConfig{
	Exec:        startPortExec,
	ListenerPID: tableListenerPID,
})

// pidAlive is the windows stale-profile probe: pidAliveVia with the real
// OpenProcess.
func pidAlive(pid int) bool {
	return pidAliveVia(pid, openProcess)
}

// openProcess opens pid with PROCESS_QUERY_LIMITED_INFORMATION and closes
// the handle at once (probe only).
func openProcess(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err //nolint:wrapcheck // an errors.Is target for pidAliveVia only, never surfaced
	}
	_ = windows.CloseHandle(h) // probe only
	return nil
}

// pidAliveVia is the windows stale-profile probe. open is the OpenProcess
// seam: nil means the handle opened. ERROR_ACCESS_DENIED means the pid runs
// under another user: alive. ERROR_INVALID_PARAMETER means no such pid:
// gone. Any other error: alive. pid <= 0: alive, open never called
// (pidAliveWith).
func pidAliveVia(pid int, open func(pid uint32) error) bool {
	return pidAliveWith(pid, open, windows.ERROR_ACCESS_DENIED, windows.ERROR_INVALID_PARAMETER)
}
