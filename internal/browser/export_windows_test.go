//go:build windows

package browser

// Test hooks for the windows-only pieces of T7c (J1). Expected unexported
// API in windows-tagged production files:
//
//	// pidAliveVia is the windows stale-profile probe. open is the
//	// OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) seam: nil means the
//	// handle opened (and was closed). ERROR_ACCESS_DENIED means the pid
//	// runs under another user: alive. ERROR_INVALID_PARAMETER means no
//	// such pid: gone. Any other error: alive (a profile is never swept on
//	// doubt). pid <= 0: alive, open never called. pidAlive (pool_other.go
//	// on windows) is pidAliveVia with the real OpenProcess.
//	func pidAliveVia(pid int, open func(pid uint32) error) bool
//
//	// parseTCPTableOwnerPID decodes a MIB_TCPTABLE_OWNER_PID buffer
//	// (GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_LISTENER):
//	// dwNumEntries (uint32 LE), then rows of six uint32: dwState (LE),
//	// dwLocalAddr (network order bytes), dwLocalPort (port big-endian in
//	// the first two bytes), dwRemoteAddr, dwRemotePort, dwOwningPid (LE).
//	// Only MIB_TCP_STATE_LISTEN (2) rows are returned. A buffer shorter
//	// than 4 bytes or than 4+24*dwNumEntries is an error (never a panic,
//	// never a partial table).
//	func parseTCPTableOwnerPID(buf []byte) ([]TCPListener, error)

// PidAliveVia exposes pidAliveVia.
func PidAliveVia(pid int, open func(pid uint32) error) bool { return pidAliveVia(pid, open) }

// ParseTCPTableOwnerPID exposes parseTCPTableOwnerPID.
func ParseTCPTableOwnerPID(buf []byte) ([]TCPListener, error) { return parseTCPTableOwnerPID(buf) }
