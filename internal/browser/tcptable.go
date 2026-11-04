package browser

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Pure decoding of the windows TCP owner tables and the windows pid probe
// classification, untagged so every OS tests them (the syscalls live in
// portexec_windows.go and pool_windows.go).

// TCP table layout (iphlpapi.h).
const (
	mibTCPStateListen = 2 // MIB_TCP_STATE_LISTEN
	tcpRowV4Size      = 24
	tcpRowV6Size      = 56
)

// parseTCPTableOwnerPID decodes a MIB_TCPTABLE_OWNER_PID buffer
// (GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_LISTENER):
// dwNumEntries (uint32 LE), then rows of six uint32: dwState (LE),
// dwLocalAddr (network order bytes), dwLocalPort (port big-endian in the
// first two bytes), dwRemoteAddr, dwRemotePort, dwOwningPid (LE). Only
// MIB_TCP_STATE_LISTEN rows are returned. A buffer shorter than 4 bytes or
// than 4+24*dwNumEntries is an error (never a panic, never a partial table).
func parseTCPTableOwnerPID(buf []byte) ([]TCPListener, error) {
	return parseTCPRows(buf, tcpRowV4Size, func(r []byte) (TCPListener, bool) {
		if binary.LittleEndian.Uint32(r[0:4]) != mibTCPStateListen {
			return TCPListener{}, false
		}
		addr := netip.AddrFrom4([4]byte(r[4:8]))
		port := binary.BigEndian.Uint16(r[8:10])
		return TCPListener{Addr: netip.AddrPortFrom(addr, port), PID: int(binary.LittleEndian.Uint32(r[20:24]))}, true
	})
}

// parseTCP6TableOwnerPID decodes a MIB_TCP6TABLE_OWNER_PID buffer (AF_INET6):
// dwNumEntries, then 56-byte rows: ucLocalAddr[16], dwLocalScopeId,
// dwLocalPort (big-endian in the first two bytes), ucRemoteAddr[16],
// dwRemoteScopeId, dwRemotePort, dwState (LE), dwOwningPid (LE). Only
// listening rows are returned; same size rules as parseTCPTableOwnerPID.
func parseTCP6TableOwnerPID(buf []byte) ([]TCPListener, error) {
	return parseTCPRows(buf, tcpRowV6Size, func(r []byte) (TCPListener, bool) {
		if binary.LittleEndian.Uint32(r[48:52]) != mibTCPStateListen {
			return TCPListener{}, false
		}
		addr := netip.AddrFrom16([16]byte(r[0:16]))
		port := binary.BigEndian.Uint16(r[20:22])
		return TCPListener{Addr: netip.AddrPortFrom(addr, port), PID: int(binary.LittleEndian.Uint32(r[52:56]))}, true
	})
}

// parseTCPRows checks the row count against the buffer, then decodes each
// row with row (which reports whether to keep it).
func parseTCPRows(buf []byte, rowSize int, row func([]byte) (TCPListener, bool)) ([]TCPListener, error) {
	if len(buf) < 4 {
		return nil, errors.New("tcp table: short header")
	}
	count := binary.LittleEndian.Uint32(buf[0:4])
	body := buf[4:]
	var out []TCPListener
	// A count larger than the buffer runs out of rows: nothing is returned.
	for i := uint32(0); i < count; i++ {
		if len(body) < rowSize {
			return nil, errors.New("tcp table: truncated rows")
		}
		if l, ok := row(body[:rowSize]); ok {
			out = append(out, l)
		}
		body = body[rowSize:]
	}
	return out, nil
}

// pidAliveWith classifies an OpenProcess result for the stale-profile
// probe: nil means the handle opened (alive); denied (ERROR_ACCESS_DENIED,
// the pid runs under another user) is alive; invalid
// (ERROR_INVALID_PARAMETER, no such pid) is gone; any other error is alive
// (a profile is never swept on doubt). pid <= 0, or beyond a DWORD, is
// alive and open is never called.
func pidAliveWith(pid int, open func(pid uint32) error, denied, invalid error) bool {
	if pid <= 0 || uint64(pid) > 0xFFFFFFFF {
		return true
	}
	err := open(uint32(pid))
	switch {
	case err == nil, errors.Is(err, denied):
		return true
	case errors.Is(err, invalid):
		return false
	default:
		return true
	}
}
