//go:build windows

// Windows-only pieces of T7c (J1): the stale-profile pid probe and the TCP
// owner table decoding. Expected API: see export_windows_test.go.
package browser_test

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/FlorianRuen/facto/internal/browser"
)

func TestPidAlive_WindowsAccessDeniedIsAlive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		pid     int
		openErr error
		want    bool
	}{
		{name: "opened", pid: 4242, want: true},
		{name: "access denied (other user)", pid: 4242, openErr: windows.ERROR_ACCESS_DENIED, want: true},
		{name: "access denied wrapped", pid: 4242, openErr: fmt.Errorf("open process: %w", windows.ERROR_ACCESS_DENIED), want: true},
		{name: "no such pid", pid: 4242, openErr: windows.ERROR_INVALID_PARAMETER, want: false},
		{name: "other error keeps the profile", pid: 4242, openErr: windows.ERROR_NOT_ENOUGH_MEMORY, want: true},
		{name: "pid 0", pid: 0, want: true},
		{name: "negative pid", pid: -1, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			got := browser.PidAliveVia(tc.pid, func(pid uint32) error {
				calls++
				if int(pid) != tc.pid {
					t.Errorf("OpenProcess pid = %d, want %d", pid, tc.pid)
				}
				return tc.openErr
			})
			if got != tc.want {
				t.Errorf("PidAliveVia(%d, err %v) = %v, want %v", tc.pid, tc.openErr, got, tc.want)
			}
			if tc.pid <= 0 && calls != 0 {
				t.Errorf("OpenProcess called %d times for pid %d", calls, tc.pid)
			}
		})
	}
}

// tcpRow encodes one MIB_TCPROW_OWNER_PID.
func tcpRow(state uint32, local netip.AddrPort, pid uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], state)
	a := local.Addr().As4()
	copy(b[4:8], a[:])
	binary.BigEndian.PutUint16(b[8:], local.Port())
	// remote addr/port zero for a listener
	binary.LittleEndian.PutUint32(b[20:], pid)
	return b
}

func tcpTable(count uint32, rows ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, count)
	for _, r := range rows {
		b = append(b, r...)
	}
	return b
}

func TestTCPTable_ParsesOwnerPIDRows(t *testing.T) {
	t.Parallel()
	const listen, established = 2, 5
	loop := netip.MustParseAddrPort("127.0.0.1:9222")
	anyAddr := netip.MustParseAddrPort("0.0.0.0:445")
	rows := [][]byte{
		tcpRow(listen, loop, 4242),
		tcpRow(established, loop, 7),
		tcpRow(listen, anyAddr, 4),
	}
	got, err := browser.ParseTCPTableOwnerPID(tcpTable(3, rows...))
	if err != nil {
		t.Fatalf("ParseTCPTableOwnerPID = %v", err)
	}
	want := []browser.TCPListener{{Addr: loop, PID: 4242}, {Addr: anyAddr, PID: 4}}
	if !slices.Equal(got, want) {
		t.Errorf("ParseTCPTableOwnerPID = %+v, want %+v (listeners only)", got, want)
	}

	bad := []struct {
		name string
		buf  []byte
	}{
		{"empty", nil},
		{"short header", []byte{1, 0}},
		{"truncated rows", tcpTable(3, rows[0], rows[1])},
		{"partial row", tcpTable(1, rows[0][:20])},
		{"huge count", tcpTable(0xFFFFFFFF, rows...)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := browser.ParseTCPTableOwnerPID(tc.buf); err == nil || got != nil {
				t.Errorf("ParseTCPTableOwnerPID(%s) = %+v, %v; want nil and an error", tc.name, got, err)
			}
		})
	}
	if _, err := browser.ParseTCPTableOwnerPID(tcpTable(0)); err != nil {
		t.Errorf("ParseTCPTableOwnerPID(empty table) = %v, want no error", err)
	}
}
