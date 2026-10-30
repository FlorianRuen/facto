package browser

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"testing"
)

// T7c review S4: the TCP owner table decoding and the pid probe
// classification are pure logic, tested on every OS (the windows-tagged
// port_windows_test.go runs the same parsers through the export hooks).

// v4Row encodes one MIB_TCPROW_OWNER_PID.
func v4Row(state uint32, local netip.AddrPort, pid uint32) []byte {
	b := make([]byte, tcpRowV4Size)
	binary.LittleEndian.PutUint32(b[0:], state)
	a := local.Addr().As4()
	copy(b[4:8], a[:])
	binary.BigEndian.PutUint16(b[8:], local.Port())
	binary.LittleEndian.PutUint32(b[20:], pid)
	return b
}

// v6Row encodes one MIB_TCP6ROW_OWNER_PID.
func v6Row(state uint32, local netip.AddrPort, pid uint32) []byte {
	b := make([]byte, tcpRowV6Size)
	a := local.Addr().As16()
	copy(b[0:16], a[:])
	binary.BigEndian.PutUint16(b[20:], local.Port())
	binary.LittleEndian.PutUint32(b[48:], state)
	binary.LittleEndian.PutUint32(b[52:], pid)
	return b
}

func table(count uint32, rows ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, count)
	for _, r := range rows {
		b = append(b, r...)
	}
	return b
}

const (
	stateListen      = 2
	stateEstablished = 5
)

func TestParseTCPTableOwnerPID_Rows(t *testing.T) {
	t.Parallel()
	loop := netip.MustParseAddrPort("127.0.0.1:9222")
	anyAddr := netip.MustParseAddrPort("0.0.0.0:445")
	rows := [][]byte{
		v4Row(stateListen, loop, 4242),
		v4Row(stateEstablished, loop, 7),
		v4Row(stateListen, anyAddr, 4),
	}
	got, err := parseTCPTableOwnerPID(table(3, rows...))
	if err != nil {
		t.Fatalf("parseTCPTableOwnerPID = %v", err)
	}
	if want := []TCPListener{{Addr: loop, PID: 4242}, {Addr: anyAddr, PID: 4}}; !slices.Equal(got, want) {
		t.Errorf("parseTCPTableOwnerPID = %+v, want %+v (listeners only)", got, want)
	}
	if got, err := parseTCPTableOwnerPID(table(0)); err != nil || got != nil {
		t.Errorf("parseTCPTableOwnerPID(empty table) = %+v, %v; want nil, nil", got, err)
	}
	// Extra bytes past the declared rows are ignored (the OS buffer may be
	// larger than the table).
	if got, err := parseTCPTableOwnerPID(append(table(1, rows[0]), 0, 0, 0)); err != nil || len(got) != 1 {
		t.Errorf("parseTCPTableOwnerPID(trailing bytes) = %+v, %v; want the one row", got, err)
	}
}

func TestParseTCPTables_RefuseShortOrForged(t *testing.T) {
	t.Parallel()
	r4 := v4Row(stateListen, netip.MustParseAddrPort("127.0.0.1:9222"), 4242)
	r6 := v6Row(stateListen, netip.MustParseAddrPort("[::1]:9222"), 4242)
	tests := []struct {
		name  string
		parse func([]byte) ([]TCPListener, error)
		buf   []byte
	}{
		{"v4 empty", parseTCPTableOwnerPID, nil},
		{"v4 short header", parseTCPTableOwnerPID, []byte{1, 0}},
		{"v4 truncated rows", parseTCPTableOwnerPID, table(3, r4, r4)},
		{"v4 partial row", parseTCPTableOwnerPID, table(1, r4[:20])},
		{"v4 huge count", parseTCPTableOwnerPID, table(0xFFFFFFFF, r4, r4, r4)},
		{"v4 forged huge count over a short body", parseTCPTableOwnerPID, table(0xFFFFFFFF, r4[:7])},
		{"v4 forged huge count, no body", parseTCPTableOwnerPID, table(0x80000000)},
		{"v6 empty", parseTCP6TableOwnerPID, nil},
		{"v6 short header", parseTCP6TableOwnerPID, []byte{1, 0, 0}},
		{"v6 truncated rows", parseTCP6TableOwnerPID, table(2, r6)},
		{"v6 partial row", parseTCP6TableOwnerPID, table(1, r6[:55])},
		{"v6 forged huge count over a short body", parseTCP6TableOwnerPID, table(0xFFFFFFFF, r6, r6[:10])},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := tc.parse(tc.buf); err == nil || got != nil {
				t.Errorf("parse(%s) = %+v, %v; want nil and an error", tc.name, got, err)
			}
		})
	}
}

func TestParseTCP6TableOwnerPID_Rows(t *testing.T) {
	t.Parallel()
	anyV6 := netip.MustParseAddrPort("[::]:9222")
	loop6 := netip.MustParseAddrPort("[::1]:9223")
	buf := table(3,
		v6Row(stateListen, anyV6, 31337),
		v6Row(stateEstablished, loop6, 7),
		v6Row(stateListen, loop6, 4242),
	)
	got, err := parseTCP6TableOwnerPID(buf)
	if err != nil {
		t.Fatalf("parseTCP6TableOwnerPID = %v", err)
	}
	want := []TCPListener{{Addr: anyV6, PID: 31337}, {Addr: loop6, PID: 4242}}
	if !slices.Equal(got, want) {
		t.Errorf("parseTCP6TableOwnerPID = %+v, want %+v", got, want)
	}
	// A port also bound on [::] is refused next to the loopback row.
	rows := slices.Concat(want, []TCPListener{{Addr: netip.MustParseAddrPort("127.0.0.1:9222"), PID: 4242}})
	if _, err := LoopbackListenerPID(rows, 9222); !errors.Is(err, ErrListenerNotBrowser) {
		t.Errorf("LoopbackListenerPID(port also on [::]) = %v, want ErrListenerNotBrowser", err)
	}
}

func TestPidAliveWith_Classification(t *testing.T) {
	t.Parallel()
	errDenied := errors.New("access denied")
	errInvalid := errors.New("invalid parameter")
	errOther := errors.New("not enough memory")
	tests := []struct {
		name    string
		pid     int
		openErr error
		want    bool
	}{
		{name: "opened", pid: 4242, want: true},
		{name: "access denied", pid: 4242, openErr: errDenied, want: true},
		{name: "access denied wrapped", pid: 4242, openErr: fmt.Errorf("open process: %w", errDenied), want: true},
		{name: "no such pid", pid: 4242, openErr: errInvalid, want: false},
		{name: "no such pid wrapped", pid: 4242, openErr: fmt.Errorf("open: %w", errInvalid), want: false},
		{name: "other error keeps the profile", pid: 4242, openErr: errOther, want: true},
		{name: "pid 0", pid: 0, want: true},
		{name: "negative pid", pid: -1, want: true},
		{name: "largest int", pid: math.MaxInt, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			got := pidAliveWith(tc.pid, func(pid uint32) error {
				calls++
				if int(pid) != tc.pid {
					t.Errorf("open pid = %d, want %d", pid, tc.pid)
				}
				return tc.openErr
			}, errDenied, errInvalid)
			if got != tc.want {
				t.Errorf("pidAliveWith(%d, %v) = %v, want %v", tc.pid, tc.openErr, got, tc.want)
			}
			if (tc.pid <= 0 || uint64(tc.pid) > math.MaxUint32) && calls != 0 {
				t.Errorf("open called %d times for pid %d", calls, tc.pid)
			}
		})
	}
}
