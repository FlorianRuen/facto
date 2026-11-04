//go:build e2e && linux

package e2e

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// procTCPTables are the LISTEN tables of a network namespace.
var procTCPTables = []string{"tcp", "tcp6"}

// snapshotHostListeners records the LISTEN rows of the test process's own
// network namespace (/proc/self/net/tcp{,6}) owned by this uid: the
// baseline taken before facto starts.
func snapshotHostListeners() (hostListeners, error) {
	rows, err := listenRows("/proc/self")
	if err != nil {
		return nil, err
	}
	uid := os.Getuid()
	out := hostListeners{}
	for _, r := range rows {
		if r.UID == uid {
			out[r.Inode] = r.Addr
		}
	}
	return out, nil
}

// probeBrowserTree inspects root and every descendant through /proc: the
// browser processes and their --user-data-dir, every listening TCP socket
// (IPv4 and IPv6, read from each process's own network namespace) and any
// debugging-port argument. A process that exits during the probe is
// skipped; any other unreadable entry sets Err.
//
// With opts.HardenedRoot, root itself may be unreadable (facto runs with
// PR_SET_DUMPABLE=0, so its fd and ns entries need ptrace rights): it is
// recorded as RootHardened instead of failing, and opts.HostBaseline keeps
// it covered: every LISTEN row of the host network namespace owned by this
// uid that is new since the baseline fails the probe, unless it is exactly
// one of opts.AllowListeners or its socket is held by a readable process outside
// root's tree (the test process's own fake sites, for instance). A new row
// nobody readable holds is counted against root. Descendants keep the full
// check: an unreadable descendant is a failure.
func probeBrowserTree(root int, opts probeOptions) browserProbe {
	var p browserProbe
	pids, err := descendants(root)
	if err != nil {
		p.Err = err
		return p
	}
	listening := map[string]map[uint64]string{} // netns -> inode -> local address
	var errs []error
	for _, pid := range pids {
		dir := filepath.Join("/proc", strconv.Itoa(pid))
		isRoot := pid == root
		argv, err := readCmdline(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil && isRoot && opts.HardenedRoot && errors.Is(err, fs.ErrPermission):
			p.RootHardened = true
			continue
		case err != nil:
			errs = append(errs, fmt.Errorf("pid %d cmdline: %w", pid, err))
			continue
		}
		var profiles []string
		for _, a := range argv {
			if d, ok := strings.CutPrefix(a, "--user-data-dir="); ok {
				profiles = append(profiles, d)
			}
		}
		for _, a := range debugPortArgs(argv) {
			p.DebugPortArgs = append(p.DebugPortArgs, fmt.Sprintf("pid %d: %s", pid, a))
		}
		inspected, err := inspectSockets(dir, pid, listening, &p)
		switch {
		case err != nil && isRoot && opts.HardenedRoot && errors.Is(err, fs.ErrPermission):
			p.RootHardened = true
			continue
		case err != nil:
			errs = append(errs, err)
			continue
		case !inspected:
			continue // exited meanwhile
		}
		p.Processes++
		if !isRoot {
			p.Inspected++
		}
		for _, d := range profiles {
			p.BrowserPIDs = append(p.BrowserPIDs, pid)
			p.Profiles = append(p.Profiles, d)
			if d != "" {
				p.InspectedBrowsers++
			}
		}
	}
	if opts.HostBaseline != nil {
		if err := checkHostListeners(pids, opts, &p); err != nil {
			errs = append(errs, err)
		}
	}
	p.Err = errors.Join(errs...)
	return p
}

// inspectSockets adds to p every LISTEN socket held by the process in
// dir (in its own network namespace). It reports false when the process
// exited meanwhile.
func inspectSockets(dir string, pid int, listening map[string]map[uint64]string, p *browserProbe) (bool, error) {
	ns, err := os.Readlink(filepath.Join(dir, "ns", "net"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("pid %d netns: %w", pid, err)
	}
	if _, ok := listening[ns]; !ok {
		rows, err := listenRows(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("pid %d tcp tables: %w", pid, err)
		}
		tbl := make(map[uint64]string, len(rows))
		for _, r := range rows {
			tbl[r.Inode] = r.Addr
		}
		listening[ns] = tbl
	}
	inodes, err := socketInodes(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("pid %d fds: %w", pid, err)
	}
	for _, ino := range inodes {
		if addr, ok := listening[ns][ino]; ok {
			p.Listeners = append(p.Listeners, fmt.Sprintf("pid %d: %s", pid, addr))
		}
	}
	return true, nil
}

// checkHostListeners compares the host namespace's LISTEN rows with the
// baseline (see probeBrowserTree).
func checkHostListeners(tree []int, opts probeOptions, p *browserProbe) error {
	rows, err := listenRows("/proc/self")
	if err != nil {
		return fmt.Errorf("host listeners: %w", err)
	}
	uid := os.Getuid()
	var fresh []listenRow
	for _, r := range rows {
		if _, seen := opts.HostBaseline[r.Inode]; seen || r.UID != uid || slices.Contains(opts.AllowListeners, r.Addr) {
			continue
		}
		fresh = append(fresh, r)
	}
	if len(fresh) == 0 {
		return nil
	}
	// A row with no readable owner may be a listener closed between the
	// table read and the descriptor scan (parallel tests start and stop
	// fake sites): only a row still listening on a second read, and still
	// unowned after a second scan, is counted. A listener of facto stays
	// open while Chrome waits for the page, so it survives both reads.
	unowned := unownedRows(fresh)
	if len(unowned) == 0 {
		return nil
	}
	again, err := listenRows("/proc/self")
	if err != nil {
		return fmt.Errorf("host listeners: %w", err)
	}
	still := map[uint64]bool{}
	for _, r := range again {
		still[r.Inode] = true
	}
	var persistent []listenRow
	for _, r := range unowned {
		if still[r.Inode] {
			persistent = append(persistent, r)
		}
	}
	for _, r := range unownedRows(persistent) {
		p.Listeners = append(p.Listeners, fmt.Sprintf("host netns, no readable owner (counted against hardened pid %d): %s", tree[0], r.Addr))
	}
	return nil
}

// unownedRows returns the rows whose socket no readable process holds. A
// socket held by a readable process is either outside facto's tree (the
// test process's fake sites) or in it, where the tree scan reports it.
func unownedRows(rows []listenRow) []listenRow {
	if len(rows) == 0 {
		return nil
	}
	owners := socketOwners(rows)
	var out []listenRow
	for _, r := range rows {
		if _, ok := owners[r.Inode]; !ok {
			out = append(out, r)
		}
	}
	return out
}

// socketOwners maps each row's inode to a readable process holding it.
// Unreadable processes are skipped: their sockets stay unattributed.
func socketOwners(rows []listenRow) map[uint64]int {
	want := map[uint64]bool{}
	for _, r := range rows {
		want[r.Inode] = true
	}
	out := map[uint64]int{}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		inodes, err := socketInodes(filepath.Join("/proc", e.Name()))
		if err != nil {
			continue
		}
		for _, ino := range inodes {
			if want[ino] {
				out[ino] = pid
			}
		}
	}
	return out
}

// descendants returns root and every process below it.
func descendants(root int) ([]int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}
	children := map[int][]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat")) // #nosec G304 -- /proc/<pid>/stat, pid from ReadDir (J1 T22, SEC-J0-14 tracking issue (BLOCKED H1))
		if err != nil {
			continue // exited
		}
		// pid (comm) state ppid ...: comm may hold spaces and parentheses.
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(b[i+1:]))
		if len(f) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		children[ppid] = append(children[ppid], pid)
	}
	out := []int{root}
	for i := 0; i < len(out); i++ {
		out = append(out, children[out[i]]...)
	}
	slices.Sort(out[1:])
	return out, nil
}

func readCmdline(dir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "cmdline")) // #nosec G304 -- /proc/<pid>/cmdline of facto's process tree (J1 T22, SEC-J0-14 tracking issue (BLOCKED H1))
	if err != nil {
		return nil, fmt.Errorf("read cmdline: %w", err)
	}
	return strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"), nil
}

// socketInodes lists the socket inodes among a process's descriptors.
func socketInodes(dir string) ([]uint64, error) {
	fdDir := filepath.Join(dir, "fd")
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("read fds: %w", err)
	}
	var out []uint64
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue // closed meanwhile
		}
		if s, ok := strings.CutPrefix(l, "socket:["); ok {
			if ino, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64); err == nil {
				out = append(out, ino)
			}
		}
	}
	return out, nil
}

// listenRow is one LISTEN row of /proc/<pid>/net/tcp{,6}.
type listenRow struct {
	Addr  string // "tcp 0100007F:9A9D"
	Port  uint16
	UID   int
	Inode uint64
}

// listenRows reads every LISTEN row of the network namespace of the
// process in dir.
func listenRows(dir string) ([]listenRow, error) {
	var out []listenRow
	for _, name := range procTCPTables {
		f, err := os.Open(filepath.Join(dir, "net", name)) // #nosec G304 -- /proc/<pid>/net/tcp{,6} of facto's process tree or the test process (J1 T22, SEC-J0-14 tracking issue (BLOCKED H1))
		if err != nil {
			return out, fmt.Errorf("open %s: %w", name, err)
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			// sl local_address rem_address st tx:rx tr:tm retrnsmt uid timeout inode
			if len(fl) < 10 || fl[3] != "0A" {
				continue
			}
			ino, err1 := strconv.ParseUint(fl[9], 10, 64)
			uid, err2 := strconv.Atoi(fl[7])
			_, hexPort, _ := strings.Cut(fl[1], ":")
			port, err3 := strconv.ParseUint(hexPort, 16, 16)
			if err1 != nil || err2 != nil || err3 != nil {
				continue
			}
			out = append(out, listenRow{Addr: name + " " + fl[1], Port: uint16(port), UID: uid, Inode: ino})
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil {
			return out, fmt.Errorf("scan %s: %w", name, err)
		}
	}
	return out, nil
}
