package browser

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// MaxStderrBytes caps how much of Chrome's stderr Launch keeps in memory.
// The rest is drained and counted, never stored.
const MaxStderrBytes = 64 << 10

// noSandboxMarker is what Chrome prints when it cannot start its sandbox
// (for example Ubuntu 23.10+ with AppArmor restricting unprivileged user
// namespaces).
const noSandboxMarker = "No usable sandbox"

// noSandboxFix names the fix outside facto. It never quotes Chrome's output.
const noSandboxFix = "unprivileged user namespaces are restricted (AppArmor on Ubuntu 23.10+); " +
	"fix it outside facto: install an AppArmor profile allowing user namespaces for the Chrome binary, " +
	"or install the SUID chrome_sandbox helper with sudo (owner root, mode 4755); " +
	"facto never disables the sandbox"

// Host is what Prepare and Launch read from the machine, injected.
type Host struct {
	Executable string                      // absolute path to Chrome
	Geteuid    func() int                  // os.Geteuid in production; -1 on windows
	LookupEnv  func(string) (string, bool) // os.LookupEnv in production
	Log        *slog.Logger                // redacting logger; nil discards
	// Owner returns the owner uid of an already resolved path (unix). Nil:
	// a stat-based lookup. Used by Prepare (CheckExecutableAs with
	// Geteuid()) and by NewPool (base directories). An error fails closed.
	Owner func(path string) (uid int, err error)
}

// owner returns h.Owner, or the stat-based lookup when nil.
func (h Host) owner() func(string) (int, error) {
	if h.Owner != nil {
		return h.Owner
	}
	return statOwner
}

// Command is one vetted Chrome invocation.
type Command struct {
	Path   string
	Args   []string
	Env    []string
	Stderr io.Writer // set by Launch: capped at MaxStderrBytes, never logged verbatim

	// checkArgs, when non-nil, is the argv check a Starter that re-vets
	// Args (the windows port Starter) uses instead of the release
	// CheckFlags. Only prepareWith sets it, from an argvPolicy, which only
	// the e2e build constructs.
	checkArgs func(args []string) error
}

// StartFunc starts Chrome (exec and transport, T7). It must write Chrome's
// stderr to cmd.Stderr, which never blocks and never fails.
type StartFunc func(ctx context.Context, cmd Command) error

// Prepare vets the host and options and returns the Command to start, with
// a nil Stderr: root check first, then CheckExecutableAs (owner checked
// against h.Geteuid() through h.Owner), Flags, CheckFlags and BuildEnv.
func Prepare(h Host, opts Options) (Command, error) {
	return prepareWith(h, opts, nil)
}

// argvPolicy builds and vets Chrome's argv in place of Flags and
// CheckFlags. Only the e2e build constructs one (WithE2E).
type argvPolicy struct {
	build func(opts Options) ([]string, error)
	check func(opts Options, args []string) error
}

// prepareWith is Prepare with the argv built and vetted by policy, or by
// Flags and CheckFlags when policy is nil.
func prepareWith(h Host, opts Options, policy *argvPolicy) (Command, error) {
	build := Flags
	check := func(o Options, args []string) error { return CheckFlags(o.GOOS, args) }
	if policy != nil {
		build, check = policy.build, policy.check
	}
	if h.Geteuid == nil {
		return Command{}, fmt.Errorf("%w: effective uid unknown", ErrRunAsRoot)
	}
	euid := h.Geteuid()
	if euid == 0 {
		return Command{}, ErrRunAsRoot
	}
	if err := CheckExecutableAs(h.Executable, euid, h.owner()); err != nil {
		return Command{}, err
	}
	args, err := build(opts)
	if err != nil {
		return Command{}, err
	}
	if err := check(opts, args); err != nil {
		return Command{}, err
	}
	env, err := launchEnv(h.LookupEnv, opts)
	if err != nil {
		return Command{}, err
	}
	cmd := Command{Path: h.Executable, Args: args, Env: env}
	if policy != nil {
		cmd.checkArgs = func(a []string) error { return policy.check(opts, a) }
	}
	return cmd, nil
}

// launchEnv returns Chrome's environment for opts: BuildLaunchEnv over the
// private dirs, each vetted like ProfileDir (ErrNoProfileDir), then the
// SingletonSocket length check (ErrSocketPathTooLong).
func launchEnv(lookup func(string) (string, bool), opts Options) ([]string, error) {
	goos, err := resolveGOOS(opts.GOOS)
	if err != nil {
		return nil, err
	}
	for _, d := range []string{opts.privateDir, opts.tempDir} {
		if d == "" {
			continue
		}
		if err := checkProfileDir(goos, d); err != nil {
			return nil, fmt.Errorf("private launch dir: %w", err)
		}
	}
	env := BuildLaunchEnv(lookup, opts.privateDir, opts.tempDir)
	if err := checkSocketPath(goos, env); err != nil {
		return nil, err
	}
	return env, nil
}

// Launch prepares the Command and starts it exactly once: a failure is
// never retried, least of all with weaker flags. On failure the captured
// stderr is classified (ErrNoUsableSandbox or ErrLaunchFailed, wrapping
// start's error) and only a summary is logged: byte count and class.
func Launch(ctx context.Context, h Host, opts Options, start StartFunc) error {
	cmd, err := Prepare(h, opts)
	if err != nil {
		return err
	}
	if start == nil {
		return fmt.Errorf("%w: no start function", ErrLaunchFailed)
	}
	stderr := &capWriter{max: MaxStderrBytes}
	cmd.Stderr = stderr
	serr := start(ctx, cmd)
	if serr == nil {
		return nil
	}
	total, sandbox := stderr.summary()
	class := "other"
	if sandbox {
		class = "no_usable_sandbox"
	}
	logger(h.Log).WarnContext(ctx, "browser: chrome launch failed",
		slog.Int64("stderr_bytes", total), slog.String("class", class))
	if sandbox {
		return fmt.Errorf("%w: %s: %w", ErrNoUsableSandbox, noSandboxFix, serr)
	}
	return fmt.Errorf("%w: %w", ErrLaunchFailed, serr)
}

func logger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.New(slog.DiscardHandler)
	}
	return l
}

// capWriter keeps the first max bytes of Chrome's stderr, counts the rest
// and always reports a full write, so Chrome never blocks on a full pipe.
// It is safe for concurrent use (os/exec copies from its own goroutine).
type capWriter struct {
	mu    sync.Mutex
	max   int
	buf   []byte
	total int64
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += int64(len(p))
	if room := w.max - len(w.buf); room > 0 {
		w.buf = append(w.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// summary returns the byte count and whether the kept part reports the
// missing sandbox.
func (w *capWriter) summary() (int64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.total, bytes.Contains(w.buf, []byte(noSandboxMarker))
}
