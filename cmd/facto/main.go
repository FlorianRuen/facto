// Command facto collects supplier invoices, renames them and files them
// locally (docs/spec.md "Configuration, commands and scheduling").
//
// This package only wires internal packages together: main calls run, run
// hardens the process and calls runEnv with the real home, environment and
// clock, and runEnv maps every outcome to the exit codes of the spec (0 all
// ok, 1 attention needed or run failed, 2 configuration or usage error).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/proc"
	"github.com/FlorianRuen/facto/internal/vault"
)

// version is the release version, set with -ldflags "-X main.version=…".
var version = "dev"

// env is what runEnv takes from the process: tests inject a sandbox home,
// a fake clock and an empty environment.
type env struct {
	// Home is the absolute user home directory ("~" in config.yaml and the
	// default config path).
	Home string
	// Clock dates the run and its report.
	Clock clock.Clock
	// LookupEnv reads one environment variable (os.LookupEnv in production).
	LookupEnv func(string) (string, bool)
	// NewSecrets builds the run's secret resolver; nil means
	// newSecretResolver. Test seam.
	NewSecrets func(ctx context.Context, e env, cfg *config.Config) (secretResolver, error)
	// Terminal is the controlling-terminal seam; nil = the OS terminal
	// (isTerminal and a termios/console no-echo read).
	Terminal terminal
	// KeyBackend returns the session key backend; nil = the OS keyring,
	// probed once (defaultKeyBackend). An error means "no keyring": sessions
	// are ephemeral for the run, with one warning (A3).
	KeyBackend func(ctx context.Context, e env) (vault.KeyBackend, error)
	// NewPool builds the run's browser pool; nil = newBrowserPool.
	NewPool func(ctx context.Context, e env, p poolParams) (browserPool, error)
	// Connectors returns every connector this build ships; nil =
	// availableConnectors.
	Connectors func() (*connector.Registry, error)
	// InstalledBrowser returns the Chrome installed by `facto browser
	// install` under the configured state dir; nil = installedBrowser.
	InstalledBrowser func(e env, stateDir string) (string, bool)
	// InstallBrowser installs the Chrome for Testing build of opts and
	// returns the executable path; nil means installPinnedBrowser (real
	// download). Test seam: CLI tests never touch the network.
	InstallBrowser func(ctx context.Context, opts cft.Options) (string, error)
}

// terminal returns e.Terminal, or the OS terminal.
func (e env) terminal() terminal {
	if e.Terminal != nil {
		return e.Terminal
	}
	return &osTerminal{}
}

// lookupEnv returns the value of the environment variable k, "" when it is
// unset or e.LookupEnv is nil.
func (e env) lookupEnv(k string) string {
	if e.LookupEnv == nil {
		return ""
	}
	v, _ := e.LookupEnv(k)
	return v
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals()...)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// shutdownSignals cancel a run: Ctrl-C, SIGTERM sent by service managers
// (systemd stop, launchd unload), and SIGHUP when the terminal is closed,
// so that a prompt waiting with echo off turns it back on before facto
// exits. On Windows the runtime never delivers SIGTERM or SIGHUP; listing
// them is harmless.
func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}

// run is the production entry point: it hardens the process (no core dump,
// no ptrace by other users' processes), then runs args against the real
// home directory, environment and clock.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if err := proc.Harden(); err != nil {
		writeErr(stderr, fmt.Errorf("harden process: %w", err))
		return orchestrator.ExitAttention
	}
	home, err := os.UserHomeDir()
	if err != nil {
		writeErr(stderr, fmt.Errorf("home directory: %w", err))
		return orchestrator.ExitConfig
	}
	return runEnv(ctx, env{Home: home, Clock: clock.Real{}, LookupEnv: os.LookupEnv}, args, stdin, stdout, stderr)
}

// exitError carries the exit code of a command that ran: any other error
// returned by cobra is a usage error (unknown command or flag, bad flag
// value) and exits ExitConfig.
type exitError struct {
	code int
	err  error // nil when the cause was already reported
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit code %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

// runEnv runs args with the injected environment and returns the exit code.
func runEnv(ctx context.Context, e env, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRootCmd(ctx, e, stdin, stdout, stderr)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return orchestrator.ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			writeErr(stderr, ee.err)
		}
		return ee.code
	}
	writeErr(stderr, err)
	_, _ = fmt.Fprintln(stderr, "Run 'facto --help' for usage.")
	return orchestrator.ExitConfig
}

// writeErr prints err on stderr, one "facto: " line per line of its
// message. Errors carry untrusted text (inbox file names repeated raw by
// *fs.PathError, config values, cobra echoing argv), so the message first
// goes through logx.Clean, the pattern masking of the redacting logger, then
// each line through logx.Escape: no control or format character reaches the
// terminal, and a line break inside an error cannot forge an unprefixed line
// (SEC-J0-19).
func writeErr(stderr io.Writer, err error) {
	var b strings.Builder
	for _, line := range strings.Split(logx.Clean(err.Error()), "\n") {
		b.WriteString("facto: " + logx.Escape(line) + "\n")
	}
	_, _ = io.WriteString(stderr, b.String())
}

// newRootCmd builds the command tree on the injected I/O. Cobra never
// prints errors or usage itself: runEnv does, on stderr.
func newRootCmd(ctx context.Context, e env, stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "facto",
		Short:         "Collect, rename and file supplier invoices",
		SilenceErrors: true,
		SilenceUsage:  true,
		// No Args validator: cobra then reports an unknown subcommand as
		// an error instead of printing the help.
	}
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newVersionCmd(), newCollectCmd(ctx, e), newLoginCmd(ctx, e), newBrowserCmd(ctx, e))
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the facto version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "facto %s (%s %s/%s)\n",
				version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			if err != nil {
				return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("write version: %w", err)}
			}
			return nil
		},
	}
}
