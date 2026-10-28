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

	"github.com/spf13/cobra"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/proc"
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
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
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

// writeErr prints err on stderr, prefixed with the program name.
func writeErr(stderr io.Writer, err error) {
	_, _ = fmt.Fprintf(stderr, "facto: %v\n", err)
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
	root.AddCommand(newVersionCmd(), newCollectCmd(ctx, e))
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
