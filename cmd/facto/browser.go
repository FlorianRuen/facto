package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

// browserSubdir is where "facto browser install" puts Chrome for Testing
// inside the state dir by default.
const browserSubdir = "chrome"

// errUnpinnedPlatform reports a platform without a pinned Chrome for
// Testing build (J1 pins linux64 only, decision A10).
var errUnpinnedPlatform = errors.New("no pinned Chrome for Testing build for this platform (linux64 only): set the browser path in the configuration instead")

// browserFlags are the flags of "facto browser install".
type browserFlags struct {
	dir    string
	config string
}

// newBrowserCmd builds "facto browser" and its "install" subcommand.
func newBrowserCmd(ctx context.Context, e env) *cobra.Command {
	browser := &cobra.Command{
		Use:   "browser",
		Short: "Manage the pinned Chrome for Testing build facto drives",
		Args:  cobra.NoArgs,
	}
	var f browserFlags
	install := &cobra.Command{
		Use:   "install",
		Short: "Download, verify and unpack the pinned Chrome for Testing build (linux64)",
		Long: "Download the Chrome for Testing build pinned in this facto release (exact URL,\n" +
			"size and SHA-256), refuse it unless both match, and unpack it into a private\n" +
			"directory: <state_dir>/chrome by default. facto never downloads a browser on\n" +
			"its own: this command is the only way. Running it again with a verified\n" +
			"install does nothing. It never prompts.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return browserInstall(ctx, e, f, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	fl := install.Flags()
	fl.StringVar(&f.dir, "dir", "", "install directory (default: <state_dir>/"+browserSubdir+")")
	fl.StringVar(&f.config, "config", "", "path to config.yaml, read for state_dir (default: the per-OS config directory)")
	browser.AddCommand(install)
	return browser
}

// browserInstall installs cft.Pinned() into the resolved directory and
// prints the executable path. The returned error is nil or an *exitError.
func browserInstall(ctx context.Context, e env, f browserFlags, stdout, stderr io.Writer) error {
	dir, err := browserDir(ctx, e, f)
	if err != nil {
		return err
	}
	if err := ensureDir(dir, noFollowLink); err != nil {
		return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("browser directory: %w", err)}
	}
	log := slog.New(logx.NewHandler(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}), logx.Options{}))
	m := cft.Pinned()
	installBrowser := e.InstallBrowser
	if installBrowser == nil {
		installBrowser = installPinnedBrowser
	}
	exe, err := installBrowser(ctx, cft.Options{Manifest: m, Dir: dir, Log: log})
	if err != nil {
		return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("browser install: %w", err)}
	}
	cft.WarnIfStale(ctx, log, e.Clock, m)
	if _, err := fmt.Fprintf(stdout, "Chrome for Testing %s installed: %s\n", m.Version, exe); err != nil {
		return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("print result: %w", err)}
	}
	return nil
}

// browserDir resolves the install directory: --dir (made absolute), else
// <state_dir>/chrome with state_dir read from the configuration. Without
// --config and without a config file, the default state dir (~/.facto) is
// used, so a browser can be installed before facto is configured.
func browserDir(ctx context.Context, e env, f browserFlags) (string, error) {
	if f.dir != "" {
		dir, err := filepath.Abs(f.dir)
		if err != nil {
			return "", configError(fmt.Errorf("--dir: %w", err))
		}
		return dir, nil
	}
	explicit := f.config != ""
	path := f.config
	if !explicit {
		p, err := configPathFor(runtimeGOOS, e)
		if err != nil {
			return "", configError(err)
		}
		path = p
	}
	cfg, err := config.Load(ctx, path, config.Options{Home: e.Home})
	var state string
	switch {
	case err == nil:
		state = cfg.StateDir
	case !explicit && errors.Is(err, fs.ErrNotExist) && e.Home != "":
		state = filepath.Join(e.Home, strings.TrimPrefix(config.DefaultStateDir, "~/"))
	default:
		return "", configError(err)
	}
	if err := ensureDir(state, noFollowLink); err != nil {
		return "", &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("state dir: %w", err)}
	}
	return filepath.Join(state, browserSubdir), nil
}

// installPinnedBrowser is the production installer: linux64 only.
func installPinnedBrowser(ctx context.Context, opts cft.Options) (string, error) {
	if runtimeGOOS != "linux" || runtime.GOARCH != "amd64" {
		return "", errUnpinnedPlatform
	}
	in, err := cft.New(opts)
	if err != nil {
		return "", fmt.Errorf("prepare: %w", err)
	}
	exe, err := in.Install(ctx)
	if err != nil {
		return "", fmt.Errorf("install: %w", err)
	}
	return exe, nil
}
