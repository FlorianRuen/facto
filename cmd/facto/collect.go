package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/dest/local"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/store"
)

// Accepted --year range: four-digit calendar years.
const (
	minYear = 1000
	maxYear = 9999
)

// inboxDir is the manual-import folder inside output.local (ADR 0007).
const inboxDir = "inbox"

// collectFlags are the flags of "facto collect".
type collectFlags struct {
	year           int
	config         string
	nonInteractive bool
}

func newCollectCmd(ctx context.Context, e env) *cobra.Command {
	var f collectFlags
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect, rename and file documents (connectors, then inbox/)",
		Long: "Collect the documents of the period from every enabled connector, then file\n" +
			"what was dropped in <output.local>/inbox, and write a report in the state dir.\n" +
			"Without --year the period is the previous calendar year. When stdin is not a\n" +
			"terminal collect never prompts, as with --non-interactive.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			yearSet := cmd.Flags().Changed("year")
			if yearSet && (f.year < minYear || f.year > maxYear) {
				return fmt.Errorf("invalid --year %d: want a year between %d and %d", f.year, minYear, maxYear)
			}
			if f.config == "" {
				p, err := configPathFor(runtimeGOOS, e)
				if err != nil {
					return configError(err)
				}
				f.config = p
			}
			period := connector.PreviousYear(e.Clock)
			if yearSet {
				period = connector.Year(f.year)
			}
			var prompter inbox.Prompter
			if !f.nonInteractive && isTerminal(cmd.InOrStdin()) {
				prompter = newLinePrompter(cmd.InOrStdin(), cmd.ErrOrStderr())
			}
			return collect(ctx, e, collectParams{
				configPath: f.config,
				period:     period,
				prompter:   prompter,
				stdout:     cmd.OutOrStdout(),
				stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	fl := cmd.Flags()
	fl.IntVar(&f.year, "year", 0, "calendar year to collect (default: the previous year)")
	fl.StringVar(&f.config, "config", "", "path to config.yaml (default: the per-OS config directory)")
	fl.BoolVar(&f.nonInteractive, "non-interactive", false, "never prompt (automatic when stdin is not a terminal)")
	return cmd
}

// collectParams are the resolved inputs of one collect run.
type collectParams struct {
	configPath string
	period     connector.Period
	prompter   inbox.Prompter
	stdout     io.Writer
	stderr     io.Writer
}

// collect loads and checks the configuration before touching anything, then
// runs the connectors, ingests the inbox, writes the report in the state dir
// and prints its summary. The returned error is nil or an *exitError.
func collect(ctx context.Context, e env, p collectParams) error {
	cfg, err := config.Load(ctx, p.configPath, config.Options{Home: e.Home})
	if err != nil {
		if ctx.Err() != nil && !errors.Is(err, config.ErrInvalid) {
			// Canceled before the config was read: a failed run, not a
			// configuration error.
			return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("collect: %w", err)}
		}
		return configError(err)
	}
	reg, err := newRegistry(cfg)
	if err != nil {
		return configError(err)
	}
	namer, err := normalize.NewNamer(normalize.Config{File: cfg.Naming.File, Dir: cfg.Naming.Dir, Language: cfg.Naming.Language})
	if err != nil {
		return configError(fmt.Errorf("naming: %w", err))
	}

	log := slog.New(logx.NewHandler(slog.NewTextHandler(p.stderr, &slog.HandlerOptions{Level: slog.LevelWarn}), logx.Options{}))
	if cfg.Output.GDrive.Enabled {
		log.WarnContext(ctx, "output.gdrive is not available in this version: documents are filed locally only")
	}

	report := orchestrator.Report{StartedAt: e.Clock.Now()}
	stateReady, runErr := collectInto(ctx, e, cfg, collectDeps{reg: reg, namer: namer, log: log}, p, &report)
	report.FinishedAt = e.Clock.Now()

	code := orchestrator.ExitCode(report, runErr)
	if runErr != nil {
		writeErr(p.stderr, runErr)
	}
	// The report of a canceled run is still written: it tells the user which
	// connector was interrupted. It needs the state dir, which opening the
	// index creates.
	if stateReady {
		if _, err := orchestrator.WriteReport(context.WithoutCancel(ctx), cfg.StateDir, report); err != nil {
			writeErr(p.stderr, fmt.Errorf("write report: %w", err))
			code = max(code, orchestrator.ExitAttention)
		}
	}
	if _, err := io.WriteString(p.stdout, report.Text()); err != nil {
		writeErr(p.stderr, fmt.Errorf("print report: %w", err))
		code = max(code, orchestrator.ExitAttention)
	}
	if code == orchestrator.ExitOK {
		return nil
	}
	return &exitError{code: code}
}

// collectDeps are what collect builds from the configuration before any
// side effect.
type collectDeps struct {
	reg   *connector.Registry
	namer *normalize.Namer
	log   *slog.Logger
}

// collectInto opens the output folder, the index and the inbox, then fills
// report with the connector run and the inbox ingestion. stateReady reports
// that the state dir exists (opening the index creates it).
func collectInto(ctx context.Context, e env, cfg *config.Config, d collectDeps, p collectParams, report *orchestrator.Report) (stateReady bool, err error) {
	inboxPath := filepath.Join(cfg.Output.Local, inboxDir)
	// output.local may be a symlink (e.g. to a folder synced by Google
	// Drive for desktop, docs/spec.md); inbox/ inside it may not: a link
	// there would make collect move files from anywhere into the output.
	if err := ensureDir(cfg.Output.Local, followLink); err != nil {
		return false, fmt.Errorf("output folder: %w", err)
	}
	if err := ensureDir(inboxPath, noFollowLink); err != nil {
		return false, fmt.Errorf("inbox folder: %w", err)
	}

	idx, err := store.Open(ctx, cfg.StateDir, e.Clock)
	if err != nil {
		return false, fmt.Errorf("open index: %w", err)
	}
	defer func() { err = errors.Join(err, closeErr("index", idx.Close())) }()

	dst, err := local.New(ctx, cfg.Output.Local)
	if err != nil {
		return true, fmt.Errorf("open output folder: %w", err)
	}
	defer func() { err = errors.Join(err, closeErr("output folder", dst.Close())) }()

	orch, err := orchestrator.New(orchestrator.Deps{Index: idx, Dest: dst, Namer: d.namer, Log: d.log})
	if err != nil {
		return true, fmt.Errorf("orchestrator: %w", err)
	}

	res, err := orch.Run(ctx, d.reg, p.period)
	report.AddRun(res)
	if err != nil {
		return true, fmt.Errorf("collect connectors: %w", err)
	}

	ib, err := inbox.New(inboxPath, inbox.Options{Prompter: p.prompter, Providers: providerDefaults(cfg)})
	if err != nil {
		return true, fmt.Errorf("open inbox: %w", err)
	}
	defer func() { err = errors.Join(err, closeErr("inbox", ib.Close())) }()

	in, err := orch.IngestInbox(ctx, ib)
	report.Documents = append(report.Documents, in.Documents...)
	report.Warnings = append(report.Warnings, in.Warnings...)
	if err != nil {
		return true, fmt.Errorf("ingest inbox: %w", err)
	}
	return true, nil
}

// configError reports a configuration error (exit 2) wrapping
// orchestrator.ErrConfig and err. Config errors name the key at fault and
// never quote a value (package config).
func configError(err error) error {
	return &exitError{code: orchestrator.ExitConfig, err: &configLoadError{err: err}}
}

// configLoadError is a configuration failure: errors.Is matches both
// orchestrator.ErrConfig and the cause, the message is the cause's.
type configLoadError struct{ err error }

func (e *configLoadError) Error() string { return "configuration error: " + e.err.Error() }

func (e *configLoadError) Unwrap() []error { return []error{orchestrator.ErrConfig, e.err} }

// closeErr wraps a Close error with what was closed; nil stays nil.
func closeErr(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close %s: %w", what, err)
}

// newRegistry returns the connectors enabled in cfg. No supplier connector
// ships in this version, so an enabled one is a configuration error rather
// than a silently skipped account.
func newRegistry(cfg *config.Config) (*connector.Registry, error) {
	var enabled []string
	for id, c := range cfg.Connectors {
		if c.Enabled {
			enabled = append(enabled, id)
		}
	}
	if len(enabled) > 0 {
		slices.Sort(enabled)
		return nil, fmt.Errorf("connectors.%s: connector not available in this version (set enabled: false)", enabled[0])
	}
	return connector.NewRegistry(), nil
}

// providerDefaults maps every provider id of the config ("manual:" entries
// and "connectors:" accounts) to its category for the inbox. A connector
// category, when set, wins over a manual entry of the same id.
func providerDefaults(cfg *config.Config) map[string]inbox.ProviderDefaults {
	out := make(map[string]inbox.ProviderDefaults, len(cfg.Manual)+len(cfg.Connectors))
	for _, m := range cfg.Manual {
		out[m.ID] = inbox.ProviderDefaults{Category: m.Category}
	}
	for id, c := range cfg.Connectors {
		if c.Category != "" {
			out[id] = inbox.ProviderDefaults{Category: c.Category}
		}
	}
	return out
}

// linkPolicy says whether ensureDir accepts dir being a symlink to a
// directory.
type linkPolicy bool

const (
	followLink   linkPolicy = true  // dir may be a symlink to a directory
	noFollowLink linkPolicy = false // dir must be a real directory
)

// ensureDir creates dir 0700 through fsx when it does not exist; its parent
// must exist. An existing directory is used as it is: the user's output
// folder may legitimately be shared with other programs. With followLink a
// symlink to a directory is accepted (fsx and local.New then confine
// everything under its target); a dangling one is not created through. With
// noFollowLink any symlink is refused with fsx.ErrNotDir.
func ensureDir(dir string, links linkPolicy) error {
	stat := os.Lstat
	if links == followLink {
		stat = os.Stat
	}
	fi, err := stat(dir)
	switch {
	case err == nil && fi.IsDir():
		return nil
	case err == nil:
		return fmt.Errorf("%s: %w", dir, fsx.ErrNotDir)
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("stat: %w", err)
	}
	root, err := fsx.Open(filepath.Dir(dir))
	if err != nil {
		return fmt.Errorf("open parent: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirPrivate(filepath.Base(dir)); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return nil
}

// isTerminal reports whether r is a character device other than the null
// device, i.e. an interactive terminal. Pipes, files, in-memory readers and
// the /dev/null stdin of schedulers are not.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err == nil && !os.SameFile(fi, null)
}
