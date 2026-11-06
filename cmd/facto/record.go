package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/har"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/record"
)

// `facto record` (docs/spec.md "facto record"): opens the hardened login
// browser (pipe, disposable 0700 profile, in-browser allowlist, J1), lets
// the user log in and reach the invoices by hand, and writes a HAR with
// no password, cookie value, Authorization header or token (internal/har).
// It never reads a secret reference, never saves a session, and refuses to
// write inside a git work tree or a synced folder.

// recordFlags are the flags of "facto record".
type recordFlags struct {
	config         string
	out            string
	allow          []string
	static         []string
	connector      string
	until          string
	timeout        time.Duration
	force          bool
	nonInteractive bool
}

// Errors of facto record (usage errors, exit 2).
var (
	errRecordNoTerminal = errors.New("facto record needs an interactive terminal (the browser window is for you to log in)")
	errRecordOut        = errors.New("--out: want a path ending in .har")
	errRecordInRepo     = errors.New("--out: inside a git work tree: recordings hold personal data and stay outside the repository (sanitized fixtures go to testdata/ through scripts/harslim and scripts/fixtures)")
	errRecordSynced     = errors.New("--out: inside a folder a sync client uploads: keep recordings local")
	errRecordExists     = errors.New("--out: file exists (pass --force to replace it)")
	errRecordAllow      = errors.New("no allowed domain: pass --allow <domain> (repeatable) or --connector <id>")
	errRecordURL        = errors.New("url: want an absolute https url on an allowed domain, port 443, no user info")
)

// defaultRecordTimeout bounds one recording.
const defaultRecordTimeout = 30 * time.Minute

func newRecordCmd(ctx context.Context, e env) *cobra.Command {
	var f recordFlags
	cmd := &cobra.Command{
		Use:   "record <https-url>",
		Short: "Record a redacted HAR of a supplier site, to write a connector",
		Long: "Open the hardened login browser on <https-url> (a visible window, its own\n" +
			"disposable profile, only the allowed domains reachable), let you log in and\n" +
			"browse to your invoices by hand, then write what the page loaded as a HAR\n" +
			"file. Passwords, login identifiers sent in forms, cookie values,\n" +
			"Authorization headers, tokens and PDF bodies are removed before anything is\n" +
			"written. Personal data in pages (names, addresses, contract numbers) is not:\n" +
			"keep the file private, outside any repository, and turn it into fixtures\n" +
			"with scripts/harslim and scripts/fixtures/sanitize.sh.\n\n" +
			"The recording stops when you press Enter in this terminal, close the\n" +
			"browser window, the --until selector shows, or --timeout elapses.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prompt := newPrompter(e, cmd.InOrStdin(), cmd.ErrOrStderr(), f.nonInteractive)
			if !prompt.Interactive() {
				return &exitError{code: orchestrator.ExitConfig, err: errRecordNoTerminal}
			}
			if f.config == "" {
				p, err := configPathFor(runtimeGOOS, e)
				if err != nil {
					return configError(err)
				}
				f.config = p
			}
			return recordRun(ctx, e, f, args[0], cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.out, "out", "o", "", "HAR file to write (required; must end in .har, outside any git work tree)")
	fl.StringSliceVar(&f.allow, "allow", nil, "allowed domain (repeatable; same syntax as a connector's allowed domains, e.g. www.example.fr, *.example.fr)")
	fl.StringSliceVar(&f.static, "allow-static", nil, "allow GET of app files under one exact https path prefix of a shared host, e.g. https://storage.googleapis.com/<bucket>/ (repeatable; never navigable, never sent data)")
	fl.StringVar(&f.connector, "connector", "", "use the allowed domains of this shipped connector")
	fl.StringVar(&f.until, "until", "", "CSS selector: stop once it is visible (default: Enter or window closed)")
	fl.DurationVar(&f.timeout, "timeout", defaultRecordTimeout, "stop after this long")
	fl.BoolVar(&f.force, "force", false, "replace --out if it exists")
	fl.StringVar(&f.config, "config", "", "path to config.yaml, read for state_dir and browser.path (default: the per-OS config directory; optional)")
	fl.BoolVar(&f.nonInteractive, "non-interactive", false, "refuse to prompt (record then fails: it needs a terminal)")
	return cmd
}

// recordConfig loads config.yaml when it exists; a missing file gives the
// defaults (record needs no connector configured).
func recordConfig(ctx context.Context, e env, path string) (*config.Config, error) {
	cfg, err := config.Load(ctx, path, config.Options{Home: e.Home})
	if errors.Is(err, os.ErrNotExist) {
		cfg, err = config.Parse(nil, config.Options{Home: e.Home})
	}
	if err != nil {
		return nil, configError(err)
	}
	return cfg, nil
}

func recordRun(ctx context.Context, e env, f recordFlags, rawURL string, stdin io.Reader, stdout, stderr io.Writer) error {
	usage := func(err error) error {
		return &exitError{code: orchestrator.ExitConfig, err: fmt.Errorf("record: %w", err)}
	}
	out, err := recordOutPath(f.out, e.Home, f.force)
	if err != nil {
		return usage(err)
	}
	domains, err := recordDomains(e, f)
	if err != nil {
		return usage(err)
	}
	static, err := recordStatic(e, f)
	if err != nil {
		return usage(err)
	}
	if err := checkRecordURL(rawURL, domains); err != nil {
		return usage(err)
	}
	if f.timeout <= 0 {
		return usage(errors.New("--timeout: want a positive duration"))
	}
	cfg, err := recordConfig(ctx, e, f.config)
	if err != nil {
		return err
	}
	hooks, err := loadRunHooks(e)
	if err != nil {
		return err
	}
	exe, err := resolveBrowserPath(cfg, installedWith(e, cfg.StateDir, hooks))
	if err != nil {
		return configError(err)
	}
	log := slog.New(logx.NewHandler(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}), logx.Options{}))
	warnIfStalePin(ctx, e, cfg, exe, log)
	if err := prepareStateDir(cfg); err != nil {
		return configError(err)
	}

	file, err := recordWith(ctx, e, cfg, recordDeps{
		url: rawURL, domains: domains, static: static, until: f.until, timeout: f.timeout,
		exe: exe, hooks: hooks, log: log, stdin: stdin, stderr: stderr,
	})
	if err != nil {
		return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("record: %w", err)}
	}
	if findings := har.Check(file); len(findings) > 0 {
		// Never reached: every entry went through RedactEntry. Fail closed.
		return &exitError{code: orchestrator.ExitAttention, err: errors.New("record: redaction check failed, nothing written")}
	}
	if err := writeRecording(ctx, out, file); err != nil {
		return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("record: write: %w", err)}
	}
	msg := fmt.Sprintf("record: wrote %s (%s, redacted)\n", out, record.Summary(file))
	if file.Log.Comment != "" {
		msg += "record: note: " + file.Log.Comment + "\n"
	}
	msg += "record: it still holds personal data: keep it private, never commit it; next: go run ./scripts/harslim\n"
	if _, err := io.WriteString(stdout, msg); err != nil {
		return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("print result: %w", err)}
	}
	return nil
}

// recordDeps are the resolved inputs of one recording.
type recordDeps struct {
	url, until string
	domains    []string
	static     []string
	timeout    time.Duration
	exe        string
	hooks      runHooks
	log        *slog.Logger
	stdin      io.Reader
	stderr     io.Writer
}

// recordWith launches a visible browser, taps its page, navigates and
// records until the stop condition. The browser and the pool are closed
// (profile removed) before it returns.
func recordWith(ctx context.Context, e env, cfg *config.Config, d recordDeps) (file *har.File, err error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	pool, err := buildPool(ctx, e, poolParams{StateDir: cfg.StateDir, Executable: d.exe, Interactive: true, Log: d.log, Configure: d.hooks.Pool})
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, closeErr("browser pool", pool.Close())) }()
	b, err := pool.Launch(ctx, connector.LaunchOptions{AllowedDomains: d.domains, Static: d.static, Visible: !d.hooks.Headless})
	if err != nil {
		return nil, fmt.Errorf("launch browser: %w", err)
	}
	defer func() { err = errors.Join(err, closeErr("browser", b.Close())) }()
	tapper, ok := b.(interface {
		Tap(ctx context.Context) (*browser.NetworkTap, error)
		Done() <-chan struct{}
	})
	if !ok {
		return nil, errors.New("this browser cannot record")
	}
	tap, err := tapper.Tap(ctx)
	if err != nil {
		return nil, fmt.Errorf("record network: %w", err)
	}
	defer tap.Close()

	rec := record.New(record.Options{Clock: e.Clock, Version: version})
	recCtx, stopRec := context.WithCancel(ctx)
	defer stopRec()
	done := make(chan *har.File, 1)
	go func() { done <- rec.Run(recCtx, tap) }()

	if err := b.Navigate(ctx, d.url); err != nil {
		stopRec()
		<-done
		return nil, fmt.Errorf("open the page: %w", err)
	}
	_, _ = io.WriteString(d.stderr, recordBanner(d.until))
	reason := waitRecordStop(ctx, b, tapper.Done(), d)
	_, _ = io.WriteString(d.stderr, "record: stopping ("+reason+")\n")
	if d.until != "" && reason == "selector visible" {
		// Let the responses of the page that just showed finish.
		settle(ctx, recordSettle)
	}
	stopRec()
	return <-done, nil
}

// recordSettle is how long the recorder keeps reading after the --until
// selector showed.
const recordSettle = 2 * time.Second

func settle(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func recordBanner(until string) string {
	s := "record: log in and browse to your invoices in the browser window (open one invoice PDF).\n"
	if until != "" {
		return s + "record: the recording stops once the --until selector is visible, or when you press Enter here.\n"
	}
	return s + "record: press Enter here (or close the window) to stop and write the file.\n"
}

// waitRecordStop blocks until Enter on stdin (or its end), the browser
// window closes, the --until selector is visible, or ctx ends.
func waitRecordStop(ctx context.Context, b connector.Browser, closed <-chan struct{}, d recordDeps) string {
	enter := make(chan struct{})
	go func() {
		r := bufio.NewReader(d.stdin)
		_, _ = r.ReadString('\n')
		close(enter)
	}()
	visible := make(chan struct{})
	if d.until != "" {
		go func() {
			if b.WaitVisible(ctx, d.until) == nil {
				close(visible)
			}
		}()
	}
	select {
	case <-enter:
		return "enter pressed"
	case <-closed:
		return "browser closed"
	case <-visible:
		return "selector visible"
	case <-ctx.Done():
		return "timeout"
	}
}

// recordDomains returns --allow, or the shipped connector's domains.
func recordDomains(e env, f recordFlags) ([]string, error) {
	var domains []string
	if f.connector != "" {
		shipped, err := shippedConnectors(e)
		if err != nil {
			return nil, fmt.Errorf("connectors: %w", err)
		}
		c, ok := shipped.Get(f.connector)
		if !ok {
			return nil, fmt.Errorf("--connector: %s is not available in this version", fsx.SafeName(f.connector))
		}
		domains = append(domains, c.Info().AllowedDomains...)
	}
	for _, a := range f.allow {
		if a = strings.TrimSpace(a); a != "" {
			domains = append(domains, strings.ToLower(a))
		}
	}
	if len(domains) == 0 {
		return nil, errRecordAllow
	}
	if _, err := httpx.ParseAllowlist(domains); err != nil {
		return nil, fmt.Errorf("--allow: %w", err)
	}
	return domains, nil
}

// recordStatic returns the shipped connector's BrowserStatic, then
// --allow-static, validated like the browser does (browser.ParseStatic).
func recordStatic(e env, f recordFlags) ([]string, error) {
	var out []string
	if f.connector != "" {
		shipped, err := shippedConnectors(e)
		if err != nil {
			return nil, fmt.Errorf("connectors: %w", err)
		}
		if c, ok := shipped.Get(f.connector); ok {
			out = append(out, c.Info().BrowserStatic...)
		}
	}
	for _, s := range f.static {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if _, err := browser.ParseStatic(out); err != nil {
		return nil, fmt.Errorf("--allow-static: %w", err)
	}
	return out, nil
}

// checkRecordURL applies the browser Navigate rules early, so a bad URL is
// a usage error before any browser starts. The error never quotes it.
func checkRecordURL(raw string, domains []string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return errRecordURL
	}
	if p := u.Port(); p != "" && p != "443" {
		return errRecordURL
	}
	allow, err := httpx.ParseAllowlist(domains)
	if err != nil || !allow.Allows(u.Hostname()) {
		return errRecordURL
	}
	return nil
}

// recordOutPath checks --out: absolute after cleaning, ends in .har, its
// directory exists, outside any git work tree and any synced folder, and
// not an existing file unless force (never a symlink).
func recordOutPath(out, home string, force bool) (string, error) {
	if out == "" || !strings.EqualFold(filepath.Ext(out), ".har") {
		return "", errRecordOut
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", errRecordOut
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", fmt.Errorf("--out: directory: %w", err)
	}
	abs = filepath.Join(dir, filepath.Base(abs))
	if inGitWorkTree(dir) {
		return "", errRecordInRepo
	}
	if config.SyncedFolder(dir, home) {
		return "", errRecordSynced
	}
	fi, err := os.Lstat(abs)
	switch {
	case err == nil && !fi.Mode().IsRegular():
		return "", fmt.Errorf("--out: %w", fsx.ErrNotRegular)
	case err == nil && !force:
		return "", errRecordExists
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("--out: %w", err)
	}
	return abs, nil
}

// inGitWorkTree reports whether dir or one of its ancestors holds a .git
// entry (directory, or file for worktrees and submodules).
func inGitWorkTree(dir string) bool {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return true
		}
		if filepath.Dir(d) == d {
			return false
		}
	}
}

// writeRecording writes the file atomically, 0600, through fsx.
func writeRecording(ctx context.Context, path string, f *har.File) error {
	var buf bytes.Buffer
	if err := har.Encode(&buf, f); err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	root, err := fsx.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(ctx, filepath.Base(path), buf.Bytes()); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}
