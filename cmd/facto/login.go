package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/vault"
)

// errNotInteractive reports `facto login` without a person at a terminal.
var errNotInteractive = errors.New("facto login needs an interactive terminal (stdin is not a terminal, or --non-interactive was given)")

// loginFlags are the flags of "facto login".
type loginFlags struct {
	config         string
	nonInteractive bool
}

func newLoginCmd(ctx context.Context, e env) *cobra.Command {
	var f loginFlags
	cmd := &cobra.Command{
		Use:   "login <connector-id>",
		Short: "Log in to one supplier interactively and save its session",
		Long: "Log in to the supplier of one configured connector, in a visible browser\n" +
			"window when the connector needs one, asking for one-time codes on the\n" +
			"terminal, and save the session (encrypted) for the next collect runs.\n" +
			"It needs an interactive terminal.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prompt := newPrompter(e, cmd.InOrStdin(), cmd.ErrOrStderr(), f.nonInteractive)
			if !prompt.Interactive() {
				return &exitError{code: orchestrator.ExitConfig, err: errNotInteractive}
			}
			if f.config == "" {
				p, err := configPathFor(runtimeGOOS, e)
				if err != nil {
					return configError(err)
				}
				f.config = p
			}
			return login(ctx, e, loginParams{
				id:         args[0],
				configPath: f.config,
				prompt:     prompt,
				stdout:     cmd.OutOrStdout(),
				stderr:     cmd.ErrOrStderr(),
			})
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.config, "config", "", "path to config.yaml (default: the per-OS config directory)")
	fl.BoolVar(&f.nonInteractive, "non-interactive", false, "refuse to prompt (login then fails: it needs a terminal)")
	return cmd
}

// loginParams are the resolved inputs of one login.
type loginParams struct {
	id         string
	configPath string
	prompt     connector.Prompter
	stdout     io.Writer
	stderr     io.Writer
}

// login checks the configuration, the connector id and the browser before
// building anything, then runs one fresh interactive Login of the
// connector and saves its session. The returned error is nil or an
// *exitError.
func login(ctx context.Context, e env, p loginParams) error {
	cfg, err := config.Load(ctx, p.configPath, config.Options{Home: e.Home})
	if err != nil {
		if ctx.Err() != nil && !errors.Is(err, config.ErrInvalid) {
			return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("login: %w", err)}
		}
		return configError(err)
	}
	conn, err := loginConnector(e, cfg, p.id)
	if err != nil {
		return err
	}
	exe, err := resolveBrowserPath(cfg, installedFor(e, cfg.StateDir))
	if err != nil {
		return configError(err)
	}

	newSecrets := e.NewSecrets
	if newSecrets == nil {
		newSecrets = newSecretResolver
	}
	secrets, err := newSecrets(ctx, e, cfg)
	if err != nil {
		return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("secrets: %w", err)}
	}
	log := slog.New(logx.NewHandler(slog.NewTextHandler(p.stderr, &slog.HandlerOptions{Level: slog.LevelWarn}), logx.Options{}))
	warnIfStalePin(ctx, e, cfg, exe, log)

	res, persistent, runErr := loginWith(ctx, e, cfg, loginDeps{conn: conn, secrets: secrets, log: log, browserPath: exe, prompt: p.prompt})
	if cerr := closeErr("secrets", secrets.CloseAll()); cerr != nil {
		runErr = errors.Join(runErr, cerr)
	}
	if runErr != nil {
		code := orchestrator.ExitAttention
		if errors.Is(runErr, orchestrator.ErrConfig) {
			code = orchestrator.ExitConfig
		}
		return &exitError{code: code, err: fmt.Errorf("login %s: %w", p.id, runErr)}
	}
	if res.State != orchestrator.StateOK {
		return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("login %s: %s", p.id, res.State)}
	}
	// Notes are fixed orchestrator texts (never error text or supplier data).
	msg := p.id + ": logged in\n"
	for _, n := range res.Notes {
		msg += p.id + ": " + n + "\n"
	}
	if !persistent {
		msg += p.id + ": session not saved: sessions are ephemeral for this run\n"
	}
	if _, err := io.WriteString(p.stdout, msg); err != nil {
		return &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("print result: %w", err)}
	}
	return nil
}

// loginConnector returns the connector id names: a valid id, shipped by
// this build and configured in config.yaml. Anything else is a usage error
// (exit 2); an invalid id is never echoed.
func loginConnector(e env, cfg *config.Config, id string) (connector.Connector, error) {
	if !vault.ValidConnectorID(id) {
		return nil, &exitError{code: orchestrator.ExitConfig, err: errors.New("login: not a valid connector id")}
	}
	shipped, err := shippedConnectors(e)
	if err != nil {
		return nil, &exitError{code: orchestrator.ExitAttention, err: fmt.Errorf("connectors: %w", err)}
	}
	conn, ok := shipped.Get(id)
	if !ok {
		return nil, &exitError{code: orchestrator.ExitConfig, err: fmt.Errorf("login: connector %s is not available in this version", id)}
	}
	if _, ok := cfg.Connectors[id]; !ok {
		return nil, configError(fmt.Errorf("%w: connectors.%s: not configured in config.yaml", config.ErrInvalid, id))
	}
	return conn, nil
}

// loginDeps are what login built before any side effect.
type loginDeps struct {
	conn        connector.Connector
	secrets     connector.SecretResolver
	log         *slog.Logger
	browserPath string
	prompt      connector.Prompter
}

// loginWith creates the state dir, opens the session store and an
// interactive browser pool, and runs the login. persistent reports whether
// the store saves sessions this run. The pool is closed before it returns.
func loginWith(ctx context.Context, e env, cfg *config.Config, d loginDeps) (res orchestrator.ConnectorResult, persistent bool, err error) {
	if err := prepareStateDir(cfg); err != nil {
		return res, false, err
	}
	// The pool first: building it sweeps stale profiles (A12), as collect.
	pool, err := buildPool(ctx, e, poolParams{StateDir: cfg.StateDir, Executable: d.browserPath, Interactive: true, Log: d.log})
	if err != nil {
		return res, false, err
	}
	defer func() { err = errors.Join(err, closeErr("browser pool", pool.Close())) }()
	sessions, err := openSessions(ctx, e, cfg, d.log, true)
	if err != nil {
		return res, false, err
	}

	res = orchestrator.Login(ctx, orchestrator.Deps{
		Log:         d.log,
		Secrets:     d.secrets,
		Sessions:    sessions,
		Browser:     pool,
		Prompt:      d.prompt,
		Credentials: credentials(cfg),
	}, d.conn)
	return res, sessions.Persistent(), nil
}

// prepareStateDir creates the state dir 0700 when missing (its parent must
// exist), after checking that, once symlinks are followed, it is not inside
// a synced folder nor, when the output folder exists, physically inside it.
func prepareStateDir(cfg *config.Config) error {
	if _, err := os.Stat(cfg.Output.Local); err == nil {
		if err := checkStateDirOutside(cfg.StateDir, cfg.Output.Local, cfg.Home()); err != nil {
			return err
		}
	} else if _, err := checkStateDirNotSynced(cfg.StateDir, cfg.Home()); err != nil {
		return err
	}
	if err := ensureDir(cfg.StateDir, noFollowLink); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	return nil
}
