package browser

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Script freeze around secret typing (ADR 0008 "Secret typing", J1 T27).
// Between TypeSecret's pre-typing check and Input.insertText a page timer
// could move the focus to a cross-origin frame, which would then receive
// the value. Page scripts are therefore disabled
// (Emulation.setScriptExecutionDisabled) on the page session and on every
// out-of-process frame session from just before the check until the value
// is typed: no page code runs in that window. A frame attached while the
// freeze holds is frozen before it is resumed. A session that cannot be
// frozen refuses the typing; scripts are always re-enabled.

// unfreezeTimeout bounds the re-enabling, run even when the caller's
// context has ended.
const unfreezeTimeout = 5 * time.Second

// errFreeze: page scripts could not be disabled before typing.
var errFreeze = errors.New("browser: page scripts could not be frozen")

// scriptsDisabled are the Emulation.setScriptExecutionDisabled params.
func scriptsDisabled(v bool) map[string]any { return map[string]any{"value": v} }

// freeze disables page scripts on the page session and on every watched
// frame session. It returns the sessions disabled so far even on error,
// for unfreeze.
func (p *Page) freeze(ctx context.Context) (*frozenSet, error) {
	fs := &frozenSet{sessions: map[string]bool{}}
	p.subsMu.Lock()
	p.frozen = fs
	targets := []string{p.sessionID}
	for id, w := range p.sessions {
		if w.typ == "iframe" {
			targets = append(targets, id)
		}
	}
	p.subsMu.Unlock()
	for _, s := range targets {
		if err := p.freezeSession(ctx, fs, s); err != nil {
			return fs, err
		}
	}
	return fs, nil
}

// freezeSession disables scripts on session and records it in fs.
func (p *Page) freezeSession(ctx context.Context, fs *frozenSet, session string) error {
	p.subsMu.Lock()
	fs.sessions[session] = true // recorded first: unfreeze re-enables it whatever the answer
	p.subsMu.Unlock()
	if _, err := p.c.Call(ctx, session, "Emulation.setScriptExecutionDisabled", scriptsDisabled(true)); err != nil {
		return fmt.Errorf("%w: %w", errFreeze, err)
	}
	return nil
}

// unfreeze re-enables scripts on every session of fs, with its own bounded
// context. It returns the first error.
func (p *Page) unfreeze(ctx context.Context, fs *frozenSet) error {
	p.subsMu.Lock()
	if p.frozen == fs {
		p.frozen = nil
	}
	fs.done = true
	sessions := make([]string, 0, len(fs.sessions))
	for s := range fs.sessions {
		sessions = append(sessions, s)
	}
	p.subsMu.Unlock()
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unfreezeTimeout)
	defer cancel()
	var first error
	for _, s := range sessions {
		if _, err := p.c.Call(uctx, s, "Emulation.setScriptExecutionDisabled", scriptsDisabled(false)); err != nil && first == nil {
			first = fmt.Errorf("re-enable page scripts: %w", err)
		}
	}
	return first
}

// freezeAttached freezes a frame session attached while a freeze holds,
// before it is resumed. A freeze that ended meanwhile is undone on it.
func (p *Page) freezeAttached(ctx context.Context, session string) error {
	p.subsMu.Lock()
	fs := p.frozen
	p.subsMu.Unlock()
	if fs == nil {
		return nil
	}
	if err := p.freezeSession(ctx, fs, session); err != nil {
		return err
	}
	p.subsMu.Lock()
	ended := fs.done
	p.subsMu.Unlock()
	if ended {
		if _, err := p.c.Call(ctx, session, "Emulation.setScriptExecutionDisabled", scriptsDisabled(false)); err != nil {
			return fmt.Errorf("re-enable page scripts: %w", err)
		}
	}
	return nil
}

// frozenSet is one freeze: the sessions it disabled (guarded by subsMu).
type frozenSet struct {
	sessions map[string]bool
	done     bool
}
