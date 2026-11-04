package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
)

// e2eInteractiveEnv enables stdin prompts in e2e builds (A8).
const e2eInteractiveEnv = "FACTO_E2E_INTERACTIVE"

// e2eStdinPrompts is false in every build but -tags e2e, where an e2e-only
// file sets it at package initialization: only then may FACTO_E2E_INTERACTIVE
// turn plain stdin lines into prompt answers (A8).
var e2eStdinPrompts bool

// errEmptyAnswer reports a prompt answered with nothing but white space.
var errEmptyAnswer = errors.New("empty answer")

// promptMode is how a connPrompter reads answers.
type promptMode int

const (
	promptOff      promptMode = iota // non-interactive: never reads
	promptTerminal                   // no-echo reads through the terminal seam
	promptLines                      // plain stdin lines (e2e builds only, A8)
)

// connPrompter is the connector.Prompter of a command. Prompts go to out
// (stderr); answers are never written anywhere.
type connPrompter struct {
	mode promptMode
	term terminal
	in   io.Reader
	out  io.Writer
	mu   sync.Mutex // one prompt at a time
}

var _ connector.Prompter = (*connPrompter)(nil)

// newPrompter returns the connector.Prompter of a command:
//   - nonInteractive (flag) → non-interactive;
//   - the terminal seam says stdin is a terminal → interactive, answers
//     read with ReadNoEcho;
//   - e2e build and FACTO_E2E_INTERACTIVE exactly "1" → interactive,
//     answers read as plain lines from stdin (A8); a release build ignores
//     the variable;
//   - otherwise non-interactive.
func newPrompter(e env, stdin io.Reader, out io.Writer, nonInteractive bool) connector.Prompter {
	p := &connPrompter{term: e.terminal(), in: stdin, out: out}
	switch {
	case nonInteractive:
	case p.term.IsTerminal(stdin):
		p.mode = promptTerminal
	case e2eStdinPrompts && e.lookupEnv(e2eInteractiveEnv) == "1":
		p.mode = promptLines
	}
	return p
}

// Interactive reports whether Prompt asks the user.
func (p *connPrompter) Interactive() bool { return p.mode != promptOff }

// Prompt writes req.CleanLabel() and ": " to out, reads one answer, trims
// the surrounding white space and returns it as a secret.Secret. A
// non-interactive prompter writes and reads nothing and returns an error
// wrapping connector.ErrNeedsLogin. A done ctx returns ctx.Err() (wrapped)
// without reading; a ctx canceled while waiting for the answer returns at
// once and turns the terminal echo back on. The end of input, or an empty
// answer, is an error with a zero Secret.
func (p *connPrompter) Prompt(ctx context.Context, req connector.PromptRequest) (secret.Secret, error) {
	if p.mode == promptOff {
		return secret.Secret{}, fmt.Errorf("prompt: %w: no interactive terminal", connector.ErrNeedsLogin)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return secret.Secret{}, fmt.Errorf("prompt: %w", err)
	}
	_, _ = io.WriteString(p.out, req.CleanLabel()+": ")

	type answer struct {
		b   []byte
		err error
	}
	done := make(chan answer, 1)
	go func() {
		var a answer
		if p.mode == promptTerminal {
			a.b, a.err = p.term.ReadNoEcho(p.in)
		} else {
			a.b, a.err = readSecretLine(p.in)
		}
		done <- a
	}()

	var a answer
	select {
	case a = <-done:
	case <-ctx.Done():
		if a, ok := p.term.(interface{ abort() }); ok && p.mode == promptTerminal {
			a.abort()
		}
		_, _ = io.WriteString(p.out, "\n")
		go func() { clear((<-done).b) }() // the late answer is wiped, never used
		return secret.Secret{}, fmt.Errorf("prompt: %w", ctx.Err())
	}
	if p.mode == promptTerminal {
		// Echo was off: the Enter key printed nothing.
		_, _ = io.WriteString(p.out, "\n")
	}
	if a.err != nil {
		clear(a.b)
		if errors.Is(a.err, io.EOF) {
			return secret.Secret{}, fmt.Errorf("prompt: no answer: %w", io.ErrUnexpectedEOF)
		}
		return secret.Secret{}, fmt.Errorf("prompt: %w", a.err)
	}
	trimmed := bytes.TrimSpace(a.b)
	if len(trimmed) == 0 {
		clear(a.b)
		return secret.Secret{}, fmt.Errorf("prompt: %w", errEmptyAnswer)
	}
	value := bytes.Clone(trimmed)
	clear(a.b)
	return secret.New(value), nil
}
