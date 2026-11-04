// Tests for the connector prompter (J1 task T19; connector.Prompter,
// PromptRequest.CleanLabel; decision A8). Expected API: newPrompter and the
// terminal seam, documented in login_test.go. Answers are synthetic
// canaries; no test touches the real terminal.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// stdinSentinel is what stdin holds when the prompter must not read it.
const stdinSentinel = "synthetic stdin that must stay unread\n"

// TestPrompt_NoEchoAndCleanLabel: on a terminal the answer is read with
// echo off through the terminal seam (never from stdin directly), the
// label shown is CleanLabel, the value comes back as a secret.Secret and is
// never written out.
func TestPrompt_NoEchoAndCleanLabel(t *testing.T) {
	t.Parallel()
	answer := testsecrets.Canary(t, testsecrets.Token)
	term := &fakeTerminal{tty: true, answers: []string{" \t" + answer + " \r"}}
	e := newSandbox(t).env()
	e.Terminal = term
	stdin := strings.NewReader(stdinSentinel)
	var out bytes.Buffer

	p := newPrompter(e, stdin, &out, false)
	if !p.Interactive() {
		t.Fatalf("Interactive() = false on a terminal, want true")
	}
	req := connector.PromptRequest{Label: synthLabel}
	got, err := p.Prompt(t.Context(), req)
	if err != nil {
		t.Fatalf("Prompt: %v", err)
	}
	defer got.Wipe()
	if got.Expose() != answer {
		t.Errorf("answer differs from what was typed (surrounding white space must be trimmed)")
	}
	if term.readCount() != 1 {
		t.Errorf("no-echo reads = %d, want 1", term.readCount())
	}
	if stdin.Len() != len(stdinSentinel) {
		t.Errorf("stdin read directly (%d bytes left of %d): answers must go through the no-echo read", stdin.Len(), len(stdinSentinel))
	}
	shown := out.String()
	if !strings.Contains(shown, req.CleanLabel()) {
		t.Errorf("prompt output = %q, want the cleaned label %q", shown, req.CleanLabel())
	}
	if strings.ContainsAny(shown, "\x1b\x07\u202e") {
		t.Errorf("prompt output carries the raw label: %q", shown)
	}
	if strings.Contains(shown, answer) {
		t.Errorf("prompt output echoes the answer")
	}
	if s := fmt.Sprintf("%v %+v %#v %s", got, got, got, got); strings.Contains(s, answer) {
		t.Errorf("formatted answer is not masked: %q", s)
	}
	func(secret.Secret) {}(got) // the answer type is secret.Secret
}

// TestPrompt_NoEchoErrors: a done context reads nothing; the end of input
// is an error with no answer.
func TestPrompt_NoEchoErrors(t *testing.T) {
	t.Parallel()

	t.Run("canceled", func(t *testing.T) {
		t.Parallel()
		term := &fakeTerminal{tty: true, answers: []string{"123456"}}
		e := newSandbox(t).env()
		e.Terminal = term
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		got, err := newPrompter(e, strings.NewReader(""), &bytes.Buffer{}, false).Prompt(ctx, connector.PromptRequest{Label: "Code"})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Prompt error = %v, want context.Canceled", err)
		}
		if !got.IsZero() || term.readCount() != 0 {
			t.Errorf("canceled prompt returned a value or read (%d reads)", term.readCount())
		}
	})

	t.Run("end of input", func(t *testing.T) {
		t.Parallel()
		e := newSandbox(t).env()
		e.Terminal = &fakeTerminal{tty: true}
		got, err := newPrompter(e, strings.NewReader(""), &bytes.Buffer{}, false).Prompt(t.Context(), connector.PromptRequest{Label: "Code"})
		if err == nil || !got.IsZero() {
			t.Fatalf("Prompt at end of input = (zero %v, err %v), want an error and no value", got.IsZero(), err)
		}
	})
}

// TestPrompt_NonInteractiveRefuses: without a terminal (or with
// --non-interactive) the prompter is not interactive, and Prompt writes
// nothing, reads nothing and returns ErrNeedsLogin.
func TestPrompt_NonInteractiveRefuses(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		tty  bool
		flag bool
	}{
		{name: "stdin not a terminal"},
		{name: "non-interactive flag on a terminal", tty: true, flag: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			term := &fakeTerminal{tty: tt.tty, answers: []string{"123456"}}
			e := newSandbox(t).env()
			e.Terminal = term
			stdin := strings.NewReader(stdinSentinel)
			var out bytes.Buffer

			p := newPrompter(e, stdin, &out, tt.flag)
			if p.Interactive() {
				t.Errorf("Interactive() = true, want false")
			}
			got, err := p.Prompt(t.Context(), connector.PromptRequest{Label: "Code"})
			if !errors.Is(err, connector.ErrNeedsLogin) {
				t.Fatalf("Prompt error = %v, want connector.ErrNeedsLogin", err)
			}
			if !got.IsZero() {
				t.Errorf("non-interactive Prompt returned a value")
			}
			if out.Len() != 0 {
				t.Errorf("non-interactive Prompt wrote %q", out.String())
			}
			if term.readCount() != 0 || stdin.Len() != len(stdinSentinel) {
				t.Errorf("non-interactive Prompt read input (%d no-echo reads, %d stdin bytes left)", term.readCount(), stdin.Len())
			}
		})
	}
}

// TestPrompt_E2EStdinOnlyWithEnvFlag (A8): an e2e build answers prompts
// from plain stdin lines when FACTO_E2E_INTERACTIVE is exactly "1" and
// stdin is not a terminal; a release build ignores the variable. The
// --non-interactive flag always wins.
func TestPrompt_E2EStdinOnlyWithEnvFlag(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		value string // "" = unset
		flag  bool
		want  bool // interactive in an e2e build
	}{
		{name: "set to 1", value: "1", want: true},
		{name: "unset"},
		{name: "set to 0", value: "0"},
		{name: "set to true", value: "true"},
		{name: "set to 1 with the flag", value: "1", flag: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			answer := testsecrets.Canary(t, testsecrets.Token)
			term := &fakeTerminal{tty: false}
			e := newSandbox(t).env()
			e.Terminal = term
			e.LookupEnv = func(k string) (string, bool) {
				if k == "FACTO_E2E_INTERACTIVE" && tt.value != "" {
					return tt.value, true
				}
				return "", false
			}
			input := answer + "\nsynthetic second line\n"
			stdin := strings.NewReader(input)
			var out bytes.Buffer

			p := newPrompter(e, stdin, &out, tt.flag)
			want := e2eBuild && tt.want
			if p.Interactive() != want {
				t.Fatalf("Interactive() = %v, want %v (e2e build: %v)", p.Interactive(), want, e2eBuild)
			}
			got, err := p.Prompt(t.Context(), connector.PromptRequest{Label: "Code"})
			if strings.Contains(out.String(), answer) {
				t.Errorf("prompt output echoes the answer")
			}
			if term.readCount() != 0 {
				t.Errorf("no-echo reads = %d, want 0 (stdin is not a terminal)", term.readCount())
			}
			if !want {
				if !errors.Is(err, connector.ErrNeedsLogin) {
					t.Fatalf("Prompt error = %v, want connector.ErrNeedsLogin", err)
				}
				if stdin.Len() != len(input) {
					t.Errorf("stdin read although prompts are off")
				}
				return
			}
			if err != nil {
				t.Fatalf("Prompt: %v", err)
			}
			defer got.Wipe()
			if got.Expose() != answer {
				t.Errorf("answer differs from the stdin line")
			}
		})
	}
}
