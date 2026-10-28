# Kickoff: launching the autonomous build

## Before the first session (Florian, checkpoint H1)
1. Create the GitHub repository (public), default branch `main`, Apache-2.0 license.
2. Copy this kit at the root, plus the spec exported as `docs/spec.md`. Commit.
3. Settings: branch protection on `main` (PR required, checks required: ci, security,
   claude-review), Actions enabled, Dependabot alerts on, private vulnerability reporting on.
4. Add the repository secret used by `claude-review.yml` (see the Claude Code GitHub
   Actions docs for the current options).
5. Install Renovate (or keep Dependabot) and enable the OpenSSF Scorecard workflow.
6. Local machine: Go (version in go.mod), Docker (Vaultwarden for E2E), Node LTS
   (PWA tests), Claude Code >= the version required by /goal.

## Starting a milestone
```bash
git switch -c milestone/j0
claude                      # accept the workspace trust dialog (needed by /goal and hooks)
```
Then in Claude Code:
```
Read CLAUDE.md, docs/spec.md and docs/agentic/GOALS.md. Use the planner subagent for J0.
/goal <paste the J0 condition from GOALS.md>
```
Headless alternative: `claude -p "/goal <condition>"` (stop with Ctrl+C).

## While it runs
- `/goal` without argument shows turns, tokens and the evaluator's last reason.
- Check `docs/agentic/PROGRESS.md` for `BLOCKED(Hn)` / `NEEDS(Hn)` lines.
- Checkpoints: H2 Google OAuth clients · H3 `facto record <url>` per supplier ·
  H4 `facto doctor <id>` and `facto collect --year 2025` with real accounts.

## After a milestone
Review the PR (the claude-review comment includes the audit score), merge, start the
next milestone on a new branch.
