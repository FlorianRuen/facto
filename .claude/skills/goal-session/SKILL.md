---
name: goal-session
description: How to run facto milestones in Claude Code goal mode until completion: delegation order, progress logging, blockers, proof printing, cost control. Load whenever a /goal is active or the user asks to work autonomously on a milestone.
---

# Running a goal session

The goal evaluator reads only the transcript. It does not run commands. Your job each
turn is to make progress AND print proof.

## Loop per turn
1. Read the last 20 lines of `docs/agentic/PROGRESS.md`; pick the next unblocked task.
2. Delegate: `test-writer` → `implementer` (worktree) → `reviewer`. Run independent
   tasks in parallel only when the planner marked them `parallel-ok`.
3. On reviewer PASS: commit, append to PROGRESS.md:
   `2026-11-03 J1 T4 done: browser pipe transport (commit abc123)`.
4. End the turn by printing the proof block:
   ```
   PROOF
   make verify -> exit 0 (last lines…)
   make cover  -> internal/normalize 91.2%, internal/store 88.0%
   make e2e    -> 8/8 scenarios passed
   security/score.json -> total 88, min category 7, AUDIT: PASS
   ```

## Closing a milestone
`red-team` → `security-auditor` → fix findings → `docs-writer` → open the PR with the
template → print the final PROOF matching the goal condition word for word.

## Blockers
Human checkpoint needed → `BLOCKED(Hn): exact request` in PROGRESS.md, continue with
other tasks. If every remaining task is blocked, print `GOAL BLOCKED: waiting for Hn`
and the list; this lets the evaluator stop cleanly.

## Cost and safety
Keep subagent prompts short and specific; avoid re-reading large files; never loop on
a failing approach more than 3 times: escalate to the planner with what you tried.
Never touch hooks, settings or workflows; never weaken tests.
