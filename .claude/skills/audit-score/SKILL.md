---
name: audit-score
description: Exact procedure and rubric to produce facto's security score (security/score.json) and audit report. Use when acting as security-auditor, when a goal condition mentions the audit score, or before closing a milestone.
---

# Producing the security score

1. `make audit` → read `security/scanners.json`. Scanner gates: govulncheck 0,
   gosec 0 high, gitleaks 0, osv-scanner 0 high/critical, CodeQL 0 high (CI only),
   leakcheck 0, security E2E scenarios all pass.
2. Score each category of `security/rubric.md` (total 100). Start each category at
   its maximum, subtract per finding: critical = category to 0, high = -50% of the
   category, medium = -2, low = -1 (never below 0). Missing evidence for a control =
   treat as a medium finding.
3. Findings need: id (`SEC-<milestone>-<n>`), category, severity, file:line, evidence
   (code excerpt or test output), suggested fix, regression test name once fixed.
4. Write `security/audit/<YYYY-MM-DD>-<milestone>.md` (summary table, findings,
   diff since previous audit) and `security/score.json` matching
   `security/score.schema.json`, with `commit` = `git rev-parse HEAD`.
5. Pass = total >= 85 AND every category >= 6 (scaled to 10) AND no open critical/high
   AND all scanner gates pass. Print `AUDIT: PASS` or `AUDIT: FAIL` with the reasons.

Re-audit only what changed since the last report, but always re-run scanners and
re-check regression tests for every past finding.
