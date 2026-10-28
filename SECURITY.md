# Security policy

facto handles credentials, session cookies and tokens for personal accounts. We treat
any way to read, leak or exfiltrate them as a vulnerability.

## Reporting
Use GitHub private vulnerability reporting on this repository. Do not open public
issues for security problems. Expect an acknowledgement within 7 days.

## Scope
In scope: secret handling, session storage, the automated browser, network allowlists,
file writes, parsers, the capture PWA, the local web UI, release artifacts.
Out of scope: attackers with root access to the user's machine; supplier websites.

## How we measure
Every milestone publishes `security/score.json` (rubric in `security/rubric.md`) and a
report in `security/audit/`. Scanners (govulncheck, gosec, gitleaks, osv-scanner,
CodeQL, OpenSSF Scorecard) run on every PR and weekly. Every past finding has a
regression test.
