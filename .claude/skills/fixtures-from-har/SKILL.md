---
name: fixtures-from-har
description: Turns a recorded HAR (from `facto record`) into sanitized, minimal test fixtures and verifies no personal data or secret remains. Use whenever a HAR, a recording, a fixture, testdata, or a new supplier page is involved.
---

# Fixtures from a HAR

Input: `testdata/<id>/recording.har` produced by `facto record` (already stripped of
passwords, cookies and Authorization headers). Raw `*.har.raw` files are never read.

1. Run `go run ./scripts/harslim testdata/<id>/recording.har -o testdata/<id>/`:
   keeps only the requests the connector needs (login, list, one PDF), one file per
   response, plus `flow.json` describing the sequence.
2. Run `scripts/fixtures/sanitize.sh testdata/<id>/`: replaces names, addresses,
   contract numbers, emails, phones, IBANs, amounts' cents and dates with synthetic
   but format-preserving values, consistently across files.
3. Run `scripts/fixtures/scan.sh testdata/<id>/`. It must print `PII scan: 0 findings`.
   Any finding blocks the commit; fix sanitization rules, never the scanner.
4. Replace the PDF with a generated one of the same layout class (`go run ./scripts/fakepdf`).
5. Commit fixtures alone first (`test(<id>): add sanitized fixtures`).
