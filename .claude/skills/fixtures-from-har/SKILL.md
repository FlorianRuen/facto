---
name: fixtures-from-har
description: Turns a recorded HAR (from `facto record`) into sanitized, minimal test fixtures and verifies no personal data or secret remains. Use whenever a HAR, a recording, a fixture, testdata, or a new supplier page is involved.
---

# Fixtures from a HAR

Input: a HAR written by `facto record` (already stripped of passwords, login
identifiers sent in forms, cookie values, Authorization headers, tokens and PDF
bodies). Florian records it OUTSIDE the repository (`facto record` refuses a
git work tree) and hands over the path. It still holds personal data: never
copy it into the repository, never print it whole, never commit it. Raw
browser exports and `*.har.raw` files are never read; `harslim` refuses any
HAR that is not redacted.

1. `go run ./scripts/harslim <path/to/recording.har> -o testdata/<id>/`
   (optional `--host <supplier host>`, repeatable; default: the first page's
   host): keeps only the requests the connector needs (pages, XHR/fetch, one
   PDF), one file per response body, plus `flow.json` describing the sequence.
2. `scripts/fixtures/sanitize.sh testdata/<id>/`: replaces names, addresses,
   postcodes and cities, contract and reference numbers, emails, phones,
   IBANs, card numbers, NIR, amounts' cents and dates (one offset for the whole
   tree) with synthetic but format-preserving values, consistently across
   files. Deterministic (`FACTO_SANITIZE_KEY` changes the mapping).
3. `scripts/fixtures/scan.sh testdata/<id>/`. It must print `PII scan: 0 findings`.
   Any finding blocks the commit: fix sanitization rules (`internal/fixtures`),
   never the scanner. Names are not pattern-detectable: read the sanitized
   pages once for a leftover name and add the field to `nameFields` if needed.
4. Replace the PDF with a generated one of the same layout class:
   `go run ./scripts/fakepdf -o testdata/<id>/<file>.pdf --like testdata/<id>/<file>.pdf --line "…"`
   (`--facturx <synthetic.xml>` to embed a Factur-X attachment). Re-run step 3.
5. Commit fixtures alone first (`test(<id>): add sanitized fixtures`).
