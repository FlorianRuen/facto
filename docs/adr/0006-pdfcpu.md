# 0006. Factur-X PDF attachments: `github.com/pdfcpu/pdfcpu`

- Status: Accepted
- Date: 2026-10-28
- Deciders: Florian (via J0 plan T5)

## Context
The spec (Normalization, Factur-X) reads a `factur-x.xml` or `zugferd-invoice.xml`
embedded file from a PDF and lets its issue date, seller, number and total win over the
connector's values; it matters most for files dropped in `inbox/`, i.e. untrusted input.
We only need to list and read embedded files from memory, without CGO; parsing the CII
XML itself is done with the stdlib (T16).

## Decision
`github.com/pdfcpu/pdfcpu` **v0.16.4** (2026-10-27), used only in
`internal/normalize/facturx` through `api.ExtractAttachmentsRaw(ctx, rs, "", names, conf)`,
which returns `[]model.Attachment` (an `io.Reader` per file) without writing to disk
(`outDir` is ignored per its doc comment). Guards on our side:
- size cap on the input PDF before parsing and on each attachment read (`io.LimitReader`);
  pdfcpu holds the attachment content in memory;
- our own `recover`: pdfcpu's `fault.Catch` only recovers its own `fault.Panic` type and
  re-panics anything else;
- fuzz test `FuzzExtract` over malformed PDFs.

Modules compiled in (`go list -deps`, CGO_ENABLED=0, same on all OSes):
`golang.org/x/crypto` v0.58.0, `golang.org/x/image` v0.47.0, `golang.org/x/text`
v0.43.0, `github.com/hhrutter/tiff` v1.0.7, `github.com/xdg-go/stringprep` v1.0.4,
`github.com/mattn/go-runewidth` v0.0.31, `github.com/clipperhouse/uax29/v2` v2.7.0,
`go.yaml.in/yaml/v3` v3.0.5 (shared with ADR 0003).

## Alternatives
| Option | Why not |
| --- | --- |
| Hand-written PDF parser (xref, streams, Flate) | Parsing untrusted PDFs is exactly where bugs hide; pdfcpu is fuzzed and widely used |
| `github.com/unidoc/unipdf` | AGPL or commercial license (unverified for current version): incompatible |
| `github.com/ledongthuc/pdf`, `rsc.io/pdf` | Text extraction readers; no embedded-file API (unverified in detail) |
| `pdfdetach` (poppler) via exec | External binary, not single-binary, CGO-free but not portable |

## License
pdfcpu: Apache-2.0. x/crypto, x/image, x/text, hhrutter/tiff: BSD-3-Clause.
stringprep: Apache-2.0. go-runewidth, uax29: MIT. yaml: MIT + Apache-2.0.

## Maintenance
77 tagged versions; 13 of the last 15 within the last 12 months; latest v0.16.4 released
the day before this ADR. Mostly a single main maintainer (hhrutter, unverified). Still
pre-1.0: API changes between minors are expected, hence the single call site.

## Consequences
- Large dependency for one feature; its blast radius is confined to `facturx`.
- `ErrNoFacturX` when neither attachment name is present; malformed PDFs are errors,
  never panics.
