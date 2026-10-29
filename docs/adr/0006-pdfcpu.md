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
`internal/normalize/facturx` (`extract.go`), and only to parse the PDF structure:
`api.ReadContext(ctx, rs, conf)` (no validation pass), then the catalog,
dictionaries and streams are read through `model.XRefTable` dereferencing. Nothing is
written to disk.

Amended during T17 (2026-10-28): `api.ExtractAttachmentsRaw` was the first plan, but it
inflates each selected attachment completely in memory (`XRefTable.DecodeStream`, up to
pdfcpu's decode limit, 512 MiB by default) before the caller can apply any cap: a
Flate bomb in an untrusted `inbox/` PDF would cost hundreds of MiB. It also matches
selected names against `/Desc`, and relies on a validation pass to populate name
trees. Instead `Extract`:
- walks the `EmbeddedFiles` name tree itself (iterative, cycle detection on object
  numbers, depth <= 32, <= 10 000 entries) and selects on the file specification's own
  name (`/UF`, else `/F`), never the name-tree key or `/Desc`;
- takes the embedded file stream's **encoded** bytes (`StreamDict.Raw`, which pdfcpu does
  not decode while reading when `DecodeAllStreams` is false) and inflates them itself
  with `compress/zlib` through `io.LimitReader(MaxSize+1)`: at most 4 MiB + 1 byte is
  ever inflated. Only no filter or a single `FlateDecode` without predictor is accepted
  (what Factur-X producers write for XML); any other filter or a filter chain is
  `ErrInvalidPDF`.

Guards on our side:
- explicit `model.NewStatelessConfiguration()` (a nil configuration makes pdfcpu create
  `<UserConfigDir>/pdfcpu`, a write outside `fsx`), with `Limits` set to
  `MaxInputBytes = MaxStreamBytes = MaxDecodeBytes = MaxPDFSize` (32 MiB); no call to
  any pdfcpu package-level state changer (`ConfigPath`, loggers, `DisableConfigDir`);
- input read through `io.LimitReader(MaxPDFSize+1)` before any parsing;
- a 10 s `context.WithTimeout` around parsing (pdfcpu checks the context between
  objects); a timeout is `ErrInvalidPDF` wrapping `context.DeadlineExceeded`;
- our own `recover`: pdfcpu's `fault.Catch` only recovers its own `fault.Panic` type and
  re-panics anything else;
- fuzz test `FuzzExtract` over malformed PDFs, `TestExtract_FlateBomb` (16x MaxSize).

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
- We depend on `XRefTable`/`StreamDict` details (`Raw`, `FilterPipeline`,
  `Dereference*`) rather than only the `api` surface: a pdfcpu upgrade must re-run the
  `facturx` tests, which pin the behaviour (including the bomb test).
- Residual risk: pdfcpu itself still inflates the PDF's *structural* streams (object
  streams, xref streams) while reading. Each is capped at `MaxDecodeBytes` (32 MiB), but
  pdfcpu's cumulative budget across streams is at least 1 GiB by design, so a crafted
  PDF with many object streams can still cost a lot of memory before the 10 s deadline.
  Accepted for J0 (the input is the user's own `inbox/` or a connector download);
  revisit if pdfcpu exposes a lower cumulative budget.
- A producer that uses another filter on the XML attachment (none known) is rejected
  with `ErrInvalidPDF`; the caller then falls back to the connector's metadata.
