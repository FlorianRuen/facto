package facturx

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// MaxPDFSize is the largest PDF Extract accepts, in bytes. Real Factur-X
// invoices weigh well under a few MiB.
const MaxPDFSize = 32 << 20

// extractTimeout bounds one Extract call: pdfcpu's reader can be slow on
// crafted inputs and Extract runs on untrusted files (inbox/).
const extractTimeout = 10 * time.Second

// Attachment names defined by Factur-X 1.0 and ZUGFeRD 2.x, in order of
// preference.
const (
	nameFacturX = "factur-x.xml"
	nameZUGFeRD = "zugferd-invoice.xml"
)

var (
	// ErrNoFacturX reports a readable PDF without an embedded file named
	// factur-x.xml or zugferd-invoice.xml.
	ErrNoFacturX = errors.New("facturx: no factur-x attachment")
	// ErrInvalidPDF reports an input that cannot be read as a PDF, an
	// attachment stream that cannot be decoded, or a panic recovered while
	// parsing.
	ErrInvalidPDF = errors.New("facturx: invalid pdf")
)

// Extract reads a whole PDF from r (at most MaxPDFSize bytes, more is
// ErrTooLarge), finds the embedded file whose own name (/UF, else /F) is
// exactly factur-x.xml (preferred) or zugferd-invoice.xml, decodes it in
// memory with at most MaxSize decoded bytes (ErrTooLarge beyond) and returns
// ParseCII's result. Errors wrap ErrTooLarge, ErrNoFacturX, ErrInvalidPDF,
// ParseCII's sentinels, the reader's error or ctx.Err(); on error the
// Invoice is the zero value. Extract writes no file and is bounded in time.
func Extract(ctx context.Context, r io.Reader) (Invoice, error) {
	if err := ctx.Err(); err != nil {
		return Invoice{}, fmt.Errorf("facturx: extract: %w", err)
	}
	pdf, err := io.ReadAll(io.LimitReader(r, MaxPDFSize+1))
	if err != nil {
		return Invoice{}, fmt.Errorf("facturx: read pdf: %w", err)
	}
	if len(pdf) > MaxPDFSize {
		return Invoice{}, fmt.Errorf("%w: pdf larger than %d bytes", ErrTooLarge, MaxPDFSize)
	}

	return extract(ctx, pdf, extractTimeout)
}

// extract is Extract once the input is in memory, bounded by timeout.
func extract(ctx context.Context, pdf []byte, timeout time.Duration) (Invoice, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	xml, err := attachment(tctx, pdf)
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return Invoice{}, fmt.Errorf("facturx: extract: %w", ctx.Err())
		case tctx.Err() != nil:
			return Invoice{}, fmt.Errorf("%w: timed out: %w", ErrInvalidPDF, tctx.Err())
		}
		return Invoice{}, err
	}
	inv, err := ParseCII(bytes.NewReader(xml))
	if err != nil {
		return Invoice{}, fmt.Errorf("facturx: attachment: %w", err)
	}
	return inv, nil
}

// attachment returns the decoded Factur-X XML embedded in pdf. pdfcpu only
// parses the PDF structure; the attachment stream itself is decoded here,
// through a size-limited reader, so that a Flate bomb never inflates more
// than MaxSize+1 bytes.
func attachment(ctx context.Context, pdf []byte) (xml []byte, err error) {
	// pdfcpu's fault.Catch only recovers its own panic type and re-panics
	// anything else: recover here so that no input can crash facto.
	defer func() {
		if p := recover(); p != nil {
			xml, err = nil, fmt.Errorf("%w: parser panic", ErrInvalidPDF)
		}
	}()

	sd, err := findStream(ctx, pdf)
	if err != nil {
		return nil, err
	}
	return decode(sd)
}

// config returns a pdfcpu configuration that never touches the disk (a nil
// configuration makes pdfcpu create a config directory under
// os.UserConfigDir) and caps what pdfcpu itself reads and decodes while
// parsing the PDF structure (object and xref streams).
func config() *model.Configuration {
	conf := model.NewStatelessConfiguration()
	conf.Limits = model.DefaultResourceLimits()
	conf.Limits.MaxInputBytes = MaxPDFSize
	conf.Limits.MaxStreamBytes = MaxPDFSize
	conf.Limits.MaxDecodeBytes = MaxPDFSize
	return conf
}

// findStream reads the PDF structure and returns the embedded file stream of
// the Factur-X attachment, still encoded.
func findStream(ctx context.Context, pdf []byte) (*types.StreamDict, error) {
	pc, err := api.ReadContext(ctx, bytes.NewReader(pdf), config())
	if err != nil {
		return nil, fmt.Errorf("%w: read: %w", ErrInvalidPDF, err)
	}
	xrt := pc.XRefTable
	if xrt == nil {
		return nil, fmt.Errorf("%w: no cross-reference table", ErrInvalidPDF)
	}
	cat, err := xrt.Catalog()
	if err != nil || cat == nil {
		return nil, fmt.Errorf("%w: no catalog", ErrInvalidPDF)
	}
	root, err := embeddedFilesRoot(xrt, cat)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, ErrNoFacturX
	}

	// The selection is done on the file specification's own name, never on
	// the name-tree key or /Desc.
	found := map[string]types.Dict{}
	visit := func(spec types.Dict) {
		name, ok := fileSpecName(xrt, spec)
		if !ok || (name != nameFacturX && name != nameZUGFeRD) {
			return
		}
		if _, dup := found[name]; !dup {
			found[name] = spec
		}
	}
	if err := walkNameTree(ctx, xrt, root, visit); err != nil {
		return nil, err
	}

	spec, ok := found[nameFacturX]
	if !ok {
		spec, ok = found[nameZUGFeRD]
	}
	if !ok {
		return nil, ErrNoFacturX
	}
	return embeddedStream(xrt, spec)
}

// embeddedFilesRoot returns the root node of the catalog's EmbeddedFiles
// name tree, or nil when there is none.
func embeddedFilesRoot(xrt *model.XRefTable, cat types.Dict) (types.Dict, error) {
	o, found := cat.Find("Names")
	if !found || o == nil {
		return nil, nil
	}
	names, err := xrt.DereferenceDict(o)
	if err != nil {
		return nil, fmt.Errorf("%w: catalog /Names: %w", ErrInvalidPDF, err)
	}
	if names == nil {
		return nil, nil
	}
	if o, found = names.Find("EmbeddedFiles"); !found || o == nil {
		return nil, nil
	}
	root, err := xrt.DereferenceDict(o)
	if err != nil {
		return nil, fmt.Errorf("%w: /EmbeddedFiles: %w", ErrInvalidPDF, err)
	}
	return root, nil
}

// Name-tree walk bounds: real Factur-X PDFs have one flat leaf with a
// handful of entries.
const (
	maxTreeDepth   = 32
	maxTreeEntries = 10_000
)

// walkNameTree calls visit with every value of the name tree rooted at root
// that is a dictionary (file specifications); other values are skipped. It
// is iterative, refuses cycles and caps depth and size: a hostile tree is
// ErrInvalidPDF.
func walkNameTree(ctx context.Context, xrt *model.XRefTable, root types.Dict, visit func(types.Dict)) error {
	type item struct {
		node  types.Dict
		depth int
	}
	stack := []item{{node: root}}
	seen := map[int]bool{}
	entries := 0
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("walk embedded files: %w", err)
		}
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if o, found := it.node.Find("Names"); found {
			arr, err := xrt.DereferenceArray(o)
			if err != nil {
				return fmt.Errorf("%w: /EmbeddedFiles /Names: %w", ErrInvalidPDF, err)
			}
			for i := 1; i < len(arr); i += 2 {
				if entries++; entries > maxTreeEntries {
					return fmt.Errorf("%w: too many embedded files", ErrInvalidPDF)
				}
				if spec, err := xrt.DereferenceDict(arr[i]); err == nil && spec != nil {
					visit(spec)
				}
			}
		}
		o, found := it.node.Find("Kids")
		if !found {
			continue
		}
		kids, err := xrt.DereferenceArray(o)
		if err != nil {
			return fmt.Errorf("%w: /EmbeddedFiles /Kids: %w", ErrInvalidPDF, err)
		}
		if it.depth >= maxTreeDepth {
			return fmt.Errorf("%w: embedded files tree too deep", ErrInvalidPDF)
		}
		for _, k := range kids {
			ref, ok := k.(types.IndirectRef)
			if !ok {
				return fmt.Errorf("%w: /EmbeddedFiles kid is not a reference", ErrInvalidPDF)
			}
			nr := ref.ObjectNumber.Value()
			if seen[nr] {
				return fmt.Errorf("%w: embedded files tree has a cycle", ErrInvalidPDF)
			}
			seen[nr] = true
			kid, err := xrt.DereferenceDict(ref)
			if err != nil || kid == nil {
				return fmt.Errorf("%w: /EmbeddedFiles kid is not a dictionary", ErrInvalidPDF)
			}
			stack = append(stack, item{node: kid, depth: it.depth + 1})
		}
	}
	return nil
}

// fileSpecName returns the file specification's /UF, else /F.
func fileSpecName(xrt *model.XRefTable, d types.Dict) (string, bool) {
	for _, k := range []string{"UF", "F"} {
		if o, found := d.Find(k); found {
			s, err := xrt.DereferenceStringOrHexLiteral(o, model.V10, nil)
			return s, err == nil
		}
	}
	return "", false
}

// embeddedStream returns the stream of the file specification's /EF entry
// (/F, else /UF).
func embeddedStream(xrt *model.XRefTable, spec types.Dict) (*types.StreamDict, error) {
	o, found := spec.Find("EF")
	if !found {
		return nil, fmt.Errorf("%w: attachment without /EF", ErrInvalidPDF)
	}
	ef, err := xrt.DereferenceDict(o)
	if err != nil || ef == nil {
		return nil, fmt.Errorf("%w: attachment /EF is not a dictionary", ErrInvalidPDF)
	}
	o, found = ef.Find("F")
	if !found {
		o, found = ef.Find("UF")
	}
	if !found {
		return nil, fmt.Errorf("%w: attachment /EF without a stream", ErrInvalidPDF)
	}
	sd, _, err := xrt.DereferenceStreamDict(o)
	if err != nil || sd == nil {
		return nil, fmt.Errorf("%w: attachment stream missing", ErrInvalidPDF)
	}
	return sd, nil
}

// decode returns the decoded content of sd, reading at most MaxSize+1
// decoded bytes. Only unfiltered and FlateDecode streams without a predictor
// are supported: that is what Factur-X producers write for XML.
func decode(sd *types.StreamDict) ([]byte, error) {
	var r io.Reader
	switch {
	case len(sd.FilterPipeline) == 0:
		r = bytes.NewReader(sd.Raw)
	case len(sd.FilterPipeline) == 1 && sd.FilterPipeline[0].Name == "FlateDecode":
		if p := sd.FilterPipeline[0].DecodeParms.IntEntry("Predictor"); p != nil && *p > 1 {
			return nil, fmt.Errorf("%w: attachment uses a flate predictor", ErrInvalidPDF)
		}
		zr, err := zlib.NewReader(bytes.NewReader(sd.Raw))
		if err != nil {
			return nil, fmt.Errorf("%w: attachment flate: %w", ErrInvalidPDF, err)
		}
		defer func() { _ = zr.Close() }() // in-memory reader: Close only releases state
		r = zr
	default:
		return nil, fmt.Errorf("%w: unsupported attachment filter", ErrInvalidPDF)
	}
	buf, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if len(buf) > MaxSize {
		return nil, fmt.Errorf("%w: attachment decodes to more than %d bytes", ErrTooLarge, MaxSize)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: attachment decode: %w", ErrInvalidPDF, err)
	}
	return buf, nil
}
