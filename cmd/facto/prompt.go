package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/normalize"
)

// maxAnswerLen caps one prompt answer, in bytes.
const maxAnswerLen = 256

// dateLayout is the date format the prompter reads.
const dateLayout = "2006-01-02"

// linePrompter asks about unidentified inbox files on a terminal, one line
// per answer. Prompts go to out (stderr), never to stdout which carries the
// report. It implements inbox.Prompter.
type linePrompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newLinePrompter(in io.Reader, out io.Writer) *linePrompter {
	return &linePrompter{in: bufio.NewReader(in), out: out}
}

// AskDoc asks for the provider and the date of file, offering guess as the
// default. An empty date without a default, an invalid date, "-" or the end
// of input skips the file (ok=false). The file name is quoted so that
// control characters in it cannot drive the terminal.
func (p *linePrompter) AskDoc(ctx context.Context, file string, guess normalize.Doc) (normalize.Doc, bool, error) {
	if err := ctx.Err(); err != nil {
		return normalize.Doc{}, false, fmt.Errorf("prompt: %w", err)
	}
	_, _ = fmt.Fprintf(p.out, "inbox file %q is not identified (\"-\" skips it)\n", file)

	doc := guess
	provider, ok, err := p.ask(fmt.Sprintf("  provider [%s]: ", guess.Provider))
	if err != nil || !ok {
		return normalize.Doc{}, false, err
	}
	if provider != "" && provider != guess.Provider {
		doc.Provider = provider
		doc.Category = "" // the inbox derives it from the new provider
	}

	def := ""
	if !guess.Date.IsZero() {
		def = guess.Date.UTC().Format(dateLayout)
	}
	date, ok, err := p.ask(fmt.Sprintf("  date %s [%s]: ", dateLayout, def))
	if err != nil || !ok {
		return normalize.Doc{}, false, err
	}
	if date == "" {
		date = def
	}
	if date == "" {
		return normalize.Doc{}, false, nil
	}
	t, err := time.ParseInLocation(dateLayout, date, time.UTC)
	if err != nil {
		_, _ = fmt.Fprintln(p.out, "  invalid date: file skipped")
		return normalize.Doc{}, false, nil
	}
	doc.Date = t
	return doc, true, nil
}

// ask prints prompt and reads one trimmed line. ok=false means skip ("-" or
// end of input).
func (p *linePrompter) ask(prompt string) (answer string, ok bool, err error) {
	_, _ = io.WriteString(p.out, prompt)
	line, n, err := p.readLine()
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false, fmt.Errorf("read answer: %w", err)
	}
	if errors.Is(err, io.EOF) && n == 0 {
		return "", false, nil
	}
	answer = strings.TrimSpace(line)
	if answer == "-" {
		return "", false, nil
	}
	return answer, true, nil
}

// readLine reads one line, newline included, and returns its first
// maxAnswerLen bytes, cut back to a rune boundary, and its full length n.
// The rest of a longer line is read and discarded in buffer-sized chunks,
// so memory stays bounded whatever the input. err is io.EOF when the input
// ends, with or without a partial last line.
func (p *linePrompter) readLine() (line string, n int, err error) {
	buf := make([]byte, 0, maxAnswerLen)
	cut := false
	for {
		chunk, rerr := p.in.ReadSlice('\n')
		n += len(chunk)
		if room := maxAnswerLen - len(buf); len(chunk) > room {
			chunk, cut = chunk[:room], true
		}
		buf = append(buf, chunk...)
		if !errors.Is(rerr, bufio.ErrBufferFull) {
			err = rerr
			break
		}
	}
	if cut {
		buf = trimPartialRune(buf)
	}
	return string(buf), n, err
}

// trimPartialRune drops an incomplete UTF-8 sequence left at the end of b by
// a byte cut. Complete runes and invalid bytes are kept as they are.
func trimPartialRune(b []byte) []byte {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i]
			}
			return b
		}
	}
	return b
}
