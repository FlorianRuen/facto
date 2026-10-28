package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// Load reads the config file at path and parses it (see Parse). The file
// must be a regular file (a symlink, directory or FIFO is refused with
// fsx.ErrNotRegular, never followed nor read), owner-only on Unix (any group
// or world bit: fsx.ErrInsecurePerms) and at most MaxFileSize bytes
// (ErrTooLarge). These refusals also wrap ErrInvalid. A missing file wraps
// fs.ErrNotExist.
func Load(ctx context.Context, path string, opts Options) (*Config, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("config load: %w", err)
	}
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("config load: %w", err)
	}
	return Parse(data, opts)
}

// readFile reads path through fsx with the checks documented on Load.
func readFile(path string) (data []byte, err error) {
	r, err := fsx.Open(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("config load: %w", err)
	}
	defer func() { _ = r.Close() }() // read-only root; nothing to flush

	f, err := r.OpenRegular(filepath.Base(path))
	if err != nil {
		if errors.Is(err, fsx.ErrNotRegular) {
			return nil, fmt.Errorf("%w: config file: %w", ErrInvalid, err)
		}
		return nil, fmt.Errorf("config load: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only file

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("config load: %w", err)
	}
	if insecure(fi.Mode()) {
		return nil, fmt.Errorf("%w: config file mode %#o allows group or world access (want 0600): %w",
			ErrInvalid, fi.Mode().Perm(), fsx.ErrInsecurePerms)
	}
	if fi.Size() > MaxFileSize {
		return nil, fmt.Errorf("%w: %w: over %d bytes", ErrInvalid, ErrTooLarge, MaxFileSize)
	}
	data, err = io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("config load: read: %w", err)
	}
	if len(data) > MaxFileSize { // grew after Stat
		return nil, fmt.Errorf("%w: %w: over %d bytes", ErrInvalid, ErrTooLarge, MaxFileSize)
	}
	return data, nil
}

// Parse decodes data strictly, applies defaults, expands "~" with
// opts.Home (which must be absolute) and validates the result. On error the
// returned Config is nil.
func Parse(data []byte, opts Options) (*Config, error) {
	if !filepath.IsAbs(opts.Home) {
		return nil, errors.New("config: home directory must be an absolute path")
	}
	cfg := &Config{home: filepath.Clean(opts.Home)}
	if err := decode(data, cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	var err error
	if cfg.Output.Local, err = expandHome(cfg.Output.Local, cfg.home, "output.local"); err != nil {
		return nil, err
	}
	if cfg.StateDir, err = expandHome(cfg.StateDir, cfg.home, "state_dir"); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// decode decodes exactly one YAML document into cfg, refusing unknown and
// duplicate keys and wrong types. An empty document leaves cfg untouched.
func decode(data []byte, cfg *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return yamlError(data, err)
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case errors.Is(err, io.EOF):
		return nil
	case err != nil:
		return yamlError(data, err)
	default:
		return fmt.Errorf("%w: line %d: a second YAML document is not allowed", ErrInvalid, extra.Line)
	}
}

var (
	// typeErrRe matches yaml.v3's "line N: cannot unmarshal !!tag `value` into T"
	// (the quoted value is optional, absent for mappings and sequences).
	typeErrRe = regexp.MustCompile("^line ([0-9]+): cannot unmarshal (!!?[A-Za-z0-9:/._-]*) .*into (.+)$")
	// unknownRe matches "line N: field K not found in type T".
	unknownRe = regexp.MustCompile(`^line ([0-9]+): field (.*) not found in type \S+$`)
	// dupRe matches `line N: mapping key "K" already defined at line M`.
	dupRe = regexp.MustCompile(`^line ([0-9]+): mapping key (.*) already defined at line ([0-9]+)$`)
	// lineRe finds the "line N:" of a parser error.
	lineRe = regexp.MustCompile(`line [0-9]+:`)
	// knownTags are the YAML core tags, safe to print.
	knownTags = map[string]bool{
		"!!str": true, "!!int": true, "!!float": true, "!!bool": true, "!!null": true,
		"!!map": true, "!!seq": true, "!!binary": true, "!!timestamp": true,
	}
)

// yamlError turns a yaml error into an ErrInvalid error that names keys and
// lines but never quotes a value (yaml.v3 type errors quote the first bytes
// of the offending value).
func yamlError(data []byte, err error) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		msg := strings.TrimPrefix(err.Error(), "yaml: ")
		if strings.ContainsAny(msg, "`'\"") {
			// Parser messages may quote the input: keep the line only.
			msg = "syntax error"
			if s := lineRe.FindString(err.Error()); s != "" {
				msg = s + " syntax error"
			}
		}
		return fmt.Errorf("%w: %s", ErrInvalid, msg)
	}
	keys := keyLines(data)
	msgs := make([]string, 0, len(te.Errors))
	for _, m := range te.Errors {
		msgs = append(msgs, cleanTypeError(m, keys))
	}
	return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(msgs, "; "))
}

// cleanTypeError rewrites one yaml.v3 unmarshal error message.
func cleanTypeError(m string, keys map[int]string) string {
	at := func(line string) string {
		if k, ok := keys[atoi(line)]; ok && k != "" {
			return k + " (line " + line + ")"
		}
		return "line " + line
	}
	if s := typeErrRe.FindStringSubmatch(m); s != nil {
		got := ""
		if knownTags[s[2]] { // a custom tag is user text: not echoed
			got = " " + s[2]
		}
		return fmt.Sprintf("%s: wrong type%s (want %s)", at(s[1]), got, want(s[3]))
	}
	if s := unknownRe.FindStringSubmatch(m); s != nil {
		key := s[2]
		if k, ok := keys[atoi(s[1])]; ok && k != "" {
			key = k
		}
		return fmt.Sprintf("line %s: unknown key %s", s[1], key)
	}
	if s := dupRe.FindStringSubmatch(m); s != nil {
		return fmt.Sprintf("line %s: duplicate key %s (first defined at line %s)", s[1], s[2], s[3])
	}
	// Unknown shape: keep only the line number, never the rest.
	if line, _, ok := strings.Cut(m, ":"); ok && strings.HasPrefix(line, "line ") {
		return line + ": invalid value"
	}
	return "invalid value"
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s) // callers pass regexp-matched digits
	return n
}

// want describes a Go type from a yaml error in config.yaml terms.
func want(goType string) string {
	switch {
	case goType == "bool":
		return "true or false"
	case goType == "string":
		return "a string"
	case strings.HasPrefix(goType, "[]"):
		return "a list"
	case strings.HasPrefix(goType, "map["), strings.HasPrefix(goType, "config."):
		return "a mapping"
	}
	return "a different type"
}

// keyLines maps a line number to the dotted path of the key on that line
// ("connectors.edf.enabled"), for error messages. Lines holding several keys
// (flow mappings) map to "" (ambiguous). Best effort: nil if data does not
// parse as a node tree.
func keyLines(data []byte) map[int]string {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil
	}
	keys := map[int]string{}
	var walk func(n *yaml.Node, path string)
	walk = func(n *yaml.Node, path string) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c, path)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				p := k.Value
				if path != "" {
					p = path + "." + k.Value
				}
				if prev, seen := keys[k.Line]; seen && prev != p {
					keys[k.Line] = ""
				} else {
					keys[k.Line] = p
				}
				walk(v, p)
			}
		case yaml.SequenceNode:
			for i, c := range n.Content {
				walk(c, fmt.Sprintf("%s[%d]", path, i))
			}
		case yaml.ScalarNode, yaml.AliasNode:
		}
	}
	walk(&root, "")
	return keys
}
