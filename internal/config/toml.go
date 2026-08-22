// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// The subset of TOML dproxy configuration is written in, parsed in-process as
// in DUD: a configuration format is worth having, and not worth a dependency in
// a module that otherwise has none.
//
// The subset:
//
//	# a comment
//	listen = "127.0.0.1:18080"      # trailing comments are allowed
//	allowlist = ["api.openai.com", "*.openai.com"]
//
//	[timeouts]
//	dial = "10s"
//
//	[log]
//	include_targets = false
//
// Supported: one level of tables, bare keys, basic and literal strings,
// booleans, decimal integers, and arrays of strings which may span lines.
// Not supported: nested or inline tables, arrays of tables, dotted keys, quoted
// keys, floats, datetimes, multi-line strings, and non-decimal integers. Each
// is a parse error naming the line, never something skipped.
//
// Three rules make the format fail closed, and they are why it is hand-written:
// a duplicate key is an error, an unknown key or table is an error, and a value
// that does not parse is an error. Nothing falls back to a default because the
// operator wrote it wrong.

// tomlDocument is a parsed configuration file: a flat map from qualified key
// ("listen", "timeouts.dial") to the raw text of its value.
type tomlDocument struct {
	// path is kept for error messages only.
	path    string
	entries map[string]tomlEntry
	// order preserves file order, so an unknown-key error reports the first
	// offending key rather than a random one.
	order []string
}

// tomlEntry is one key's unparsed value and the line it was written on.
type tomlEntry struct {
	raw  string
	line int
}

// parseTOML reads the supported subset. path appears in error messages.
func parseTOML(r io.Reader, path string) (*tomlDocument, error) {
	document := &tomlDocument{path: path, entries: map[string]tomlEntry{}}
	scanner := bufio.NewScanner(r)
	section := ""
	lineNumber := 0

	readLine := func() (string, bool) {
		if !scanner.Scan() {
			return "", false
		}
		lineNumber++
		return strings.TrimSpace(strings.TrimSuffix(scanner.Text(), "\r")), true
	}

	for {
		line, ok := readLine()
		if !ok {
			break
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			name, err := parseTableHeader(line)
			if err != nil {
				return nil, document.errorAt(lineNumber, err)
			}
			section = name
			continue
		}

		name, rest, found := strings.Cut(line, "=")
		if !found {
			return nil, document.errorAt(lineNumber, fmt.Errorf("expected key = value"))
		}
		name = strings.TrimSpace(name)
		if err := validateBareKey(name); err != nil {
			return nil, document.errorAt(lineNumber, err)
		}

		startLine := lineNumber
		raw, depth, err := scanValue(strings.TrimSpace(rest), 0)
		if err != nil {
			return nil, document.errorAt(startLine, err)
		}
		// An array may continue on following lines, carrying its bracket
		// depth with it. Nothing else may.
		for depth > 0 {
			continuation, ok := readLine()
			if !ok {
				return nil, document.errorAt(startLine, fmt.Errorf("unterminated array"))
			}
			fragment, continued, scanErr := scanValue(continuation, depth)
			if scanErr != nil {
				return nil, document.errorAt(lineNumber, scanErr)
			}
			raw += fragment
			depth = continued
		}
		if raw == "" {
			return nil, document.errorAt(startLine, fmt.Errorf("key %q has no value", name))
		}

		key := name
		if section != "" {
			key = section + "." + name
		}
		if previous, exists := document.entries[key]; exists {
			return nil, document.errorAt(startLine,
				fmt.Errorf("duplicate key %q, already set on line %d", key, previous.line))
		}
		document.entries[key] = tomlEntry{raw: raw, line: startLine}
		document.order = append(document.order, key)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return document, nil
}

// parseTableHeader validates "[name]" and returns the table name.
func parseTableHeader(line string) (string, error) {
	if !strings.HasSuffix(line, "]") {
		return "", fmt.Errorf("malformed table header")
	}
	name := strings.TrimSpace(line[1 : len(line)-1])
	if strings.HasPrefix(name, "[") {
		return "", fmt.Errorf("arrays of tables are not supported")
	}
	if strings.Contains(name, ".") {
		return "", fmt.Errorf("nested tables are not supported")
	}
	if err := validateBareKey(name); err != nil {
		return "", fmt.Errorf("table name: %w", err)
	}
	return name, nil
}

// validateBareKey enforces the only key syntax this subset accepts. Quoted keys
// are rejected, not unquoted, so no key arrives under two spellings.
func validateBareKey(name string) error {
	if name == "" {
		return fmt.Errorf("empty key")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return fmt.Errorf("key %q must use only letters, digits, underscores, and hyphens", name)
		}
	}
	return nil
}

// scanValue returns one line's value text with any trailing comment removed,
// and the bracket depth left open, carried in and out so an array may span
// lines.
//
// It is quote-aware: a "#" inside a string is part of the string. Getting that
// wrong would silently truncate a pin or a hostname into a shorter,
// still-parsable value.
func scanValue(line string, depth int) (string, int, error) {
	var (
		value   strings.Builder
		quote   byte
		escaped bool
	)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			value.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case quote == '"' && c == '\\':
				escaped = true
			case c == quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '#':
			// Everything from here to the end of the line is a comment.
			return strings.TrimSpace(value.String()), depth, nil
		case '"', '\'':
			quote = c
			value.WriteByte(c)
		case '[':
			depth++
			value.WriteByte(c)
		case ']':
			depth--
			if depth < 0 {
				return "", 0, fmt.Errorf("unbalanced \"]\"")
			}
			value.WriteByte(c)
		default:
			value.WriteByte(c)
		}
	}
	if quote != 0 {
		return "", 0, fmt.Errorf("unterminated string")
	}
	return strings.TrimSpace(value.String()), depth, nil
}

// errorAt builds an error naming the file and line.
func (d *tomlDocument) errorAt(line int, err error) error {
	return fmt.Errorf("%s line %d: %w", d.path, line, err)
}

// rejectUnknownKeys fails on the first key the schema does not define, naming
// it and its line.
func (d *tomlDocument) rejectUnknownKeys(known []string) error {
	permitted := make(map[string]bool, len(known))
	for _, key := range known {
		permitted[key] = true
	}
	for _, key := range d.order {
		if !permitted[key] {
			return d.errorAt(d.entries[key].line, fmt.Errorf("unknown key %q", key))
		}
	}
	return nil
}

// applyString assigns a quoted string value when the key is present.
func (d *tomlDocument) applyString(key string, into *string) error {
	entry, ok := d.entries[key]
	if !ok {
		return nil
	}
	value, err := unquote(entry.raw)
	if err != nil {
		return d.errorAt(entry.line, fmt.Errorf("%s must be a quoted string", key))
	}
	*into = value
	return nil
}

// applyBool assigns a boolean value when the key is present.
func (d *tomlDocument) applyBool(key string, into *bool) error {
	entry, ok := d.entries[key]
	if !ok {
		return nil
	}
	switch entry.raw {
	case "true":
		*into = true
	case "false":
		*into = false
	default:
		return d.errorAt(entry.line, fmt.Errorf("%s must be true or false", key))
	}
	return nil
}

// applyInt assigns a decimal integer value when the key is present.
func (d *tomlDocument) applyInt(key string, into *int) error {
	entry, ok := d.entries[key]
	if !ok {
		return nil
	}
	value, err := strconv.Atoi(entry.raw)
	if err != nil {
		return d.errorAt(entry.line, fmt.Errorf("%s must be a decimal integer", key))
	}
	*into = value
	return nil
}

// applyDuration assigns a quoted Go duration string ("10s", "5m"). TOML has no
// duration type, so the unit is always explicit.
func (d *tomlDocument) applyDuration(key string, into *time.Duration) error {
	entry, ok := d.entries[key]
	if !ok {
		return nil
	}
	text, err := unquote(entry.raw)
	if err != nil {
		return d.errorAt(entry.line, fmt.Errorf("%s must be a quoted duration such as \"10s\"", key))
	}
	value, err := time.ParseDuration(text)
	if err != nil {
		return d.errorAt(entry.line, fmt.Errorf("%s is not a duration: %w", key, err))
	}
	*into = value
	return nil
}

// applyStrings assigns an array of quoted strings when the key is present.
func (d *tomlDocument) applyStrings(key string, into *[]string) error {
	entry, ok := d.entries[key]
	if !ok {
		return nil
	}
	values, err := parseStringArray(entry.raw)
	if err != nil {
		return d.errorAt(entry.line, fmt.Errorf("%s: %w", key, err))
	}
	*into = values
	return nil
}

// unquote decodes both TOML string forms: basic (double quotes, escapes apply)
// and literal (single quotes, they do not). strconv.Unquote cannot do the
// second: in Go single quotes delimit a rune, so it rejects anything longer.
func unquote(raw string) (string, error) {
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1], nil
	}
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		value, err := strconv.Unquote(raw)
		if err != nil {
			return "", fmt.Errorf("invalid string: %w", err)
		}
		return value, nil
	}
	return "", fmt.Errorf("value must be a quoted string")
}

// parseStringArray decodes ["a", "b"], with an optional trailing comma.
func parseStringArray(raw string) ([]string, error) {
	if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
		return nil, fmt.Errorf("must be an array in square brackets")
	}
	content := strings.TrimSpace(raw[1 : len(raw)-1])
	if content == "" {
		return []string{}, nil
	}
	elements, err := splitArrayElements(content)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(elements))
	for _, element := range elements {
		value, err := unquote(element)
		if err != nil {
			return nil, fmt.Errorf("array values must be quoted strings, got %s", element)
		}
		values = append(values, value)
	}
	return values, nil
}

// splitArrayElements splits on commas that are not inside a string.
func splitArrayElements(content string) ([]string, error) {
	var (
		elements []string
		current  strings.Builder
		quote    byte
		escaped  bool
	)
	for i := 0; i < len(content); i++ {
		c := content[i]
		if quote != 0 {
			current.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case quote == '"' && c == '\\':
				escaped = true
			case c == quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
			current.WriteByte(c)
		case ',':
			elements = append(elements, strings.TrimSpace(current.String()))
			current.Reset()
		case '[', ']':
			return nil, fmt.Errorf("nested arrays are not supported")
		default:
			current.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated string")
	}
	last := strings.TrimSpace(current.String())
	if last != "" {
		elements = append(elements, last)
	}
	for _, element := range elements {
		if element == "" {
			return nil, fmt.Errorf("empty array element")
		}
	}
	return elements, nil
}
