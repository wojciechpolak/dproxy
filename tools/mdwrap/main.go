// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Command mdwrap hard-wraps Markdown prose at a column limit.
//
// markdownfmt has no width option: -soft-wraps preserves existing breaks rather
// than creating them, and its default joins paragraphs into one long line. So
// mdwrap makes the breaks and "markdownfmt -soft-wraps" keeps them.
//
// It follows gofmt's interface, including "gofmt -l": a file is correctly
// wrapped when wrapping it changes nothing. A line with no break opportunity
// before the limit is left alone, so it is already a fixpoint.
//
//	mdwrap file.md          # write the result to stdout
//	mdwrap -w file.md ...   # rewrite the files
//	mdwrap -l file.md ...   # list files that would change
//
// Left alone, where a break would change meaning or look wrong: fenced and
// indented code, tables (markdownfmt aligns those past the limit by design),
// headings, link reference definitions, and HTML blocks. Inline code spans and
// complete links are unbreakable tokens, so no break lands inside a URL.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	write = flag.Bool("w", false, "write the result to the source file instead of stdout")
	list  = flag.Bool("l", false, "list files whose wrapping differs from mdwrap's")
	width = flag.Int("width", 80, "column limit")
)

var (
	fencePattern        = regexp.MustCompile("^\\s*(```|~~~)")
	tablePattern        = regexp.MustCompile(`^\s*\|`)
	headingPattern      = regexp.MustCompile(`^\s*#{1,6}\s`)
	linkDefPattern      = regexp.MustCompile(`^\s*\[[^\]]+\]:\s`)
	htmlPattern         = regexp.MustCompile(`^\s*<`)
	blockquotePattern   = regexp.MustCompile(`^\s*>`)
	quotePrefixPattern  = regexp.MustCompile(`^\s*>\s?`)
	alertMarkerPattern  = regexp.MustCompile(`^\s*>\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$`)
	listPattern         = regexp.MustCompile(`^(\s*)([-*+]|\d+\.)(\s+)(.*)$`)
	indentedCodePattern = regexp.MustCompile(`^(\t| {4,})\S`)
	indentPattern       = regexp.MustCompile(`^\s*`)
	// linkPattern matches a complete inline or reference link, kept whole so
	// no break lands inside a destination.
	linkPattern = regexp.MustCompile(`^(\[[^\]]*\]\([^)]*\)|\[[^\]]*\]\[[^\]]*\])`)
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: mdwrap [flags] file.md ...\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	changed := false
	failed := false
	for _, path := range flag.Args() {
		source, err := os.ReadFile(path) // #nosec G304 -- paths come from the caller's command line.
		if err != nil {
			fmt.Fprintf(os.Stderr, "mdwrap: %v\n", err)
			failed = true
			continue
		}
		wrapped := wrapDocument(string(source), *width)
		switch {
		case *list:
			if wrapped != string(source) {
				fmt.Println(path)
				changed = true
			}
		case *write:
			if wrapped == string(source) {
				continue
			}
			if err := os.WriteFile(path, []byte(wrapped), 0o644); err != nil { // #nosec G306 -- documentation is world-readable.
				fmt.Fprintf(os.Stderr, "mdwrap: %v\n", err)
				failed = true
			}
		default:
			fmt.Print(wrapped)
		}
	}
	switch {
	case failed:
		os.Exit(1)
	case *list && changed:
		os.Exit(1)
	}
}

// wrapDocument rewraps every prose block in a Markdown document.
func wrapDocument(source string, limit int) string {
	lines := strings.Split(source, "\n")
	out := make([]string, 0, len(lines))
	fenced := false
	fenceMarker := ""

	for i := 0; i < len(lines); {
		line := lines[i]

		if fenced {
			out = append(out, line)
			if match := fencePattern.FindStringSubmatch(line); match != nil &&
				strings.HasPrefix(strings.TrimSpace(line), fenceMarker) {
				fenced = false
			}
			i++
			continue
		}
		if match := fencePattern.FindStringSubmatch(line); match != nil {
			fenced = true
			fenceMarker = match[1]
			out = append(out, line)
			i++
			continue
		}
		if verbatim(line) {
			out = append(out, line)
			i++
			continue
		}

		if blockquotePattern.MatchString(line) {
			block := []string{line}
			j := i + 1
			for j < len(lines) && blockquotePattern.MatchString(lines[j]) && strings.TrimSpace(lines[j]) != ">" {
				block = append(block, lines[j])
				j++
			}
			prefix := quotePrefixPattern.FindString(block[0])
			parts := make([]string, 0, len(block))
			for _, quoted := range block {
				parts = append(parts, strings.TrimSpace(quotePrefixPattern.ReplaceAllString(quoted, "")))
			}
			out = append(out, wrapText(strings.Join(parts, " "), prefix, prefix, limit)...)
			i = j
			continue
		}

		// Collect the following lines that continue the block.
		block := []string{line}
		j := i + 1
		for j < len(lines) && continues(lines[j]) {
			block = append(block, lines[j])
			j++
		}

		var firstPrefix, restPrefix, text string
		if match := listPattern.FindStringSubmatch(block[0]); match != nil {
			indent, marker, gap, rest := match[1], match[2], match[3], match[4]
			firstPrefix = indent + marker + gap
			restPrefix = strings.Repeat(" ", utf8.RuneCountInString(firstPrefix))
			parts := []string{rest}
			for _, continuation := range block[1:] {
				parts = append(parts, strings.TrimSpace(continuation))
			}
			text = strings.Join(parts, " ")
		} else {
			firstPrefix = indentPattern.FindString(block[0])
			restPrefix = firstPrefix
			parts := make([]string, 0, len(block))
			for _, part := range block {
				parts = append(parts, strings.TrimSpace(part))
			}
			text = strings.Join(parts, " ")
		}

		out = append(out, wrapText(text, firstPrefix, restPrefix, limit)...)
		i = j
	}
	return strings.Join(out, "\n")
}

// verbatim reports a line that is copied through untouched.
func verbatim(line string) bool {
	return strings.TrimSpace(line) == "" ||
		tablePattern.MatchString(line) ||
		headingPattern.MatchString(line) ||
		linkDefPattern.MatchString(line) ||
		htmlPattern.MatchString(line) ||
		alertMarkerPattern.MatchString(line) ||
		indentedCodePattern.MatchString(line)
}

// continues reports a line that belongs to the prose block above it.
func continues(line string) bool {
	return !(strings.TrimSpace(line) == "" ||
		fencePattern.MatchString(line) ||
		verbatim(line) ||
		blockquotePattern.MatchString(line) ||
		listPattern.MatchString(line))
}

// wrapText greedily wraps to the limit in characters, not bytes: these
// documents are full of em dashes, and a byte count would call a 79-character
// line an 81-character one.
func wrapText(text, firstPrefix, restPrefix string, limit int) []string {
	tokens := tokenize(text)
	if len(tokens) == 0 {
		return []string{strings.TrimRight(firstPrefix, " ")}
	}
	var lines []string
	current := firstPrefix + tokens[0]
	for _, token := range tokens[1:] {
		candidate := current + " " + token
		if utf8.RuneCountInString(candidate) > limit && strings.TrimSpace(current) != "" {
			lines = append(lines, current)
			current = restPrefix + token
		} else {
			current = candidate
		}
	}
	return append(lines, current)
}

// tokenize splits on spaces, keeping inline code spans and complete links whole
// so a break never lands inside one.
func tokenize(text string) []string {
	var (
		tokens  []string
		current strings.Builder
	)
	for i := 0; i < len(text); {
		switch {
		case text[i] == '`':
			if end := strings.IndexByte(text[i+1:], '`'); end >= 0 {
				current.WriteString(text[i : i+end+2])
				i += end + 2
				continue
			}
		case text[i] == '[':
			if match := linkPattern.FindString(text[i:]); match != "" {
				current.WriteString(match)
				i += len(match)
				continue
			}
		case text[i] == ' ':
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			i++
			continue
		}
		current.WriteByte(text[i])
		i++
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}
