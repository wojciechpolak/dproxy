// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"strings"
	"testing"
)

func TestWrapsProse(t *testing.T) {
	source := "This paragraph is written as one long line and should come back " +
		"as several, each within the limit, with no word left dangling past it.\n"
	got := wrapDocument(source, 40)
	for _, line := range strings.Split(got, "\n") {
		if len([]rune(line)) > 40 {
			t.Errorf("line over the limit: %q", line)
		}
	}
	if joined := strings.Join(strings.Fields(got), " "); joined != strings.Join(strings.Fields(source), " ") {
		t.Errorf("words changed:\n got %q\nwant %q", joined, source)
	}
}

// TestIdempotent is the property the -l check relies on: a wrapped file is a
// fixpoint, so "would wrapping change this file" is the whole test.
func TestIdempotent(t *testing.T) {
	sources := []string{
		"Some prose that will certainly need wrapping at a narrow limit like this one.\n",
		"- a list item long enough to wrap onto a second line and then a third one\n",
		"> a quoted sentence that is also long enough to need wrapping somewhere\n",
		"| a | table |\n| --- | --- |\n| that is wide enough to exceed any limit | yes |\n",
		"```\nsome code that is far too wide to fit inside the limit but must not move\n```\n",
	}
	for _, source := range sources {
		once := wrapDocument(source, 40)
		twice := wrapDocument(once, 40)
		if once != twice {
			t.Errorf("not idempotent:\n once: %q\ntwice: %q", once, twice)
		}
	}
}

func TestLeavesVerbatimBlocksAlone(t *testing.T) {
	source := strings.Join([]string{
		"# A heading that is quite long and would otherwise be wrapped by this tool",
		"",
		"```bash",
		"go test -run TestSomethingWithAVeryLongNameIndeed ./internal/config/ --verbose",
		"```",
		"",
		"| Layer | Endpoints | Visible to |",
		"|-------|-----------|------------|",
		"| Outer TLS 1.3 + ECH | local dproxy to Cloudflare | Cloudflare terminates |",
		"",
		"    indented code that is also too wide to fit within the configured limit",
		"",
		"<div class=\"a-very-long-attribute-value-that-would-otherwise-be-wrapped\">",
		"",
		"[ref]: https://example.com/a/very/long/url/that/must/stay/on/one/line/please",
		"",
	}, "\n")
	if got := wrapDocument(source, 40); got != source {
		t.Errorf("verbatim block was modified:\n%s", got)
	}
}

func TestKeepsLinksAndCodeSpansWhole(t *testing.T) {
	source := "See [the development guide](docs/development.md) and `make md-check` now.\n"
	got := wrapDocument(source, 30)
	for _, fragment := range []string{"[the development guide](docs/development.md)", "`make md-check`"} {
		if !strings.Contains(got, fragment) {
			t.Errorf("%q was broken across lines:\n%s", fragment, got)
		}
	}
}

func TestLeavesUnbreakableLinesAlone(t *testing.T) {
	// One token with no break opportunity cannot be wrapped better, so it is
	// already a fixpoint and the -l check will not flag it.
	source := "`internal/{config,logging,localproxy,tunnel,protocol,securetransport,policy,relay}`.\n"
	if got := wrapDocument(source, 80); got != source {
		t.Errorf("an unbreakable line was modified:\n%s", got)
	}
}

func TestCountsCharactersNotBytes(t *testing.T) {
	// Each em dash is three bytes and one column. A byte count would wrap
	// this line even though it fits.
	source := "a — b — c — d — e\n"
	if got := wrapDocument(source, 17); got != source {
		t.Errorf("wrapped a line that fits in characters:\n%q", got)
	}
}

func TestListContinuationIsIndented(t *testing.T) {
	source := "- an item whose text runs past the limit and must continue indented\n"
	got := wrapDocument(source, 30)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected the item to wrap: %q", got)
	}
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("continuation is not indented into the item: %q", line)
		}
	}
}

func TestBlockquoteKeepsItsPrefix(t *testing.T) {
	source := "> a quoted sentence long enough that it has to wrap at this limit\n"
	got := wrapDocument(source, 30)
	for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
		if !strings.HasPrefix(line, "> ") {
			t.Errorf("quote prefix lost: %q", line)
		}
	}
}

func TestKeepsGitHubAlertMarkerSeparate(t *testing.T) {
	source := "> [!TIP]\n> A quoted sentence long enough that it has to wrap at this limit.\n"
	got := wrapDocument(source, 40)
	if !strings.HasPrefix(got, "> [!TIP]\n> A quoted sentence") {
		t.Errorf("alert marker joined with body:\n%s", got)
	}
	if wrappedAgain := wrapDocument(got, 40); wrappedAgain != got {
		t.Errorf("alert is not idempotent:\n once: %q\ntwice: %q", got, wrappedAgain)
	}
}

func TestPreservesTrailingNewline(t *testing.T) {
	if got := wrapDocument("short line\n", 80); got != "short line\n" {
		t.Errorf("trailing newline changed: %q", got)
	}
	if got := wrapDocument("no trailing newline", 80); got != "no trailing newline" {
		t.Errorf("a newline was added: %q", got)
	}
}
