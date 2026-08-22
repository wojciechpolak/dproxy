// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"errors"
	"strings"
	"testing"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestParseHostPatternCanonicalizes(t *testing.T) {
	cases := []struct {
		raw    string
		want   string
		kind   PatternKind
		suffix string
	}{
		{raw: "api.openai.com", want: "api.openai.com", kind: PatternExact, suffix: "api.openai.com"},
		{raw: "API.OpenAI.COM", want: "api.openai.com", kind: PatternExact, suffix: "api.openai.com"},
		{raw: "api.anthropic.com.", want: "api.anthropic.com", kind: PatternExact, suffix: "api.anthropic.com"},
		{raw: "  claude.ai  ", want: "claude.ai", kind: PatternExact, suffix: "claude.ai"},
		{raw: "*.openai.com", want: "*.openai.com", kind: PatternWildcard, suffix: "openai.com"},
		{raw: "*.OAIStatic.com.", want: "*.oaistatic.com", kind: PatternWildcard, suffix: "oaistatic.com"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			pattern, err := ParseHostPattern(tc.raw)
			if err != nil {
				t.Fatalf("ParseHostPattern(%q) = error %v", tc.raw, err)
			}
			if got := pattern.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
			if pattern.Kind() != tc.kind {
				t.Errorf("Kind() = %v, want %v", pattern.Kind(), tc.kind)
			}
			if pattern.Suffix() != tc.suffix {
				t.Errorf("Suffix() = %q, want %q", pattern.Suffix(), tc.suffix)
			}
		})
	}
}

func TestAllowlistReturnsIndependentPatterns(t *testing.T) {
	list, err := ParseAllowlist([]string{"api.openai.com", "*.openai.com", "api.openai.com"})
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	if list.Len() != 2 {
		t.Fatalf("ParseAllowlist length = %d, want 2", list.Len())
	}
	patterns := list.Patterns()
	patterns[0] = HostPattern{}
	if list.Patterns()[0].String() != "api.openai.com" {
		t.Fatal("Patterns returned mutable allowlist storage")
	}
	checker := NewChecker(list, nil)
	if checker.Allowlist().String() != list.String() {
		t.Fatal("Checker.Allowlist changed the configured patterns")
	}
	if PatternExact.String() != "exact" || PatternWildcard.String() != "wildcard" || PatternKind(99).String() != "PatternKind(99)" {
		t.Fatal("pattern kind names changed")
	}
	if (HostPattern{}).matches("") || (HostPattern{kind: PatternKind(99), host: "example"}).matches("example") {
		t.Fatal("zero or unknown pattern matched a host")
	}
}

func TestParseHostPatternRejects(t *testing.T) {
	cases := []string{
		"",
		"   ",
		".",
		"..",
		"example..com",
		"-example.com",
		"example-.com",
		"exa mple.com",
		"example.com/path",
		"example.com:443",
		"http://example.com",
		"*",
		"*.com.",
		"*.",
		"foo.*.com",
		"exa*mple.com",
		"127.0.0.1",
		"::1",
		"[::1]",
		"192.168.1.1",
		"10.0.0.1",
		"xn--bcher-kva.example.comü",
		"bücher.example.com",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("a.", 130) + "com",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if pattern, err := ParseHostPattern(raw); err == nil {
				t.Fatalf("ParseHostPattern(%q) = %q, want error", raw, pattern)
			}
		})
	}
}

func TestParseHostPatternKeepsALabels(t *testing.T) {
	pattern, err := ParseHostPattern("xn--bcher-kva.example.com")
	if err != nil {
		t.Fatalf("ParseHostPattern = error %v", err)
	}
	if pattern.String() != "xn--bcher-kva.example.com" {
		t.Errorf("String() = %q", pattern.String())
	}
}

func TestParseAllowlistDeduplicates(t *testing.T) {
	list, err := ParseAllowlist([]string{"api.openai.com", "API.OPENAI.COM.", "*.openai.com"})
	if err != nil {
		t.Fatalf("ParseAllowlist = error %v", err)
	}
	if list.Len() != 2 {
		t.Fatalf("Len() = %d, want 2 (%s)", list.Len(), list)
	}
	if got, want := list.String(), "api.openai.com *.openai.com"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestParseAllowlistReportsFirstInvalidEntry(t *testing.T) {
	_, err := ParseAllowlist([]string{"api.openai.com", "10.0.0.1"})
	if err == nil {
		t.Fatal("ParseAllowlist = nil error, want failure on the IP literal")
	}
	if !strings.Contains(err.Error(), "10.0.0.1") {
		t.Errorf("error %v does not name the offending entry", err)
	}
}

func TestZeroAllowlistPermitsNothing(t *testing.T) {
	var list Allowlist
	if !list.IsEmpty() || list.Len() != 0 {
		t.Fatalf("zero Allowlist is not empty: %s", list)
	}
}

func TestAllowAllPermitsAnyValidHostnameOnPort443(t *testing.T) {
	list := AllowAll()
	if !list.AllowsAll() || list.IsEmpty() || list.String() != "all" {
		t.Fatalf("AllowAll() = %q, AllowsAll %t, IsEmpty %t", list, list.AllowsAll(), list.IsEmpty())
	}
	checker := NewChecker(list, nil)
	for _, authority := range []string{"example.com:443", "api.openai.com:443", "service.example.org:443"} {
		if _, decision := checker.CheckAuthority(authority); !decision.Allowed() {
			t.Errorf("%s denied: %s", authority, decision)
		}
	}
	for _, authority := range []string{"example.com:80", "127.0.0.1:443"} {
		if _, decision := checker.CheckAuthority(authority); decision.Allowed() {
			t.Errorf("%s allowed", authority)
		}
	}
}

func TestReadAllowlistSkipsCommentsAndBlanks(t *testing.T) {
	const file = `
# OpenAI
api.openai.com

  *.openai.com  # trailing text is part of the pattern, so keep comments alone
`
	if _, err := ReadAllowlist(strings.NewReader(file)); err == nil {
		t.Fatal("ReadAllowlist accepted a trailing comment on a pattern line")
	}

	list, err := ReadAllowlist(strings.NewReader("\n# OpenAI\napi.openai.com\n\n  *.openai.com\n"))
	if err != nil {
		t.Fatalf("ReadAllowlist = error %v", err)
	}
	if got, want := list.String(), "api.openai.com *.openai.com"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestReadAllowlistReportsLineNumber(t *testing.T) {
	_, err := ReadAllowlist(strings.NewReader("api.openai.com\n\n127.0.0.1\n"))
	if err == nil {
		t.Fatal("ReadAllowlist = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error %v does not name line 3", err)
	}
}

func TestReadAllowlistReportsReadFailure(t *testing.T) {
	if _, err := ReadAllowlist(errReader{}); err == nil || !strings.Contains(err.Error(), "read allowlist") {
		t.Fatalf("ReadAllowlist read error = %v", err)
	}
}

func TestReadAllowlistOfShippedDefault(t *testing.T) {
	list, err := ReadAllowlist(strings.NewReader(shippedExample))
	if err != nil {
		t.Fatalf("ReadAllowlist = error %v", err)
	}
	if list.Len() != 12 {
		t.Fatalf("Len() = %d, want 12 (%s)", list.Len(), list)
	}
}

// shippedExample mirrors configs/allowlist.example, duplicated so this test
// does not depend on a path outside the package.
const shippedExample = `# comment
api.openai.com
*.openai.com
chatgpt.com
*.chatgpt.com
*.oaistatic.com
*.oaiusercontent.com

api.anthropic.com
*.anthropic.com
claude.ai
*.claude.ai
claude.com
*.claude.com
`
