// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import "testing"

// mustDestination takes an authority so the tables read like CONNECT lines.
func mustDestination(t *testing.T, authority string) Destination {
	t.Helper()
	destination, err := ParseAuthority(authority)
	if err != nil {
		t.Fatalf("ParseAuthority(%q) = error %v", authority, err)
	}
	return destination
}

func mustAllowlist(t *testing.T, entries ...string) Allowlist {
	t.Helper()
	list, err := ParseAllowlist(entries)
	if err != nil {
		t.Fatalf("ParseAllowlist(%v) = error %v", entries, err)
	}
	return list
}

// TestWildcardDoesNotConfuseSuffixes: every "want false" line is a name a
// plain suffix comparison would let through.
func TestWildcardDoesNotConfuseSuffixes(t *testing.T) {
	pattern, err := ParseHostPattern("*.openai.com")
	if err != nil {
		t.Fatalf("ParseHostPattern = error %v", err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"api.openai.com", true},
		{"chat.api.openai.com", true},
		{"a.b.c.openai.com", true},
		{"API.OpenAI.com", true},

		{"openai.com", false},     // the bare suffix is not covered
		{"evilopenai.com", false}, // no label boundary
		{"notopenai.com", false},
		{"xopenai.com", false},
		{"openai.com.evil.test", false}, // suffix in the middle
		{"api.openai.com.evil.test", false},
		{"api.openai.como", false},
		{"api.openai.co", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			destination := mustDestination(t, tc.host+":443")
			if got := pattern.Matches(destination); got != tc.want {
				t.Errorf("Matches(%q) = %v, want %v", destination.Host(), got, tc.want)
			}
		})
	}
}

func TestExactPatternMatchesOnlyItself(t *testing.T) {
	pattern, err := ParseHostPattern("api.anthropic.com")
	if err != nil {
		t.Fatalf("ParseHostPattern = error %v", err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"api.anthropic.com", true},
		{"API.ANTHROPIC.COM", true},
		{"anthropic.com", false},
		{"sub.api.anthropic.com", false},
		{"api.anthropic.com.evil.test", false},
		{"xapi.anthropic.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			destination := mustDestination(t, tc.host+":443")
			if got := pattern.Matches(destination); got != tc.want {
				t.Errorf("Matches(%q) = %v, want %v", destination.Host(), got, tc.want)
			}
		})
	}
}

func TestPatternDoesNotMatchTheZeroDestination(t *testing.T) {
	for _, entry := range []string{"api.openai.com", "*.openai.com"} {
		pattern, err := ParseHostPattern(entry)
		if err != nil {
			t.Fatalf("ParseHostPattern(%q) = error %v", entry, err)
		}
		if pattern.Matches(Destination{}) {
			t.Errorf("pattern %s matches the zero Destination", pattern)
		}
	}
}

func TestAllowlistPermits(t *testing.T) {
	list := mustAllowlist(t,
		"api.openai.com", "*.openai.com", "claude.ai", "*.claude.ai",
	)
	cases := []struct {
		host string
		want bool
	}{
		{"api.openai.com", true},
		{"cdn.openai.com", true},
		{"claude.ai", true},
		{"www.claude.ai", true},
		{"openai.com", false},
		{"claude.com", false},
		{"claudeai.com", false},
		{"api.openai.com.attacker.test", false},
		{"example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			decision := list.Permits(mustDestination(t, tc.host+":443"))
			if decision.Allowed() != tc.want {
				t.Fatalf("Permits(%q) = %s, want allowed=%v", tc.host, decision, tc.want)
			}
			if !tc.want && decision.Reason() != DenyNotAllowlisted {
				t.Errorf("Reason() = %s, want %s", decision.Reason(), DenyNotAllowlisted)
			}
		})
	}
}

// TestEmptyAllowlistPermitsNothing is the default a misconfiguration falls to.
func TestEmptyAllowlistPermitsNothing(t *testing.T) {
	var list Allowlist
	decision := list.Permits(mustDestination(t, "api.openai.com:443"))
	if decision.Allowed() {
		t.Fatal("the zero Allowlist permitted a destination")
	}
	if decision.Reason() != DenyNotAllowlisted {
		t.Errorf("Reason() = %s", decision.Reason())
	}
}

func TestAllowlistPermitsRejectsTheZeroDestination(t *testing.T) {
	list := mustAllowlist(t, "api.openai.com")
	decision := list.Permits(Destination{})
	if decision.Allowed() {
		t.Fatal("the zero Destination was permitted")
	}
	if decision.Reason() != DenyMalformedAuthority {
		t.Errorf("Reason() = %s, want %s", decision.Reason(), DenyMalformedAuthority)
	}
}

// TestAllowlistRechecksThePort covers a Destination that arrived over the wire
// rather than through ParseAuthority.
func TestAllowlistRechecksThePort(t *testing.T) {
	list := mustAllowlist(t, "api.openai.com")
	forged := Destination{host: "api.openai.com", port: 8443}
	decision := list.Permits(forged)
	if decision.Allowed() {
		t.Fatal("a forged non-443 destination was permitted")
	}
	if decision.Reason() != DenyPortNotAllowed {
		t.Errorf("Reason() = %s, want %s", decision.Reason(), DenyPortNotAllowed)
	}
}
