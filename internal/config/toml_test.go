// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"strings"
	"testing"
	"time"
)

func parse(t *testing.T, content string) (*tomlDocument, error) {
	t.Helper()
	return parseTOML(strings.NewReader(content), "test.toml")
}

func mustParse(t *testing.T, content string) *tomlDocument {
	t.Helper()
	document, err := parse(t, content)
	if err != nil {
		t.Fatalf("parseTOML = %v", err)
	}
	return document
}

func TestTOMLReadsScalars(t *testing.T) {
	document := mustParse(t, `
# a comment
listen = "127.0.0.1:18080"
count  = 42
flag   = true

[log]
level = 'info'
`)
	var (
		listen string
		level  string
		count  int
		flag   bool
	)
	if err := document.applyString("listen", &listen); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if err := document.applyString("log.level", &level); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if err := document.applyInt("count", &count); err != nil {
		t.Fatalf("applyInt = %v", err)
	}
	if err := document.applyBool("flag", &flag); err != nil {
		t.Fatalf("applyBool = %v", err)
	}
	if listen != "127.0.0.1:18080" || level != "info" || count != 42 || !flag {
		t.Errorf("got %q %q %d %v", listen, level, count, flag)
	}
}

func TestTOMLLeavesAbsentKeysAlone(t *testing.T) {
	document := mustParse(t, "listen = \"127.0.0.1:1\"\n")
	value := "unchanged"
	number := 7
	flag := true
	duration := time.Minute
	list := []string{"kept"}
	if err := document.applyString("absent", &value); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if err := document.applyInt("absent", &number); err != nil {
		t.Fatalf("applyInt = %v", err)
	}
	if err := document.applyBool("absent", &flag); err != nil {
		t.Fatalf("applyBool = %v", err)
	}
	if err := document.applyDuration("absent", &duration); err != nil {
		t.Fatalf("applyDuration = %v", err)
	}
	if err := document.applyStrings("absent", &list); err != nil {
		t.Fatalf("applyStrings = %v", err)
	}
	if value != "unchanged" || number != 7 || !flag || duration != time.Minute || len(list) != 1 {
		t.Error("an absent key overwrote a default")
	}
	if document.has("absent") {
		t.Error("has() reports an absent key")
	}
}

// TestTOMLKeepsHashInsideStrings: a "#" inside a quoted value is data.
// Truncating there would silently shorten a pin or a hostname.
func TestTOMLKeepsHashInsideStrings(t *testing.T) {
	document := mustParse(t, `
pin  = "sha256:aa#bb"     # rotated 2026-08-19
note = 'a # inside a literal string'
list = ["a#b", "c"]  # trailing comment after an array
`)
	var pin, note string
	var list []string
	if err := document.applyString("pin", &pin); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if err := document.applyString("note", &note); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if err := document.applyStrings("list", &list); err != nil {
		t.Fatalf("applyStrings = %v", err)
	}
	if pin != "sha256:aa#bb" {
		t.Errorf("pin = %q", pin)
	}
	if note != "a # inside a literal string" {
		t.Errorf("note = %q", note)
	}
	if len(list) != 2 || list[0] != "a#b" || list[1] != "c" {
		t.Errorf("list = %q", list)
	}
}

func TestTOMLRejectsDuplicateKeys(t *testing.T) {
	cases := map[string]string{
		"root":            "ech = \"required\"\nech = \"insecure-disabled\"\n",
		"inside a table":  "[log]\nlevel = \"info\"\nlevel = \"debug\"\n",
		"across comments": "ech = \"required\"\n# comment\nech = \"required\"\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, content)
			if err == nil {
				t.Fatal("parseTOML accepted a duplicate key")
			}
			if !strings.Contains(err.Error(), "duplicate key") {
				t.Errorf("error = %v", err)
			}
		})
	}
}

// TestTOMLSameKeyInDifferentTables guards the qualifying logic: log.level and
// limits.level are different keys and must not collide.
func TestTOMLSameKeyInDifferentTables(t *testing.T) {
	document := mustParse(t, "[log]\nlevel = \"info\"\n\n[limits]\nlevel = \"high\"\n")
	var log, limits string
	if err := document.applyString("log.level", &log); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if err := document.applyString("limits.level", &limits); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if log != "info" || limits != "high" {
		t.Errorf("log = %q, limits = %q", log, limits)
	}
}

func TestTOMLRejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name    string
		content string
		message string
	}{
		{"no equals sign", "listen\n", "expected key = value"},
		{"empty key", "= \"value\"\n", "empty key"},
		{"quoted key", "\"listen\" = \"x\"\n", "must use only letters"},
		{"dotted key", "log.level = \"info\"\n", "must use only letters"},
		{"missing value", "listen =\n", "has no value"},
		{"unterminated string", "listen = \"127.0.0.1\n", "unterminated string"},
		{"unterminated literal", "listen = '127.0.0.1\n", "unterminated string"},
		{"malformed table", "[log\nlevel = \"info\"\n", "malformed table"},
		{"nested table", "[log.file]\nlevel = \"info\"\n", "nested tables"},
		{"array of tables", "[[peer]]\nname = \"x\"\n", "arrays of tables"},
		{"empty table name", "[]\nlevel = \"info\"\n", "table name"},
		{"unbalanced bracket", "list = \"a\"]\n", "unbalanced"},
		{"unterminated array", "list = [\"a\",\n", "unterminated array"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.content)
			if err == nil {
				t.Fatalf("parseTOML(%q) = nil, want error", tc.content)
			}
			if !strings.Contains(err.Error(), tc.message) {
				t.Errorf("error = %v, want it to mention %q", err, tc.message)
			}
			if !strings.Contains(err.Error(), "test.toml line") {
				t.Errorf("error = %v, want it to name the file and line", err)
			}
		})
	}
}

func TestTOMLReportsTheOffendingLine(t *testing.T) {
	_, err := parse(t, "a = \"1\"\n\n# comment\nb = \"2\"\nbroken\n")
	if err == nil {
		t.Fatal("parseTOML = nil, want error")
	}
	if !strings.Contains(err.Error(), "line 5") {
		t.Errorf("error = %v, want it to name line 5", err)
	}
}

func TestTOMLRejectsWrongValueTypes(t *testing.T) {
	document := mustParse(t, `
unquoted = bare
number   = "12"
boolish  = "true"
flag     = yes
count    = 1_000
hex      = 0x10
`)
	var text string
	var number int
	var flag bool
	var duration time.Duration
	cases := []struct {
		name string
		err  error
	}{
		{"unquoted string", document.applyString("unquoted", &text)},
		{"quoted integer", document.applyInt("number", &number)},
		{"quoted boolean", document.applyBool("boolish", &flag)},
		{"yes is not a boolean", document.applyBool("flag", &flag)},
		{"underscored integer", document.applyInt("count", &number)},
		{"hexadecimal integer", document.applyInt("hex", &number)},
		{"integer as duration", document.applyDuration("number", &duration)},
	}
	for _, tc := range cases {
		if tc.err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}

func TestTOMLDurations(t *testing.T) {
	document := mustParse(t, "dial = \"10s\"\nidle = \"5m\"\nlifetime = \"0s\"\nbad = \"10 seconds\"\n")
	var dial, idle, lifetime, bad time.Duration
	if err := document.applyDuration("dial", &dial); err != nil {
		t.Fatalf("applyDuration = %v", err)
	}
	if err := document.applyDuration("idle", &idle); err != nil {
		t.Fatalf("applyDuration = %v", err)
	}
	if err := document.applyDuration("lifetime", &lifetime); err != nil {
		t.Fatalf("applyDuration = %v", err)
	}
	if dial != 10*time.Second || idle != 5*time.Minute || lifetime != 0 {
		t.Errorf("got %s %s %s", dial, idle, lifetime)
	}
	if err := document.applyDuration("bad", &bad); err == nil {
		t.Error(`applyDuration accepted "10 seconds"`)
	}
}

func TestTOMLArrays(t *testing.T) {
	document := mustParse(t, `
inline   = ["api.openai.com", "*.openai.com"]
trailing = ["a", "b",]
empty    = []
spread   = [
  "api.openai.com",   # OpenAI
  "api.anthropic.com",
]
`)
	cases := map[string][]string{
		"inline":   {"api.openai.com", "*.openai.com"},
		"trailing": {"a", "b"},
		"empty":    {},
		"spread":   {"api.openai.com", "api.anthropic.com"},
	}
	for key, want := range cases {
		t.Run(key, func(t *testing.T) {
			var got []string
			if err := document.applyStrings(key, &got); err != nil {
				t.Fatalf("applyStrings = %v", err)
			}
			if len(got) != len(want) {
				t.Fatalf("got %q, want %q", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("got %q, want %q", got, want)
				}
			}
		})
	}
}

func TestTOMLRejectsMalformedArrays(t *testing.T) {
	document := mustParse(t, `
unquoted = [api.openai.com]
scalar   = "not an array"
nested   = [["a"]]
gap      = ["a", , "b"]
`)
	for _, key := range []string{"unquoted", "scalar", "nested", "gap"} {
		t.Run(key, func(t *testing.T) {
			var values []string
			if err := document.applyStrings(key, &values); err == nil {
				t.Fatalf("applyStrings(%s) = %q, want error", key, values)
			}
		})
	}
}

func TestTOMLRejectsUnknownKeys(t *testing.T) {
	document := mustParse(t, "listen = \"x\"\nech_mode = \"off\"\n\n[log]\nlevel = \"info\"\n")
	err := document.rejectUnknownKeys([]string{"listen", "ech", "log.level"})
	if err == nil {
		t.Fatal("rejectUnknownKeys accepted a misspelled key")
	}
	if !strings.Contains(err.Error(), "ech_mode") || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error = %v", err)
	}
	if err := document.rejectUnknownKeys([]string{"listen", "ech_mode", "log.level"}); err != nil {
		t.Errorf("rejectUnknownKeys = %v for a schema that covers the file", err)
	}
}

func TestTOMLRejectsUnknownTables(t *testing.T) {
	document := mustParse(t, "[logging]\nlevel = \"info\"\n")
	err := document.rejectUnknownKeys([]string{"log.level"})
	if err == nil {
		t.Fatal("rejectUnknownKeys accepted an unknown table")
	}
	if !strings.Contains(err.Error(), "logging.level") {
		t.Errorf("error = %v", err)
	}
}

func TestTOMLAcceptsCRLFAndBlankLines(t *testing.T) {
	document := mustParse(t, "\r\n# comment\r\nlisten = \"127.0.0.1:18080\"\r\n\r\n[log]\r\nlevel = \"info\"\r\n")
	var listen, level string
	if err := document.applyString("listen", &listen); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if err := document.applyString("log.level", &level); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if listen != "127.0.0.1:18080" || level != "info" {
		t.Errorf("listen = %q, level = %q", listen, level)
	}
}

func TestTOMLStringEscapes(t *testing.T) {
	document := mustParse(t, `
escaped = "a\"quote\" and a \\backslash"
literal = 'no \escape processing'
`)
	var escaped, literal string
	if err := document.applyString("escaped", &escaped); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if err := document.applyString("literal", &literal); err != nil {
		t.Fatalf("applyString = %v", err)
	}
	if escaped != `a"quote" and a \backslash` {
		t.Errorf("escaped = %q", escaped)
	}
	if literal != `no \escape processing` {
		t.Errorf("literal = %q", literal)
	}
}
