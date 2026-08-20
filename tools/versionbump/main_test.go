// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNextVersion(t *testing.T) {
	current := semanticVersion{major: 0, minor: 9, patch: 0}
	tests := map[string]string{
		"major": "1.0.0",
		"minor": "0.10.0",
		"patch": "0.9.1",
		"1.2.3": "1.2.3",
	}
	for requested, want := range tests {
		got, err := nextVersion(current, requested)
		if err != nil {
			t.Fatalf("nextVersion(%q): %v", requested, err)
		}
		if got.String() != want {
			t.Errorf("nextVersion(%q) = %s, want %s", requested, got, want)
		}
	}
}

func TestNextVersionRejectsBadOrOldValues(t *testing.T) {
	current := semanticVersion{major: 0, minor: 9, patch: 0}
	for _, requested := range []string{"0.9.0", "0.8.9", "v1.0.0", "1.2", "01.2.3", "other"} {
		if _, err := nextVersion(current, requested); err == nil {
			t.Errorf("nextVersion(%q) unexpectedly succeeded", requested)
		}
	}
}

func TestReleaseChangelogMovesUnreleasedNotes(t *testing.T) {
	input := `# Changelog

## [Unreleased](https://github.com/wojciechpolak/dproxy/compare/v0.9.0...HEAD)

### Fixed

- A bug.

## [0.9.0](https://github.com/wojciechpolak/dproxy/releases/tag/v0.9.0) - 2026-08-20

- Initial release.
`
	got, err := releaseChangelog(input, "0.9.1", time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"## [Unreleased]\n\n",
		"## [0.9.1] - 2026-08-21\n\n### Fixed\n\n- A bug.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("updated changelog does not contain %q:\n%s", want, got)
		}
	}
}

func TestReleaseChangelogCreatesFirstRelease(t *testing.T) {
	input := `# Changelog

## Unreleased

### Added

- Initial release.
`
	got, err := releaseChangelog(input, "0.9.1", time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"## [Unreleased]\n\n",
		"## [0.9.1] - 2026-08-21\n\n### Added\n\n- Initial release.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("updated changelog does not contain %q:\n%s", want, got)
		}
	}
}

func TestBumpUpdatesRepositoryFiles(t *testing.T) {
	root := t.TempDir()
	versionDir := filepath.Join(root, "cmd", "dproxy")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"VERSION": "0.9.0\n",
		filepath.Join("cmd", "dproxy", "version.go"): "package main\n\nconst sourceVersion = \"v0.9.0\"\n",
		"CHANGELOG.md": `# Changelog

## Unreleased

### Added

- Initial release.
`,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldVersion, newVersion, err := bump(root, "minor", time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if oldVersion != "0.9.0" || newVersion != "0.10.0" {
		t.Fatalf("bump = %s to %s", oldVersion, newVersion)
	}
	for name, want := range map[string]string{
		"VERSION": "0.10.0\n",
		filepath.Join("cmd", "dproxy", "version.go"): `const sourceVersion = "v0.10.0"`,
		"CHANGELOG.md": "## [0.10.0] - 2026-08-21",
	} {
		contents, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(contents), want) {
			t.Errorf("%s = %q, want it to contain %q", name, contents, want)
		}
	}
}
