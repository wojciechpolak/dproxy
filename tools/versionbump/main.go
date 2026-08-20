// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Command versionbump updates dproxy's version sources and changelog.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var stableVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var unreleasedHeadingPattern = regexp.MustCompile(`(?m)^## (?:Unreleased|\[Unreleased\](?:\([^\n)]+\))?)$`)

type semanticVersion struct {
	major uint64
	minor uint64
	patch uint64
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: versionbump [-root directory] <major|minor|patch|x.y.z>\n")
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	oldVersion, newVersion, err := bump(*root, flag.Arg(0), time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "versionbump: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Bumped dproxy from %s to %s\n", oldVersion, newVersion)
}

func bump(root, requested string, now time.Time) (string, string, error) {
	versionPath := filepath.Join(root, "VERSION")
	contents, err := os.ReadFile(versionPath)
	if err != nil {
		return "", "", fmt.Errorf("read VERSION: %w", err)
	}
	oldVersion := strings.TrimSpace(string(contents))
	current, err := parseVersion(oldVersion)
	if err != nil {
		return "", "", fmt.Errorf("VERSION contains %q: %w", oldVersion, err)
	}
	next, err := nextVersion(current, requested)
	if err != nil {
		return "", "", err
	}
	newVersion := next.String()

	versionSourcePath := filepath.Join(root, "cmd", "dproxy", "version.go")
	versionSource, err := os.ReadFile(versionSourcePath)
	if err != nil {
		return "", "", fmt.Errorf("read source version: %w", err)
	}
	oldDeclaration := `const sourceVersion = "v` + oldVersion + `"`
	newDeclaration := `const sourceVersion = "v` + newVersion + `"`
	updatedSource, err := replaceExactlyOnce(string(versionSource), oldDeclaration, newDeclaration)
	if err != nil {
		return "", "", fmt.Errorf("update source version: %w", err)
	}

	changelogPath := filepath.Join(root, "CHANGELOG.md")
	changelog, err := os.ReadFile(changelogPath)
	if err != nil {
		return "", "", fmt.Errorf("read CHANGELOG.md: %w", err)
	}
	updatedChangelog, err := releaseChangelog(string(changelog), newVersion, now)
	if err != nil {
		return "", "", fmt.Errorf("update CHANGELOG.md: %w", err)
	}

	updates := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{path: versionPath, data: []byte(newVersion + "\n"), mode: 0o644},
		{path: versionSourcePath, data: []byte(updatedSource), mode: 0o644},
		{path: changelogPath, data: []byte(updatedChangelog), mode: 0o644},
	}
	for _, update := range updates {
		if err := writeFile(update.path, update.data, update.mode); err != nil {
			return "", "", err
		}
	}
	return oldVersion, newVersion, nil
}

func parseVersion(value string) (semanticVersion, error) {
	match := stableVersionPattern.FindStringSubmatch(value)
	if match == nil {
		return semanticVersion{}, errors.New("want a stable semantic version such as 1.2.3")
	}
	parts := make([]uint64, 3)
	for index, value := range match[1:] {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return semanticVersion{}, errors.New("version component is too large")
		}
		parts[index] = parsed
	}
	return semanticVersion{major: parts[0], minor: parts[1], patch: parts[2]}, nil
}

func (v semanticVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func nextVersion(current semanticVersion, requested string) (semanticVersion, error) {
	switch requested {
	case "major":
		if current.major == ^uint64(0) {
			return semanticVersion{}, errors.New("major version is too large to increment")
		}
		return semanticVersion{major: current.major + 1}, nil
	case "minor":
		if current.minor == ^uint64(0) {
			return semanticVersion{}, errors.New("minor version is too large to increment")
		}
		return semanticVersion{major: current.major, minor: current.minor + 1}, nil
	case "patch":
		if current.patch == ^uint64(0) {
			return semanticVersion{}, errors.New("patch version is too large to increment")
		}
		return semanticVersion{major: current.major, minor: current.minor, patch: current.patch + 1}, nil
	}
	next, err := parseVersion(requested)
	if err != nil {
		return semanticVersion{}, fmt.Errorf("invalid version %q: %w", requested, err)
	}
	if next.compare(current) <= 0 {
		return semanticVersion{}, fmt.Errorf("version %s must be newer than %s", next, current)
	}
	return next, nil
}

func (v semanticVersion) compare(other semanticVersion) int {
	for _, pair := range [][2]uint64{{v.major, other.major}, {v.minor, other.minor}, {v.patch, other.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	return 0
}

func releaseChangelog(changelog, newVersion string, now time.Time) (string, error) {
	headings := unreleasedHeadingPattern.FindAllStringIndex(changelog, -1)
	if len(headings) != 1 {
		return "", errors.New("missing or duplicate Unreleased heading")
	}
	headingStart, bodyStart := headings[0][0], headings[0][1]
	nextReleaseOffset := strings.Index(changelog[bodyStart:], "\n## [")
	nextReleaseStart := len(changelog)
	hasPreviousRelease := nextReleaseOffset >= 0
	if hasPreviousRelease {
		nextReleaseStart = bodyStart + nextReleaseOffset
	}
	body := strings.TrimSpace(changelog[bodyStart:nextReleaseStart])

	var released strings.Builder
	released.WriteString(changelog[:headingStart])
	released.WriteString("## [Unreleased]")
	released.WriteString("\n\n## [")
	released.WriteString(newVersion)
	released.WriteString("] - ")
	released.WriteString(now.Format("2006-01-02"))
	if body != "" {
		released.WriteString("\n\n")
		released.WriteString(body)
	}
	released.WriteString("\n")
	released.WriteString(changelog[nextReleaseStart:])
	return released.String(), nil
}

func replaceExactlyOnce(value, old, replacement string) (string, error) {
	if strings.Count(value, old) != 1 {
		return "", fmt.Errorf("expected one occurrence of %q", old)
	}
	return strings.Replace(value, old, replacement, 1), nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".versionbump-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set mode on temporary file for %s: %w", path, err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary file for %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
