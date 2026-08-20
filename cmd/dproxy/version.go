// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// sourceVersion is the version recorded in the source tree. The version bump
// tool keeps it in sync with the repository's VERSION file.
const sourceVersion = "v1.0.0"

// version is the release version. A release build sets it with
// -ldflags "-X main.version=v1.2.3".
var version string

// versionLine is what "dproxy version" prints: binary, version, source revision
// when recorded, toolchain, and platform. Nothing operator-specific.
func versionLine() string {
	parts := []string{"dproxy " + resolveVersion()}
	if revision := buildRevision(); revision != "" {
		parts = append(parts, "("+revision+")")
	}
	parts = append(parts, runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)
	return strings.Join(parts, " ")
}

func resolveVersion() string {
	if version != "" {
		return version
	}
	return sourceVersion
}

// buildRevision reports the VCS revision, with a "+dirty" marker when the
// working tree carried uncommitted changes.
func buildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var revision, modified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if revision == "" {
		return ""
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified == "true" {
		return fmt.Sprintf("%s+dirty", revision)
	}
	return revision
}
