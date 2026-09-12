// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build !windows

// Package privatepath applies and validates access controls for files that
// contain dproxy credentials.
package privatepath

import (
	"fmt"
	"io/fs"
	"os"
)

// Restrict limits path to its owner. Directories remain traversable by that
// owner; files remain readable and writable.
func Restrict(path string, directory bool) error {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}

// Validate rejects a path that grants group or world access.
func Validate(path string, info fs.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s permissions %#o are too open; use 0600", path, info.Mode().Perm())
	}
	return nil
}
