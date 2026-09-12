// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// userConfigDir follows XDG_CONFIG_HOME. When it is unset, dproxy uses
// ~/.config, including on macOS.
func userConfigDir() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("XDG_CONFIG_HOME must be an absolute path, got %q", dir)
		}
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config"), nil
}
