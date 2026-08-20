// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Provider names belong in configuration. This regression test keeps a future
// endpoint update from turning into special-case tunnel or relay behavior.
func TestProviderHostnamesStayOutOfTransportLogic(t *testing.T) {
	packages := []string{"localproxy", "policy", "protocol", "relay", "securetransport", "tunnel"}
	providerNames := []string{
		"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
		"anthropic.com", "claude.ai", "claude.com",
	}
	for _, packageName := range packages {
		entries, err := os.ReadDir(filepath.Join("..", packageName))
		if err != nil {
			t.Fatalf("read package %s: %v", packageName, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join("..", packageName, entry.Name())
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			lower := strings.ToLower(string(contents))
			for _, providerName := range providerNames {
				if strings.Contains(lower, providerName) {
					t.Errorf("%s hard-codes provider hostname %q; keep it in config", path, providerName)
				}
			}
		}
	}
}
