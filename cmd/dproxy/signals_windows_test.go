// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build windows

package main

import (
	"os"
	"strings"
	"testing"
)

func TestWindowsShutdownUsesConsoleInterrupt(t *testing.T) {
	signals := shutdownSignals()
	if len(signals) != 1 || signals[0] != os.Interrupt {
		t.Fatalf("shutdown signals = %#v", signals)
	}
}

func TestWindowsUsageShowsPowerShellProxyConfiguration(t *testing.T) {
	if usage := proxyEnvironmentUsage(); !strings.Contains(usage, "$env:HTTPS_PROXY") {
		t.Fatalf("proxy usage = %q", usage)
	}
}
