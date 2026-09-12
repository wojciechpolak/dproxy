// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build windows

package main

func proxyEnvironmentUsage() string {
	return "  $env:HTTPS_PROXY = \"http://127.0.0.1:18080\"\n"
}
