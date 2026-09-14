// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build e2e || docker_e2e || cloudflare

package integration_test

import "testing"

// scenario names what an end-to-end test proves. Go prints it under -v, which
// is how the e2e targets run this package, so a passing run reads as a list of
// covered scenarios rather than one "ok" line.
func scenario(t *testing.T, description string) {
	t.Helper()
	t.Log(description)
}
