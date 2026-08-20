// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"io"

	"github.com/wojciechpolak/dproxy/internal/policy"
)

// policyEmpty returns an allowlist that permits nothing.
func policyEmpty() policy.Allowlist { return policy.Allowlist{} }

// readAllowlistForTest parses the shipped allowlist file format.
func readAllowlistForTest(r io.Reader) (policy.Allowlist, error) { return policy.ReadAllowlist(r) }
