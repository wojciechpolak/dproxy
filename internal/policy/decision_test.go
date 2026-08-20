// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"strings"
	"testing"
)

// TestZeroDecisionDenies: a decision nobody assigned must refuse.
func TestZeroDecisionDenies(t *testing.T) {
	var decision Decision
	if decision.Allowed() {
		t.Fatal("the zero Decision permits")
	}
	if decision.Reason() != DenyNone {
		t.Errorf("Reason() = %s", decision.Reason())
	}
}

func TestDecisionCarriesItsReason(t *testing.T) {
	if !Allow().Allowed() {
		t.Error("Allow() does not permit")
	}
	if Allow().String() != "allow" {
		t.Errorf("Allow().String() = %q", Allow().String())
	}
	decision := Deny(DenyNonPublicAddress)
	if decision.Allowed() {
		t.Error("Deny() permits")
	}
	if decision.Reason() != DenyNonPublicAddress {
		t.Errorf("Reason() = %s", decision.Reason())
	}
	if got, want := decision.String(), "deny:non-public-address"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestDenyReasonsHaveStableTokens(t *testing.T) {
	reasons := []DenyReason{
		DenyNone, DenyMalformedAuthority, DenyIPLiteral, DenyPortNotAllowed,
		DenyNotAllowlisted, DenyResolutionFailed, DenyNonPublicAddress,
	}
	seen := map[string]bool{}
	for _, reason := range reasons {
		token := reason.String()
		if strings.HasPrefix(token, "DenyReason(") {
			t.Errorf("%d has no token", uint8(reason))
		}
		if seen[token] {
			t.Errorf("token %q is used twice", token)
		}
		seen[token] = true
	}
	if got := DenyReason(200).String(); !strings.HasPrefix(got, "DenyReason(") {
		t.Errorf("unknown reason rendered as %q", got)
	}
}
