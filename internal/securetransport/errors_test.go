// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestFailureReasonsHaveStableTokens(t *testing.T) {
	reasons := []FailureReason{
		FailureNone, FailureDoH, FailureHTTPSRecord, FailureECHUnavailable,
		FailureECHRejected, FailureTLSVersion, FailureCertificate,
		FailureRedirect, FailureAddressRejected, FailureHandshake,
	}
	seen := map[string]bool{}
	for _, reason := range reasons {
		token := reason.String()
		if strings.HasPrefix(token, "FailureReason(") {
			t.Errorf("%d has no token", uint8(reason))
		}
		if seen[token] {
			t.Errorf("token %q is used twice", token)
		}
		seen[token] = true
	}
}

func TestFailWrapsAndClassifies(t *testing.T) {
	cause := errors.New("no HTTPS record for the relay")
	err := Fail(FailureECHUnavailable, cause)
	if ReasonOf(err) != FailureECHUnavailable {
		t.Errorf("ReasonOf = %s", ReasonOf(err))
	}
	if !errors.Is(err, cause) {
		t.Error("the cause did not survive wrapping")
	}
	wrapped := fmt.Errorf("establish tunnel: %w", err)
	if ReasonOf(wrapped) != FailureECHUnavailable {
		t.Errorf("ReasonOf(wrapped) = %s", ReasonOf(wrapped))
	}
	if !strings.Contains(err.Error(), "ech-unavailable") {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestReasonOfUnrelatedError(t *testing.T) {
	if got := ReasonOf(errors.New("something else")); got != FailureNone {
		t.Errorf("ReasonOf = %s, want none", got)
	}
	if got := ReasonOf(nil); got != FailureNone {
		t.Errorf("ReasonOf(nil) = %s, want none", got)
	}
}

func TestFailWithoutACause(t *testing.T) {
	err := Fail(FailureTLSVersion, nil)
	if !strings.Contains(err.Error(), "tls-version") {
		t.Errorf("Error() = %q", err.Error())
	}
	if errors.Unwrap(err) != nil {
		t.Error("Unwrap returned a cause that was never set")
	}
}
