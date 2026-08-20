// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParsePinAcceptsHexAndBase64(t *testing.T) {
	spki := []byte("subject public key info")
	digest := sha256.Sum256(spki)
	fromHex, err := ParsePin("sha256:" + hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("ParsePin(hex) = %v", err)
	}
	fromBase64, err := ParsePin("sha256:" + base64.StdEncoding.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("ParsePin(base64) = %v", err)
	}
	if fromHex != fromBase64 {
		t.Fatal("the same digest parsed from hex and base64 produced different pins")
	}
	if !fromHex.MatchesSPKI(spki) {
		t.Error("MatchesSPKI(spki) = false for the pin built from its own digest")
	}
	if fromHex.MatchesSPKI([]byte("some other key")) {
		t.Error("MatchesSPKI accepted a different key")
	}
	if got := PinFromSPKI(spki); got != fromHex {
		t.Errorf("PinFromSPKI = %v, want %v", got, fromHex)
	}
	if !strings.HasPrefix(fromHex.String(), "sha256:") {
		t.Errorf("String() = %q", fromHex.String())
	}
	if fromHex.Algorithm() != PinSHA256 {
		t.Errorf("Algorithm() = %q", fromHex.Algorithm())
	}
}

func TestParsePinRejects(t *testing.T) {
	cases := []string{
		"",
		"   ",
		hex.EncodeToString(make([]byte, 32)),
		"sha1:" + hex.EncodeToString(make([]byte, 20)),
		"sha256:",
		"sha256:not-base64!!",
		"sha256:" + hex.EncodeToString(make([]byte, 16)),
		"sha256:" + base64.StdEncoding.EncodeToString(make([]byte, 31)),
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if pin, err := ParsePin(raw); err == nil {
				t.Fatalf("ParsePin(%q) = %v, want error", raw, pin)
			}
		})
	}
}

func TestZeroPinMatchesNothing(t *testing.T) {
	var pin Pin
	if !pin.IsZero() {
		t.Fatal("zero Pin reports IsZero() = false")
	}
	digest := sha256.Sum256(nil)
	if pin.Matches(digest[:]) || pin.MatchesSPKI(nil) {
		t.Error("the zero Pin matched a digest")
	}
	if pin.String() != "<unset>" {
		t.Errorf("String() = %q", pin.String())
	}
}
