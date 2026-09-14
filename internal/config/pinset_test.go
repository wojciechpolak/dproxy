// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"strings"
	"testing"
)

func testSPKI(seed byte) []byte {
	spki := make([]byte, 64)
	for index := range spki {
		spki[index] = seed
	}
	return spki
}

func TestNewPinSetRejectsEmptyAndOversizedSets(t *testing.T) {
	if _, err := NewPinSet(); err == nil {
		t.Fatal("empty set accepted")
	}
	pins := make([]Pin, MaxClientPins+1)
	for index := range pins {
		pins[index] = PinFromSPKI(testSPKI(byte(index)))
	}
	if _, err := NewPinSet(pins...); err == nil {
		t.Fatalf("set of %d accepted", len(pins))
	}
	if _, err := NewPinSet(pins[:MaxClientPins]...); err != nil {
		t.Fatalf("set of %d rejected: %v", MaxClientPins, err)
	}
}

func TestNewPinSetRejectsAZeroEntry(t *testing.T) {
	_, err := NewPinSet(PinFromSPKI(testSPKI(1)), Pin{})
	if err == nil {
		t.Fatal("zero entry accepted")
	}
	if !strings.Contains(err.Error(), "entry 2") {
		t.Fatalf("error = %v, want the 1-based position", err)
	}
}

func TestParsePinSetAcceptsNoEntries(t *testing.T) {
	set, err := ParsePinSet(nil)
	if err != nil {
		t.Fatalf("no entries rejected: %v", err)
	}
	if set.Len() != 0 {
		t.Fatalf("Len = %d, want 0", set.Len())
	}
}

func TestParsePinSetReportsThePositionWithoutEchoingTheEntry(t *testing.T) {
	secret := "a-token-pasted-into-the-wrong-key"
	_, err := ParsePinSet([]string{PinFromSPKI(testSPKI(1)).String(), secret})
	if err == nil {
		t.Fatal("malformed entry accepted")
	}
	if !strings.Contains(err.Error(), "client pin 2") {
		t.Fatalf("error = %v, want the 1-based position", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error echoed the entry: %v", err)
	}
}

func TestPinSetContainsSPKIMatchesEveryConfiguredPin(t *testing.T) {
	first, second := testSPKI(1), testSPKI(2)
	set, err := ParsePinSet([]string{PinFromSPKI(first).String(), PinFromSPKI(second).String()})
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}
	// The second entry covers the case where the scan must not stop early.
	for _, spki := range [][]byte{first, second} {
		if !set.ContainsSPKI(spki) {
			t.Errorf("configured pin not matched")
		}
	}
	if set.ContainsSPKI(testSPKI(3)) {
		t.Error("unconfigured key matched")
	}
	if set.ContainsSPKI(nil) {
		t.Error("empty SPKI matched")
	}
}

func TestZeroPinSetAuthorizesNothing(t *testing.T) {
	var set PinSet
	if set.Len() != 0 {
		t.Fatalf("Len = %d, want 0", set.Len())
	}
	if set.ContainsSPKI(testSPKI(1)) {
		t.Error("zero set authorized a key")
	}
}
