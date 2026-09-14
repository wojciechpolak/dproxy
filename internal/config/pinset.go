// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"errors"
	"fmt"
)

// MaxClientPins bounds the accepted client identities. The bound catches a
// configuration mistake; it is not a security control.
const MaxClientPins = 16

// PinSet is the remote's accepted client-identity set. The zero value
// authorizes nothing, and on the server means no client certificate is
// requested at all.
type PinSet struct {
	pins []Pin
}

// NewPinSet validates and copies the accepted client pins.
func NewPinSet(pins ...Pin) (PinSet, error) {
	if len(pins) == 0 {
		return PinSet{}, errors.New("client pin set is empty")
	}
	if len(pins) > MaxClientPins {
		return PinSet{}, fmt.Errorf("client pin set has %d entries, want at most %d", len(pins), MaxClientPins)
	}
	set := PinSet{pins: make([]Pin, len(pins))}
	for index, pin := range pins {
		if pin.IsZero() {
			return PinSet{}, fmt.Errorf("client pin set entry %d is empty", index+1)
		}
		set.pins[index] = pin
	}
	return set, nil
}

// ParsePinSet reads configured client pins. An empty list is the default, not
// an error. A failing entry is reported by position and
// never echoed, so a token pasted into the wrong key stays out of the error.
func ParsePinSet(raw []string) (PinSet, error) {
	if len(raw) == 0 {
		return PinSet{}, nil
	}
	pins := make([]Pin, len(raw))
	for index, entry := range raw {
		pin, err := ParsePin(entry)
		if err != nil {
			return PinSet{}, fmt.Errorf("client pin %d is not a valid pin (want %q)", index+1, "sha256:<digest>")
		}
		pins[index] = pin
	}
	return NewPinSet(pins...)
}

// Len reports the number of accepted client pins.
func (s PinSet) Len() int { return len(s.pins) }

// ContainsSPKI compares a DER-encoded SubjectPublicKeyInfo with every
// configured pin. Pins are public, so constant time matters less here than in
// TokenSet, but this is an authentication boundary: the comparison is constant
// time and does not return early on a match.
func (s PinSet) ContainsSPKI(spki []byte) bool {
	if len(s.pins) == 0 || len(spki) == 0 {
		return false
	}
	matched := false
	for _, pin := range s.pins {
		matched = pin.MatchesSPKI(spki) || matched
	}
	return matched
}
