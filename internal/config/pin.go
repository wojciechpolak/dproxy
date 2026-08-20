// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// PinAlgorithm names the digest a pin is expressed in. Only SHA-256 exists in
// v1; naming it stops a later algorithm reinterpreting an existing pin.
type PinAlgorithm string

// PinSHA256 is the SHA-256 digest of the remote SubjectPublicKeyInfo.
const PinSHA256 PinAlgorithm = "sha256"

// Pin is the digest of the SubjectPublicKeyInfo the inner TLS session must
// present. Public PKI alone is not sufficient there, so it is mandatory.
type Pin struct {
	algorithm PinAlgorithm
	digest    [sha256.Size]byte
	set       bool
}

// IsZero reports a pin that was never configured.
func (p Pin) IsZero() bool { return !p.set }

// Algorithm returns the digest algorithm.
func (p Pin) Algorithm() PinAlgorithm { return p.algorithm }

// Digest returns a copy of the raw digest bytes.
func (p Pin) Digest() []byte {
	digest := p.digest
	return digest[:]
}

// String renders the pin in the syntax ParsePin accepts. A pin identifies the
// server rather than authenticating the client, so it is safe to print.
func (p Pin) String() string {
	if !p.set {
		return "<unset>"
	}
	return string(p.algorithm) + ":" + base64.StdEncoding.EncodeToString(p.digest[:])
}

// Matches reports whether a candidate SPKI digest is the pinned one, in
// constant time.
func (p Pin) Matches(digest []byte) bool {
	if !p.set || len(digest) != len(p.digest) {
		return false
	}
	return subtle.ConstantTimeCompare(p.digest[:], digest) == 1
}

// MatchesSPKI hashes a DER-encoded SubjectPublicKeyInfo and compares it.
func (p Pin) MatchesSPKI(spki []byte) bool {
	digest := sha256.Sum256(spki)
	return p.Matches(digest[:])
}

// PinFromSPKI builds the pin for a DER-encoded SubjectPublicKeyInfo: how the
// server reports its own pin for an operator to configure.
func PinFromSPKI(spki []byte) Pin {
	return Pin{algorithm: PinSHA256, digest: sha256.Sum256(spki), set: true}
}

// ParsePin accepts "sha256:<base64>" and "sha256:<hex>". The prefix is
// required: an unprefixed digest would become whatever a later version
// defaults to.
func ParsePin(raw string) (Pin, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Pin{}, errors.New("pin is empty")
	}
	algorithm, encoded, found := strings.Cut(trimmed, ":")
	if !found {
		return Pin{}, fmt.Errorf("pin %q has no algorithm prefix (want %q)", trimmed, "sha256:<digest>")
	}
	if PinAlgorithm(strings.ToLower(algorithm)) != PinSHA256 {
		return Pin{}, fmt.Errorf("unsupported pin algorithm %q (want %q)", algorithm, PinSHA256)
	}
	decoded, err := decodeDigest(encoded)
	if err != nil {
		return Pin{}, err
	}
	if len(decoded) != sha256.Size {
		return Pin{}, fmt.Errorf("pin digest is %d bytes, want %d", len(decoded), sha256.Size)
	}
	pin := Pin{algorithm: PinSHA256, set: true}
	copy(pin.digest[:], decoded)
	return pin, nil
}

func decodeDigest(encoded string) ([]byte, error) {
	if len(encoded) == hex.EncodedLen(sha256.Size) {
		decoded, err := hex.DecodeString(encoded)
		if err == nil {
			return decoded, nil
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("pin digest is neither hex nor standard base64: %w", err)
	}
	return decoded, nil
}
