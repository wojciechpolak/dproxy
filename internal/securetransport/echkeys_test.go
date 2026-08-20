// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// A real ECH keypair and the ECHConfigList that publishes it, so the tests can
// run a genuine ECH handshake against a local terminator rather than assert
// against a hand-written blob that no implementation ever accepted.

// echKey is a generated ECH keypair with the configuration that advertises it.
type echKey struct {
	// list is the ECHConfigList, the form an HTTPS record carries and
	// crypto/tls accepts on the client.
	list []byte
	// config is the single ECHConfig inside it, the form crypto/tls accepts
	// on the server.
	config []byte
	// private is the raw X25519 private key.
	private []byte
	// publicName is the name that appears in the outer ClientHello.
	publicName string
}

// newECHKey generates a keypair and encodes an ECHConfigList for it: one
// DHKEM(X25519, HKDF-SHA256) key with the HKDF-SHA256/AES-128-GCM suite.
func newECHKey(t *testing.T, publicName string) echKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	public := key.PublicKey().Bytes()

	var suites []byte
	suites = binary.BigEndian.AppendUint16(suites, 0x0001) // HKDF-SHA256
	suites = binary.BigEndian.AppendUint16(suites, 0x0001) // AES-128-GCM

	contents := []byte{0x01}                                   // config_id
	contents = binary.BigEndian.AppendUint16(contents, 0x0020) // DHKEM(X25519)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(public)))
	contents = append(contents, public...)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(suites)))
	contents = append(contents, suites...)
	contents = append(contents, 0) // maximum_name_length
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0) // extensions

	config := binary.BigEndian.AppendUint16(nil, echConfigVersion)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)

	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	list = append(list, config...)

	return echKey{list: list, config: config, private: key.Bytes(), publicName: publicName}
}

// testECHConfigList returns a usable ECHConfigList.
func testECHConfigList(t *testing.T, publicName string) []byte {
	t.Helper()
	return newECHKey(t, publicName).list
}

// testUnsupportedECHConfigList returns a well-formed list whose only
// configuration uses a version crypto/tls cannot use.
func testUnsupportedECHConfigList(t *testing.T) []byte {
	t.Helper()
	list := append([]byte(nil), testECHConfigList(t, "cloudflare-ech.com")...)
	binary.BigEndian.PutUint16(list[2:4], 0xfe0a)
	return list
}
