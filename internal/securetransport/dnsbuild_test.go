// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// Wire-message builders for the tests. They are deliberately not the encoder
// under test: a response is assembled byte by byte here so a test can write a
// malformed one on purpose.

// testAnswer is one record to place in the answer section.
type testAnswer struct {
	name  string
	rtype dnsType
	class uint16
	ttl   uint32
	data  []byte
}

// answer builds an ordinary IN answer.
func answer(name string, rtype dnsType, data []byte) testAnswer {
	return testAnswer{name: name, rtype: rtype, class: classINET, ttl: 300, data: data}
}

// mustName encodes a name or fails the test.
func mustName(t *testing.T, name string) []byte {
	t.Helper()
	wire, err := encodeName(nil, name)
	if err != nil {
		t.Fatalf("encodeName(%q): %v", name, err)
	}
	return wire
}

// addressData renders an address as A or AAAA record data.
func addressData(t *testing.T, text string) []byte {
	t.Helper()
	address, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", text, err)
	}
	if address.Is4() {
		value := address.As4()
		return value[:]
	}
	value := address.As16()
	return value[:]
}

// svcParam encodes one SvcParam.
func svcParam(key svcParamKey, value []byte) []byte {
	wire := binary.BigEndian.AppendUint16(nil, uint16(key))
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(value)))
	return append(wire, value...)
}

// httpsData builds HTTPS record data.
func httpsData(t *testing.T, priority uint16, target string, params ...[]byte) []byte {
	t.Helper()
	wire := binary.BigEndian.AppendUint16(nil, priority)
	wire = append(wire, mustName(t, target)...)
	for _, param := range params {
		wire = append(wire, param...)
	}
	return wire
}

// responseOptions are the header bits a test wants to bend.
type responseOptions struct {
	id           uint16
	question     dnsQuestion
	answers      []testAnswer
	notAResponse bool
	truncated    bool
	rcode        dnsRCode
	// omitQuestion writes QDCOUNT 0 and no question section.
	omitQuestion bool
	// answerCount overrides ANCOUNT without changing what is written.
	answerCount int
}

// buildResponse assembles a DNS response message.
func buildResponse(t *testing.T, options responseOptions) []byte {
	t.Helper()
	flags := uint16(0x0100)
	if !options.notAResponse {
		flags |= 0x8000
	}
	if options.truncated {
		flags |= 0x0200
	}
	flags |= uint16(options.rcode) & 0x000f

	questions := 1
	if options.omitQuestion {
		questions = 0
	}
	answers := len(options.answers)
	if options.answerCount != 0 {
		answers = options.answerCount
	}

	wire := binary.BigEndian.AppendUint16(nil, options.id)
	wire = binary.BigEndian.AppendUint16(wire, flags)
	wire = binary.BigEndian.AppendUint16(wire, uint16(questions))
	wire = binary.BigEndian.AppendUint16(wire, uint16(answers))
	wire = binary.BigEndian.AppendUint16(wire, 0)
	wire = binary.BigEndian.AppendUint16(wire, 0)
	if questions != 0 {
		wire = append(wire, mustName(t, options.question.name)...)
		wire = binary.BigEndian.AppendUint16(wire, uint16(options.question.qtype))
		wire = binary.BigEndian.AppendUint16(wire, options.question.class)
	}
	for _, record := range options.answers {
		wire = append(wire, mustName(t, record.name)...)
		wire = binary.BigEndian.AppendUint16(wire, uint16(record.rtype))
		wire = binary.BigEndian.AppendUint16(wire, record.class)
		wire = binary.BigEndian.AppendUint32(wire, record.ttl)
		wire = binary.BigEndian.AppendUint16(wire, uint16(len(record.data)))
		wire = append(wire, record.data...)
	}
	return wire
}
