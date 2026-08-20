// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestEncodeNameRoundTrips(t *testing.T) {
	for _, name := range []string{"relay.example.com", "a.b.c.d.e", "xn--bcher-kva.example", "example.com."} {
		wire, err := encodeName(nil, name)
		if err != nil {
			t.Fatalf("encodeName(%q): %v", name, err)
		}
		decoded, next, err := decodeName(wire, 0)
		if err != nil {
			t.Fatalf("decodeName(%q): %v", name, err)
		}
		if want := canonicalDNSName(name); decoded != want {
			t.Errorf("decodeName = %q, want %q", decoded, want)
		}
		if next != len(wire) {
			t.Errorf("next = %d, want %d", next, len(wire))
		}
	}
}

func TestEncodeNameRejectsUnusableNames(t *testing.T) {
	cases := map[string]string{
		"empty label":     "relay..example.com",
		"leading dot":     ".example.com",
		"label too long":  strings.Repeat("a", 64) + ".example.com",
		"name too long":   strings.Repeat("a.", 130) + "example.com",
		"space in label":  "relay example.com",
		"control byte":    "relay\x00.example.com",
		"non-ascii byte":  "relay\xff.example.com",
		"tab in label":    "relay\t.example.com",
		"trailing spaces": "relay.example.com ",
	}
	for description, name := range cases {
		t.Run(description, func(t *testing.T) {
			if _, err := encodeName(nil, name); err == nil {
				t.Fatalf("encodeName(%q) was accepted", name)
			} else if !errors.Is(err, errDNSName) {
				t.Errorf("err = %v, want errDNSName", err)
			}
		})
	}
}

func TestEncodeNameEncodesTheRoot(t *testing.T) {
	wire, err := encodeName(nil, ".")
	if err != nil || len(wire) != 1 || wire[0] != 0 {
		t.Fatalf("encodeName(\".\") = %v, %v", wire, err)
	}
}

func TestDecodeNameFollowsACompressionPointer(t *testing.T) {
	// "example.com" at offset 0, then "relay" + a pointer back to it.
	message := mustName(t, "example.com")
	start := len(message)
	message = append(message, 5)
	message = append(message, "relay"...)
	message = binary.BigEndian.AppendUint16(message, 0xc000)

	name, next, err := decodeName(message, start)
	if err != nil {
		t.Fatalf("decodeName: %v", err)
	}
	if name != "relay.example.com" {
		t.Errorf("name = %q", name)
	}
	if next != len(message) {
		t.Errorf("next = %d, want %d", next, len(message))
	}
}

func TestDecodeNameRejectsHostileNames(t *testing.T) {
	// Both pointers are read from offset 0, where any target at or past the
	// pointer itself is forwards.
	forwardPointer := []byte{0xc0, 0x02, 1, 'a', 0}
	selfPointer := []byte{0xc0, 0x00}

	dotInLabel := []byte{11}
	dotInLabel = append(dotInLabel, "api.evil.com"[:11]...)
	dotInLabel = append(dotInLabel, 0)

	cases := map[string][]byte{
		"pointer to itself":       selfPointer,
		"pointer forwards":        forwardPointer,
		"label runs past the end": {5, 'r', 'e'},
		"no terminator":           {1, 'a'},
		"dot inside a label":      dotInLabel,
		"reserved length bits":    {0x80, 0x00},
	}
	for description, message := range cases {
		t.Run(description, func(t *testing.T) {
			if name, _, err := decodeName(message, 0); err == nil {
				t.Fatalf("decodeName accepted %q", name)
			}
		})
	}
}

// A chain of individually legal backwards pointers is still a chain: the
// budget, not the direction rule, is what stops it.
func TestDecodeNameBoundsAPointerChain(t *testing.T) {
	message := mustName(t, "example.com")
	offset := 0
	for i := 0; i < dnsPointerBudget+2; i++ {
		next := len(message)
		message = binary.BigEndian.AppendUint16(message, 0xc000|uint16(offset))
		offset = next
	}
	if _, _, err := decodeName(message, offset); err == nil {
		t.Fatal("a pointer chain longer than the budget was accepted")
	}
}

func TestBuildDNSQueryShape(t *testing.T) {
	wire, err := buildDNSQuery(0x1234, dnsQuestion{name: "relay.example.com", qtype: typeHTTPS, class: classINET})
	if err != nil {
		t.Fatalf("buildDNSQuery: %v", err)
	}
	if binary.BigEndian.Uint16(wire[0:2]) != 0x1234 {
		t.Error("the transaction ID was not written")
	}
	if flags := binary.BigEndian.Uint16(wire[2:4]); flags != 0x0100 {
		t.Errorf("flags = %#04x, want recursion desired only", flags)
	}
	if binary.BigEndian.Uint16(wire[4:6]) != 1 || binary.BigEndian.Uint16(wire[6:8]) != 0 {
		t.Error("the query does not carry exactly one question and no answers")
	}
	message, err := parseDNSMessage(wire)
	if err != nil {
		t.Fatalf("parseDNSMessage: %v", err)
	}
	if len(message.questions) != 1 || message.questions[0].name != "relay.example.com" ||
		message.questions[0].qtype != typeHTTPS {
		t.Errorf("questions = %+v", message.questions)
	}
}

func TestParseDNSMessageReadsAnswers(t *testing.T) {
	question := dnsQuestion{name: "relay.example.com", qtype: typeA, class: classINET}
	wire := buildResponse(t, responseOptions{
		id:       7,
		question: question,
		answers: []testAnswer{
			answer("relay.example.com", typeCNAME, mustName(t, "edge.example.net")),
			answer("edge.example.net", typeA, addressData(t, "203.0.113.7")),
		},
	})
	message, err := parseDNSMessage(wire)
	if err != nil {
		t.Fatalf("parseDNSMessage: %v", err)
	}
	if message.header.id != 7 || !message.header.response || message.header.truncated {
		t.Errorf("header = %+v", message.header)
	}
	if len(message.answers) != 2 {
		t.Fatalf("answers = %d, want 2", len(message.answers))
	}
	if message.answers[0].rtype != typeCNAME || message.answers[1].rtype != typeA {
		t.Errorf("answer types = %s, %s", message.answers[0].rtype, message.answers[1].rtype)
	}
	target, _, err := decodeName(message.wire, message.answers[0].dataOffset)
	if err != nil || target != "edge.example.net" {
		t.Errorf("CNAME target = %q, %v", target, err)
	}
}

func TestParseDNSMessageRejectsMalformedMessages(t *testing.T) {
	question := dnsQuestion{name: "relay.example.com", qtype: typeA, class: classINET}
	valid := buildResponse(t, responseOptions{
		id:       1,
		question: question,
		answers:  []testAnswer{answer("relay.example.com", typeA, addressData(t, "203.0.113.7"))},
	})

	cases := map[string][]byte{
		"shorter than a header":  valid[:11],
		"truncated question":     valid[:14],
		"truncated record":       valid[:len(valid)-6],
		"record data runs past":  valid[:len(valid)-1],
		"answer count too large": buildResponse(t, responseOptions{id: 1, question: question, answerCount: 3}),
	}
	for description, wire := range cases {
		t.Run(description, func(t *testing.T) {
			if _, err := parseDNSMessage(wire); err == nil {
				t.Fatal("a malformed message was accepted")
			}
		})
	}
}

// Records past the answer section are never read: dproxy must not be able to
// act on an authority or additional record it did not ask for.
func TestParseDNSMessageIgnoresTrailingSections(t *testing.T) {
	question := dnsQuestion{name: "relay.example.com", qtype: typeA, class: classINET}
	wire := buildResponse(t, responseOptions{
		id:       9,
		question: question,
		answers:  []testAnswer{answer("relay.example.com", typeA, addressData(t, "203.0.113.7"))},
	})
	// Claim an additional record and append one; the parser must not care.
	binary.BigEndian.PutUint16(wire[10:12], 1)
	wire = append(wire, mustName(t, "extra.example.com")...)
	wire = binary.BigEndian.AppendUint16(wire, uint16(typeA))
	wire = binary.BigEndian.AppendUint16(wire, classINET)
	wire = binary.BigEndian.AppendUint32(wire, 60)
	wire = binary.BigEndian.AppendUint16(wire, 4)
	wire = append(wire, addressData(t, "198.51.100.1")...)

	message, err := parseDNSMessage(wire)
	if err != nil {
		t.Fatalf("parseDNSMessage: %v", err)
	}
	if len(message.answers) != 1 {
		t.Errorf("answers = %d, want only the answer section", len(message.answers))
	}
}
