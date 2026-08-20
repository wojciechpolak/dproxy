// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// The DNS wire format, hand-written because the product module links the
// standard library and nothing else. DUD reaches for
// golang.org/x/net/dns/dnsmessage here; dproxy needs four record types and one
// query shape, which is less code than a dependency is worth.
//
// Only what a resolver must build and read is implemented: a single-question
// query, and the answer section of the response. Authority and additional
// records are never parsed, so nothing dproxy trusts can come from them.

// dnsType is a resource record type. Named so a type cannot be passed where a
// class or a length is expected.
type dnsType uint16

const (
	typeA     dnsType = 1
	typeCNAME dnsType = 5
	typeAAAA  dnsType = 28
	typeHTTPS dnsType = 65
)

// String returns the mnemonic, for error messages.
func (t dnsType) String() string {
	switch t {
	case typeA:
		return "A"
	case typeCNAME:
		return "CNAME"
	case typeAAAA:
		return "AAAA"
	case typeHTTPS:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
}

// classINET is the only class dproxy asks for or accepts.
const classINET uint16 = 1

// Wire limits. A response longer than dnsMessageLimit is refused before it is
// parsed; the name limits are RFC 1035's.
const (
	dnsMessageLimit = 65535
	dnsNameLimit    = 255
	dnsLabelLimit   = 63
	// dnsPointerBudget bounds compression-pointer following. Pointers must
	// also point strictly backwards, so this is a second bound rather than
	// the only one.
	dnsPointerBudget = 16
)

// dnsRCode is the response code. Only success is accepted; every other value
// fails the query rather than being retried elsewhere.
type dnsRCode uint8

const (
	rcodeSuccess   dnsRCode = 0
	rcodeNameError dnsRCode = 3
)

// String returns the mnemonic where there is one.
func (c dnsRCode) String() string {
	switch c {
	case rcodeSuccess:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case rcodeNameError:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", uint8(c))
	}
}

// dnsHeader is the fixed 12-byte message header.
type dnsHeader struct {
	id        uint16
	response  bool
	truncated bool
	rcode     dnsRCode
	questions uint16
	answers   uint16
}

// dnsQuestion is one question. The name is canonical: lowercase, no trailing
// dot, so a comparison against the name asked for is a string comparison.
type dnsQuestion struct {
	name  string
	qtype dnsType
	class uint16
}

// dnsRecord is one answer record. The record data is kept unparsed, together
// with its offset in the message, because an HTTPS record's target name may
// use a compression pointer into earlier bytes.
type dnsRecord struct {
	name       string
	rtype      dnsType
	class      uint16
	ttl        uint32
	data       []byte
	dataOffset int
}

// Errors the codec reports. They are wrapped rather than returned bare, so a
// caller can classify a resolution failure without matching on prose.
var (
	// errDNSMalformed reports a message that does not decode.
	errDNSMalformed = errors.New("malformed DNS message")
	// errDNSName reports a name that cannot be encoded or decoded.
	errDNSName = errors.New("invalid DNS name")
)

// encodeName appends the wire encoding of a hostname.
//
// The input is a hostname, not a presentation-format name: escapes are not
// decoded, so a name containing "\." is rejected rather than reinterpreted.
func encodeName(dst []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(dst, 0), nil
	}
	if len(name) > dnsNameLimit-2 {
		return nil, fmt.Errorf("%w: %d bytes is too long", errDNSName, len(name))
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, fmt.Errorf("%w: empty label", errDNSName)
		}
		if len(label) > dnsLabelLimit {
			return nil, fmt.Errorf("%w: label of %d bytes", errDNSName, len(label))
		}
		for i := 0; i < len(label); i++ {
			if label[i] <= 0x20 || label[i] >= 0x7f {
				return nil, fmt.Errorf("%w: label contains byte %#02x", errDNSName, label[i])
			}
		}
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	return append(dst, 0), nil
}

// decodeName reads a name at offset and returns it canonicalized along with
// the offset just past it.
//
// A label byte outside printable ASCII, or a "." inside a label, is rejected:
// a label containing a dot would decode into a name that reads as a different,
// possibly permitted one.
func decodeName(message []byte, offset int) (string, int, error) {
	var builder strings.Builder
	next := -1
	budget := dnsPointerBudget
	total := 0
	for {
		if offset < 0 || offset >= len(message) {
			return "", 0, fmt.Errorf("%w: name runs past the message", errDNSMalformed)
		}
		length := int(message[offset])
		switch {
		case length == 0:
			offset++
			if next < 0 {
				next = offset
			}
			return builder.String(), next, nil
		case length&0xc0 == 0xc0:
			if offset+1 >= len(message) {
				return "", 0, fmt.Errorf("%w: truncated compression pointer", errDNSMalformed)
			}
			target := int(binary.BigEndian.Uint16(message[offset:offset+2]) & 0x3fff)
			// Backwards-only, and bounded: two rules for one hazard, since
			// a chain of legal backwards pointers is still a chain.
			if target >= offset {
				return "", 0, fmt.Errorf("%w: compression pointer does not point backwards", errDNSMalformed)
			}
			budget--
			if budget < 0 {
				return "", 0, fmt.Errorf("%w: too many compression pointers", errDNSMalformed)
			}
			if next < 0 {
				next = offset + 2
			}
			offset = target
		case length > dnsLabelLimit:
			return "", 0, fmt.Errorf("%w: label length %d", errDNSMalformed, length)
		default:
			start := offset + 1
			if start+length > len(message) {
				return "", 0, fmt.Errorf("%w: label runs past the message", errDNSMalformed)
			}
			total += length + 1
			if total > dnsNameLimit {
				return "", 0, fmt.Errorf("%w: name exceeds %d bytes", errDNSMalformed, dnsNameLimit)
			}
			label := message[start : start+length]
			for _, character := range label {
				if character <= 0x20 || character >= 0x7f || character == '.' {
					return "", 0, fmt.Errorf("%w: label contains byte %#02x", errDNSName, character)
				}
			}
			if builder.Len() != 0 {
				builder.WriteByte('.')
			}
			builder.Write(lowerASCII(label))
			offset = start + length
		}
	}
}

// lowerASCII lowercases a label copy. DNS names are compared case-insensitively,
// and every name this package returns is already folded so callers do not have
// to remember to.
func lowerASCII(label []byte) []byte {
	folded := make([]byte, len(label))
	for i, character := range label {
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		folded[i] = character
	}
	return folded
}

// canonicalDNSName folds a name for comparison: lowercase, no trailing dot.
func canonicalDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// buildDNSQuery encodes a single-question query with recursion desired.
func buildDNSQuery(id uint16, question dnsQuestion) ([]byte, error) {
	wire := make([]byte, 0, 32+len(question.name))
	wire = binary.BigEndian.AppendUint16(wire, id)
	wire = binary.BigEndian.AppendUint16(wire, 0x0100) // RD
	wire = binary.BigEndian.AppendUint16(wire, 1)      // QDCOUNT
	wire = binary.BigEndian.AppendUint16(wire, 0)      // ANCOUNT
	wire = binary.BigEndian.AppendUint16(wire, 0)      // NSCOUNT
	wire = binary.BigEndian.AppendUint16(wire, 0)      // ARCOUNT
	wire, err := encodeName(wire, question.name)
	if err != nil {
		return nil, err
	}
	wire = binary.BigEndian.AppendUint16(wire, uint16(question.qtype))
	wire = binary.BigEndian.AppendUint16(wire, question.class)
	return wire, nil
}

// dnsMessage is a parsed response: the header, the questions it echoes, and
// the answer section. Nothing past the answers is read.
//
// The wire bytes are kept because record data may hold a compressed name,
// which can only be decoded against the whole message.
type dnsMessage struct {
	header    dnsHeader
	questions []dnsQuestion
	answers   []dnsRecord
	wire      []byte
}

// parseDNSMessage decodes a response far enough to validate it and read its
// answers. Trailing bytes after the answer section are ignored rather than
// rejected: they are the authority and additional sections, which dproxy does
// not use and must not be influenced by.
func parseDNSMessage(wire []byte) (*dnsMessage, error) {
	if len(wire) < 12 {
		return nil, fmt.Errorf("%w: shorter than a header", errDNSMalformed)
	}
	if len(wire) > dnsMessageLimit {
		return nil, fmt.Errorf("%w: %d bytes", errDNSMalformed, len(wire))
	}
	flags := binary.BigEndian.Uint16(wire[2:4])
	message := &dnsMessage{wire: wire, header: dnsHeader{
		id:        binary.BigEndian.Uint16(wire[0:2]),
		response:  flags&0x8000 != 0,
		truncated: flags&0x0200 != 0,
		rcode:     dnsRCode(flags & 0x000f),
		questions: binary.BigEndian.Uint16(wire[4:6]),
		answers:   binary.BigEndian.Uint16(wire[6:8]),
	}}
	offset := 12
	for i := 0; i < int(message.header.questions); i++ {
		name, next, err := decodeName(wire, offset)
		if err != nil {
			return nil, err
		}
		if next+4 > len(wire) {
			return nil, fmt.Errorf("%w: truncated question", errDNSMalformed)
		}
		message.questions = append(message.questions, dnsQuestion{
			name:  name,
			qtype: dnsType(binary.BigEndian.Uint16(wire[next : next+2])),
			class: binary.BigEndian.Uint16(wire[next+2 : next+4]),
		})
		offset = next + 4
	}
	for i := 0; i < int(message.header.answers); i++ {
		name, next, err := decodeName(wire, offset)
		if err != nil {
			return nil, err
		}
		if next+10 > len(wire) {
			return nil, fmt.Errorf("%w: truncated record header", errDNSMalformed)
		}
		length := int(binary.BigEndian.Uint16(wire[next+8 : next+10]))
		start := next + 10
		if start+length > len(wire) {
			return nil, fmt.Errorf("%w: record data runs past the message", errDNSMalformed)
		}
		message.answers = append(message.answers, dnsRecord{
			name:       name,
			rtype:      dnsType(binary.BigEndian.Uint16(wire[next : next+2])),
			class:      binary.BigEndian.Uint16(wire[next+2 : next+4]),
			ttl:        binary.BigEndian.Uint32(wire[next+4 : next+8]),
			data:       wire[start : start+length],
			dataOffset: start,
		})
		offset = start + length
	}
	return message, nil
}
