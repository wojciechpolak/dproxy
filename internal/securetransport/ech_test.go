// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseHTTPSRecordReadsTheECHConfig(t *testing.T) {
	list := testECHConfigList(t, "cloudflare-ech.com")
	data := httpsData(t, 1, "", svcParam(svcParamALPN, []byte{2, 'h', '2'}), svcParam(svcParamECH, list))
	wire := buildResponse(t, responseOptions{
		id:       1,
		question: dnsQuestion{name: "relay.example.com", qtype: typeHTTPS, class: classINET},
		answers:  []testAnswer{answer("relay.example.com", typeHTTPS, data)},
	})
	message, err := parseDNSMessage(wire)
	if err != nil {
		t.Fatalf("parseDNSMessage: %v", err)
	}
	record, err := parseHTTPSRecord(message.wire, message.answers[0])
	if err != nil {
		t.Fatalf("parseHTTPSRecord: %v", err)
	}
	if record.priority != 1 || record.alias() {
		t.Errorf("record = %+v, want a service record", record)
	}
	if record.target != "" {
		t.Errorf("target = %q, want the empty owner-name form", record.target)
	}
	if !bytes.Equal(record.ech, list) {
		t.Error("the ECHConfigList was not recovered")
	}
	if record.ttl != 300 {
		t.Errorf("ttl = %d", record.ttl)
	}
}

func TestParseHTTPSRecordReadsAnAliasRecord(t *testing.T) {
	data := httpsData(t, 0, "edge.example.net")
	wire := buildResponse(t, responseOptions{
		id:       1,
		question: dnsQuestion{name: "relay.example.com", qtype: typeHTTPS, class: classINET},
		answers:  []testAnswer{answer("relay.example.com", typeHTTPS, data)},
	})
	message, _ := parseDNSMessage(wire)
	record, err := parseHTTPSRecord(message.wire, message.answers[0])
	if err != nil {
		t.Fatalf("parseHTTPSRecord: %v", err)
	}
	if !record.alias() || record.target != "edge.example.net" {
		t.Errorf("record = %+v, want an alias to edge.example.net", record)
	}
}

func TestParseHTTPSRecordRejectsMalformedRecords(t *testing.T) {
	list := testECHConfigList(t, "cloudflare-ech.com")
	cases := map[string][]byte{
		"too short for a priority": {0, 1},
		"params out of order": httpsData(t, 1, "",
			svcParam(svcParamECH, list), svcParam(svcParamALPN, []byte{2, 'h', '2'})),
		"repeated param": httpsData(t, 1, "",
			svcParam(svcParamECH, list), svcParam(svcParamECH, list)),
		"truncated param header": append(httpsData(t, 1, ""), 0, 5),
		"param runs past the record": append(httpsData(t, 1, ""),
			svcParam(svcParamECH, []byte{1, 2, 3})[:6]...),
	}
	for description, data := range cases {
		t.Run(description, func(t *testing.T) {
			wire := buildResponse(t, responseOptions{
				id:       1,
				question: dnsQuestion{name: "relay.example.com", qtype: typeHTTPS, class: classINET},
				answers:  []testAnswer{answer("relay.example.com", typeHTTPS, data)},
			})
			message, err := parseDNSMessage(wire)
			if err != nil {
				t.Fatalf("parseDNSMessage: %v", err)
			}
			if _, err := parseHTTPSRecord(message.wire, message.answers[0]); err == nil {
				t.Fatal("a malformed HTTPS record was accepted")
			} else if !errors.Is(err, errHTTPSRecord) {
				t.Errorf("err = %v, want errHTTPSRecord", err)
			}
		})
	}
}

func TestValidateECHConfigList(t *testing.T) {
	valid := testECHConfigList(t, "cloudflare-ech.com")
	if err := validateECHConfigList(valid); err != nil {
		t.Fatalf("validateECHConfigList: %v", err)
	}

	unsupported := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(unsupported[2:4], 0xfe0a)

	shortOuter := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(shortOuter[:2], uint16(len(valid)))

	zeroLength := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(zeroLength[4:6], 0)

	cases := map[string][]byte{
		"empty":                     nil,
		"too short":                 {0, 2, 0xfe, 0x0d},
		"outer length inconsistent": shortOuter,
		"config length zero":        zeroLength,
		"no supported version":      unsupported,
		"no configurations":         {0, 0},
	}
	for description, list := range cases {
		t.Run(description, func(t *testing.T) {
			if err := validateECHConfigList(list); err == nil {
				t.Fatal("an unusable ECHConfigList was accepted")
			} else if !errors.Is(err, errECHConfig) {
				t.Errorf("err = %v, want errECHConfig", err)
			}
		})
	}
}

func TestECHPublicName(t *testing.T) {
	list := testECHConfigList(t, "cloudflare-ech.com")
	if got := echPublicName(list); got != "cloudflare-ech.com" {
		t.Errorf("echPublicName = %q", got)
	}
	// A list that cannot be walked reports no name rather than a wrong one.
	for description, list := range map[string][]byte{
		"empty":               nil,
		"truncated":           list[:6],
		"unsupported only":    testUnsupportedECHConfigList(t),
		"length inconsistent": {0, 9, 0xfe, 0x0d, 0, 1, 0},
	} {
		t.Run(description, func(t *testing.T) {
			if got := echPublicName(list); got != "" {
				t.Errorf("echPublicName = %q, want empty", got)
			}
		})
	}
}
