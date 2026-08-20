// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HTTPS resource records (RFC 9460) and the ECHConfigList they carry.
//
// This is where the outer-SNI guarantee comes from: the ECHConfigList in the
// HTTPS record is what crypto/tls encrypts the real ServerName under, and its
// public_name is what appears on the wire instead. A list that cannot be used
// is rejected here, at configuration time, rather than at the handshake where
// the failure would look like a network fault.

// echConfigVersion is the single ECHConfig version crypto/tls implements,
// draft-ietf-tls-esni-13. A list offering only other versions is unusable.
const echConfigVersion uint16 = 0xfe0d

// svcParamKey identifies one SvcParam. Only ech is read; the rest are parsed
// so the record can be validated rather than skimmed.
type svcParamKey uint16

const (
	svcParamMandatory svcParamKey = 0
	svcParamALPN      svcParamKey = 1
	svcParamPort      svcParamKey = 3
	svcParamECH       svcParamKey = 5
)

// String returns the registry mnemonic where there is one.
func (k svcParamKey) String() string {
	switch k {
	case svcParamMandatory:
		return "mandatory"
	case svcParamALPN:
		return "alpn"
	case 2:
		return "no-default-alpn"
	case svcParamPort:
		return "port"
	case 4:
		return "ipv4hint"
	case svcParamECH:
		return "ech"
	case 6:
		return "ipv6hint"
	default:
		return fmt.Sprintf("key%d", uint16(k))
	}
}

// Errors this file reports.
var (
	// errHTTPSRecord reports an HTTPS record that does not decode.
	errHTTPSRecord = errors.New("malformed HTTPS record")
	// errECHConfig reports an ECHConfigList dproxy cannot use.
	errECHConfig = errors.New("unusable ECHConfigList")
)

// httpsRecord is one decoded HTTPS record. Priority 0 is an AliasMode record:
// it names another owner to query rather than a service to use.
type httpsRecord struct {
	priority uint16
	target   string
	ech      []byte
	ttl      uint32
}

// alias reports an AliasMode record.
func (r httpsRecord) alias() bool { return r.priority == 0 }

// parseHTTPSRecord decodes the record data of an HTTPS record. message is the
// whole DNS message, so a target name written with a compression pointer still
// decodes; RFC 9460 forbids compressing it, but accepting it costs nothing and
// rejecting a valid answer costs a tunnel.
func parseHTTPSRecord(message []byte, record dnsRecord) (httpsRecord, error) {
	if len(record.data) < 3 {
		return httpsRecord{}, fmt.Errorf("%w: %d bytes of record data", errHTTPSRecord, len(record.data))
	}
	priority := binary.BigEndian.Uint16(record.data[:2])
	target, next, err := decodeName(message, record.dataOffset+2)
	if err != nil {
		return httpsRecord{}, fmt.Errorf("%w: target: %w", errHTTPSRecord, err)
	}
	end := record.dataOffset + len(record.data)
	if next > end {
		return httpsRecord{}, fmt.Errorf("%w: target name runs past the record", errHTTPSRecord)
	}
	params, err := parseSvcParams(message[next:end])
	if err != nil {
		return httpsRecord{}, err
	}
	return httpsRecord{
		priority: priority,
		target:   target,
		ech:      params[svcParamECH],
		ttl:      record.ttl,
	}, nil
}

// parseSvcParams decodes the SvcParams field.
//
// RFC 9460 requires keys in strictly increasing order with no duplicates, and
// that is enforced: a record carrying two "ech" values, or one hidden behind
// an out-of-order key, is refused rather than resolved by picking one.
func parseSvcParams(data []byte) (map[svcParamKey][]byte, error) {
	params := map[svcParamKey][]byte{}
	previous := -1
	for len(data) != 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("%w: truncated SvcParam", errHTTPSRecord)
		}
		key := svcParamKey(binary.BigEndian.Uint16(data[:2]))
		length := int(binary.BigEndian.Uint16(data[2:4]))
		if len(data) < 4+length {
			return nil, fmt.Errorf("%w: SvcParam %s runs past the record", errHTTPSRecord, key)
		}
		if int(key) <= previous {
			return nil, fmt.Errorf("%w: SvcParam %s is out of order or repeated", errHTTPSRecord, key)
		}
		previous = int(key)
		params[key] = data[4 : 4+length]
		data = data[4+length:]
	}
	return params, nil
}

// validateECHConfigList checks a list before it is handed to crypto/tls.
//
// A list whose configurations are all versions this build cannot use is
// invalid, not merely unsupported: in required mode the tunnel must fail here,
// naming the reason, rather than at a handshake that reports only a rejection.
func validateECHConfigList(list []byte) error {
	if len(list) < 6 {
		return fmt.Errorf("%w: %d bytes is too short", errECHConfig, len(list))
	}
	if int(binary.BigEndian.Uint16(list[:2])) != len(list)-2 {
		return fmt.Errorf("%w: outer length is inconsistent", errECHConfig)
	}
	remaining := list[2:]
	configs, supported := 0, 0
	for len(remaining) != 0 {
		if len(remaining) < 4 {
			return fmt.Errorf("%w: config header is truncated", errECHConfig)
		}
		length := int(binary.BigEndian.Uint16(remaining[2:4]))
		if length == 0 || len(remaining) < 4+length {
			return fmt.Errorf("%w: config body length is inconsistent", errECHConfig)
		}
		if binary.BigEndian.Uint16(remaining[:2]) == echConfigVersion {
			supported++
		}
		remaining = remaining[4+length:]
		configs++
	}
	if configs == 0 {
		return fmt.Errorf("%w: it contains no configurations", errECHConfig)
	}
	if supported == 0 {
		return fmt.Errorf("%w: no configuration uses version %#04x", errECHConfig, echConfigVersion)
	}
	return nil
}

// echPublicName returns the public_name of the first usable ECHConfig in a
// list. That name is what the outer ClientHello carries in place of the real
// one, so "dproxy test" can report the outer SNI from the configuration the
// handshake used instead of from a packet capture.
//
// An empty result means the list could not be walked; callers report the outer
// SNI as unknown rather than treating it as a failure, since crypto/tls has
// already accepted the list by the time this is asked.
func echPublicName(list []byte) string {
	if len(list) < 2 || int(binary.BigEndian.Uint16(list[:2])) != len(list)-2 {
		return ""
	}
	remaining := list[2:]
	for len(remaining) >= 4 {
		version := binary.BigEndian.Uint16(remaining[:2])
		length := int(binary.BigEndian.Uint16(remaining[2:4]))
		if length == 0 || len(remaining) < 4+length {
			return ""
		}
		contents := remaining[4 : 4+length]
		remaining = remaining[4+length:]
		if version != echConfigVersion {
			continue
		}
		// HpkeKeyConfig: config_id(1) kem_id(2) public_key<2> cipher_suites<2>,
		// then maximum_name_length(1) and public_name<1>.
		cursor := 3
		for _, width := range []int{2, 2} {
			if len(contents) < cursor+width {
				return ""
			}
			cursor += width + int(binary.BigEndian.Uint16(contents[cursor:cursor+width]))
		}
		if len(contents) < cursor+2 {
			return ""
		}
		cursor++
		size := int(contents[cursor])
		cursor++
		if len(contents) < cursor+size {
			return ""
		}
		return string(contents[cursor : cursor+size])
	}
	return ""
}
