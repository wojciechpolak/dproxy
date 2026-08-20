// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// AllowedPort is the only destination port v1 permits. A constant, not
// configuration: widening it is a design change.
const AllowedPort uint16 = 443

// Destination is a validated CONNECT target. Everything that dials, resolves,
// or matches an allowlist takes one, and only this package can build one, so
// an unchecked hostname cannot reach those paths.
type Destination struct {
	host string
	port uint16
}

// NewDestination validates and canonicalizes a host and port.
func NewDestination(host string, port uint16) (Destination, error) {
	canonical, deny, err := canonicalHostname(host)
	if err != nil {
		return Destination{}, &InvalidDestinationError{Authority: host, Deny: deny, Reason: err.Error()}
	}
	if port != AllowedPort {
		return Destination{}, &InvalidDestinationError{
			Authority: canonical + ":" + strconv.Itoa(int(port)),
			Deny:      DenyPortNotAllowed,
			Reason:    fmt.Sprintf("port %d is not %d", port, AllowedPort),
		}
	}
	return Destination{host: canonical, port: port}, nil
}

// ParseAuthority validates an authority-form value: the target of a CONNECT
// request or of a decoded OPEN message.
//
// The syntax is "host:port" and "[ipv6]:port", the second only so it can be
// rejected. Everything else — missing port, service name, leading-zero port,
// userinfo, path, surrounding whitespace, second colon — is malformed.
// Nothing is repaired or guessed at.
func ParseAuthority(raw string) (Destination, error) {
	if raw == "" {
		return Destination{}, &InvalidDestinationError{
			Deny:   DenyMalformedAuthority,
			Reason: ErrNoDestination.Error(),
		}
	}
	if strings.TrimSpace(raw) != raw {
		return Destination{}, &InvalidDestinationError{
			Authority: raw,
			Deny:      DenyMalformedAuthority,
			Reason:    "surrounded by whitespace",
		}
	}
	// A bare address, bracketed or not, is still an address; classify it as
	// one rather than as "not host:port".
	if _, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return Destination{}, &InvalidDestinationError{
			Authority: raw,
			Deny:      DenyIPLiteral,
			Reason:    "IP literals are never permitted",
		}
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return Destination{}, &InvalidDestinationError{
			Authority: raw,
			Deny:      DenyMalformedAuthority,
			Reason:    "not host:port",
		}
	}
	// SplitHostPort strips brackets from any host, so "[api.example.com]:443"
	// would otherwise arrive here as an ordinary hostname. Brackets are for
	// IPv6 literals only.
	if strings.HasPrefix(raw, "[") {
		deny := DenyMalformedAuthority
		reason := "brackets are only for IPv6 address literals"
		if _, err := netip.ParseAddr(host); err == nil {
			deny = DenyIPLiteral
			reason = "IP literals are never permitted"
		}
		return Destination{}, &InvalidDestinationError{Authority: raw, Deny: deny, Reason: reason}
	}
	port, err := parsePort(portText)
	if err != nil {
		return Destination{}, &InvalidDestinationError{
			Authority: raw,
			Deny:      DenyMalformedAuthority,
			Reason:    err.Error(),
		}
	}
	return NewDestination(host, port)
}

// parsePort accepts only a canonical decimal port. ParseUint alone would take
// "0443" and "+443", two more spellings than the wire needs.
func parsePort(text string) (uint16, error) {
	if text == "" {
		return 0, errors.New("port is required")
	}
	if len(text) > 5 {
		return 0, fmt.Errorf("port %q is too long", text)
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, fmt.Errorf("port %q is not a decimal number", text)
		}
	}
	if len(text) > 1 && text[0] == '0' {
		return 0, fmt.Errorf("port %q has a leading zero", text)
	}
	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil || value == 0 || value > 65535 {
		return 0, fmt.Errorf("port %q is not a usable TCP port", text)
	}
	return uint16(value), nil
}

// Host returns the canonical hostname.
func (d Destination) Host() string { return d.host }

// Port returns the destination port.
func (d Destination) Port() uint16 { return d.port }

// IsZero reports a destination that was never built.
func (d Destination) IsZero() bool { return d.host == "" }

// Authority renders "host:port".
func (d Destination) Authority() string {
	if d.IsZero() {
		return ""
	}
	return d.host + ":" + strconv.Itoa(int(d.port))
}

// String implements fmt.Stringer. The result is a name the operator may not
// want recorded: log it through the logger's target attribute, not directly.
func (d Destination) String() string { return d.Authority() }

// InvalidDestinationError reports an unusable CONNECT target. The authority is
// kept so a caller can decide whether to record it.
type InvalidDestinationError struct {
	// Authority is the rejected value, as given.
	Authority string
	// Deny is the log-safe classification, mapping onto the OPEN_ERROR code
	// and the HTTP proxy status.
	Deny DenyReason
	// Reason is prose for a verbose log.
	Reason string
}

func (e *InvalidDestinationError) Error() string {
	return fmt.Sprintf("invalid destination %q: %s", e.Authority, e.Reason)
}

// Decision renders the refusal as a policy decision.
func (e *InvalidDestinationError) Decision() Decision { return Deny(e.Deny) }

// DenyReasonOf reports the classification carried by err. An error from
// elsewhere classifies as DenyMalformedAuthority: an unrecognized validation
// failure must never read as permission.
func DenyReasonOf(err error) DenyReason {
	if err == nil {
		return DenyNone
	}
	var invalid *InvalidDestinationError
	if errors.As(err, &invalid) && invalid.Deny != DenyNone {
		return invalid.Deny
	}
	return DenyMalformedAuthority
}

// ErrNoDestination reports an empty authority.
var ErrNoDestination = errors.New("no destination")
