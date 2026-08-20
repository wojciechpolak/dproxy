// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"errors"
	"fmt"
)

// DenyReason names why a destination was refused. It is an enumeration so both
// sides map the same refusal onto the same protocol error code and HTTP status,
// and so a refusal can be logged without the hostname that caused it.
type DenyReason uint8

const (
	// DenyNone is the zero value and means "not denied".
	DenyNone DenyReason = iota
	// DenyMalformedAuthority covers an unparsable "host:port".
	DenyMalformedAuthority
	// DenyIPLiteral covers an address given where a name is required.
	DenyIPLiteral
	// DenyPortNotAllowed covers any port other than 443.
	DenyPortNotAllowed
	// DenyNotAllowlisted covers a valid hostname no pattern permits.
	DenyNotAllowlisted
	// DenyResolutionFailed covers a name DoH could not resolve.
	DenyResolutionFailed
	// DenyNonPublicAddress covers a name that resolved to loopback, private,
	// link-local, multicast, unspecified, or reserved space. This is what
	// stops the remote from becoming an SSRF path into its own network.
	DenyNonPublicAddress
)

// String returns a short, stable token suitable for a log attribute.
func (r DenyReason) String() string {
	switch r {
	case DenyNone:
		return "none"
	case DenyMalformedAuthority:
		return "malformed-authority"
	case DenyIPLiteral:
		return "ip-literal"
	case DenyPortNotAllowed:
		return "port-not-allowed"
	case DenyNotAllowlisted:
		return "not-allowlisted"
	case DenyResolutionFailed:
		return "resolution-failed"
	case DenyNonPublicAddress:
		return "non-public-address"
	default:
		return fmt.Sprintf("DenyReason(%d)", uint8(r))
	}
}

// ErrNoResolver reports a Checker asked to resolve without a resolver. It
// denies rather than falling back to any other way of resolving a name.
var ErrNoResolver = errors.New("no DoH resolver is configured; dproxy never uses the operating system resolver")

// Decision is the outcome of a policy check. The zero value denies.
//
// Compare decisions through Allowed and Reason, not with ==: a decision may
// carry a cause.
type Decision struct {
	allowed bool
	reason  DenyReason
	cause   error
}

// Allow returns a permitting decision.
func Allow() Decision { return Decision{allowed: true} }

// Deny returns a refusing decision with the reason recorded.
func Deny(reason DenyReason) Decision { return Decision{reason: reason} }

// DenyBecause returns a refusing decision carrying the underlying cause, for
// failures the reason token alone cannot explain — a resolver error above all.
//
// The cause may name the destination, so it belongs in a verbose run only;
// normal-mode logging records Reason.
func DenyBecause(reason DenyReason, cause error) Decision {
	return Decision{reason: reason, cause: cause}
}

// Allowed reports whether the destination may be used.
func (d Decision) Allowed() bool { return d.allowed }

// Reason returns why the destination was refused, or DenyNone.
func (d Decision) Reason() DenyReason { return d.reason }

// Cause returns the underlying failure behind a refusal, or nil.
func (d Decision) Cause() error { return d.cause }

// String renders the decision for a log attribute.
func (d Decision) String() string {
	if d.allowed {
		return "allow"
	}
	return "deny:" + d.reason.String()
}
