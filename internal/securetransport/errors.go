// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"errors"
	"fmt"
)

// FailureReason names the transport invariant that did not hold. Every value is
// fatal: no retry, fallback, or flag turns one into a warning.
type FailureReason uint8

const (
	// FailureNone is the zero value.
	FailureNone FailureReason = iota
	// FailureDoH covers a resolver that could not be reached or answered
	// something that did not match the query. There is no OS-DNS fallback.
	FailureDoH
	// FailureHTTPSRecord covers a missing or unparsable HTTPS RR.
	FailureHTTPSRecord
	// FailureECHUnavailable covers an HTTPS RR with no usable ECHConfig.
	FailureECHUnavailable
	// FailureECHRejected covers a handshake completed without ECH.
	FailureECHRejected
	// FailureTLSVersion covers a negotiated version other than TLS 1.3.
	FailureTLSVersion
	// FailureCertificate covers chain validation failure.
	FailureCertificate
	// FailureRedirect covers a redirect met while establishing the tunnel.
	FailureRedirect
	// FailureAddressRejected covers an endpoint that resolved to a
	// non-public address.
	FailureAddressRejected
	// FailureHandshake covers a WebSocket upgrade that did not complete.
	FailureHandshake
)

// String returns a stable, log-safe token.
func (r FailureReason) String() string {
	switch r {
	case FailureNone:
		return "none"
	case FailureDoH:
		return "doh"
	case FailureHTTPSRecord:
		return "https-record"
	case FailureECHUnavailable:
		return "ech-unavailable"
	case FailureECHRejected:
		return "ech-rejected"
	case FailureTLSVersion:
		return "tls-version"
	case FailureCertificate:
		return "certificate"
	case FailureRedirect:
		return "redirect"
	case FailureAddressRejected:
		return "address-rejected"
	case FailureHandshake:
		return "handshake"
	default:
		return fmt.Sprintf("FailureReason(%d)", uint8(r))
	}
}

// Error is a transport failure: an enumerated reason a caller can branch on and
// a log can record, wrapping the cause for a verbose run.
type Error struct {
	Reason FailureReason
	Err    error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "transport failed: " + e.Reason.String()
	}
	return fmt.Sprintf("transport failed (%s): %v", e.Reason, e.Err)
}

// Unwrap exposes the cause to errors.Is and errors.As.
func (e *Error) Unwrap() error { return e.Err }

// Fail builds a transport failure.
func Fail(reason FailureReason, err error) error { return &Error{Reason: reason, Err: err} }

// ReasonOf reports the failure reason carried by err, or FailureNone.
func ReasonOf(err error) FailureReason {
	var failure *Error
	if errors.As(err, &failure) {
		return failure.Reason
	}
	return FailureNone
}

// ErrNoFallback is returned where a caller might otherwise degrade, so "we
// could try without ECH here" reads as a decision rather than an omission.
var ErrNoFallback = errors.New("dproxy does not downgrade: this failure is final")
