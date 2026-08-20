// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package protocol

import (
	"fmt"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/policy"
)

// Message is a control message of protocol v1. The set is closed: a decoder
// that meets anything else fails rather than extending it at runtime.
type Message interface {
	// Type reports which message this is.
	Type() MessageType
	// Validate checks the message's own fields, on both sides: a peer's
	// message is untrusted input.
	Validate() error
}

// Hello is the client's opening message. The token travels in it and nowhere
// else — never in a hostname, URL, header, or query parameter — and never
// before inner TLS and pin verification have both succeeded.
//
// Token is a config.Token rather than []byte so it redacts itself in every
// formatting path, including %+v on this struct.
type Hello struct {
	Version Version
	Token   config.Token
}

// Type implements Message.
func (Hello) Type() MessageType { return MessageHello }

// Validate implements Message.
func (m Hello) Validate() error {
	if !m.Version.Supported() {
		return &UnsupportedVersionError{Offered: m.Version}
	}
	if m.Token.IsZero() {
		return fmt.Errorf("%w: HELLO carries no token", ErrMalformedMessage)
	}
	if m.Token.Len() < config.MinTokenBytes {
		return fmt.Errorf("%w: HELLO token is shorter than %d bytes", ErrMalformedMessage, config.MinTokenBytes)
	}
	return nil
}

// String redacts, so logging a Hello cannot print its token even through the
// Message interface.
func (m Hello) String() string { return fmt.Sprintf("HELLO{version:%s, token:%s}", m.Version, m.Token) }

// HelloOK is the server's acceptance. It repeats the version so a mismatch
// surfaces immediately.
type HelloOK struct {
	Version Version
}

// Type implements Message.
func (HelloOK) Type() MessageType { return MessageHelloOK }

// Validate implements Message.
func (m HelloOK) Validate() error {
	if !m.Version.Supported() {
		return &UnsupportedVersionError{Offered: m.Version}
	}
	return nil
}

// Open asks the server to connect to one destination. It holds a
// policy.Destination, so an unchecked hostname cannot be placed in an OPEN.
type Open struct {
	Destination policy.Destination
}

// Type implements Message.
func (Open) Type() MessageType { return MessageOpen }

// Validate implements Message.
func (m Open) Validate() error {
	if m.Destination.IsZero() {
		return fmt.Errorf("%w: OPEN carries no destination", ErrMalformedMessage)
	}
	if m.Destination.Port() != policy.AllowedPort {
		return fmt.Errorf("%w: OPEN port is not %d", ErrMalformedMessage, policy.AllowedPort)
	}
	return nil
}

// OpenOK reports the remote TCP connection is established. Everything after it
// is application bytes.
type OpenOK struct{}

// Type implements Message.
func (OpenOK) Type() MessageType { return MessageOpenOK }

// Validate implements Message.
func (OpenOK) Validate() error { return nil }

// OpenError reports a refusal, as a code and nothing else: free text would let
// the remote put an arbitrary string into a client's log.
type OpenError struct {
	Code ErrorCode
}

// Type implements Message.
func (OpenError) Type() MessageType { return MessageOpenError }

// Validate implements Message.
func (m OpenError) Validate() error {
	if !m.Code.Valid() {
		return fmt.Errorf("%w: OPEN_ERROR carries an unknown code %d", ErrMalformedMessage, uint16(m.Code))
	}
	return nil
}

// ErrorCode is the reason an OPEN was refused.
type ErrorCode uint16

const (
	// ErrorUnauthenticated means OPEN arrived before an accepted HELLO.
	ErrorUnauthenticated ErrorCode = 1
	// ErrorForbiddenDestination means the remote allowlist refused the
	// destination. A malformed authority reports the same code.
	ErrorForbiddenDestination ErrorCode = 2
	// ErrorResolutionFailed means DoH did not resolve the destination.
	ErrorResolutionFailed ErrorCode = 3
	// ErrorAddressRejected means the destination resolved to a non-public
	// address.
	ErrorAddressRejected ErrorCode = 4
	// ErrorDialFailed means the outbound TCP connection failed.
	ErrorDialFailed ErrorCode = 5
	// ErrorLimitExceeded means a server limit was reached.
	ErrorLimitExceeded ErrorCode = 6
	// ErrorMalformed means the control message did not decode.
	ErrorMalformed ErrorCode = 7
	// ErrorUnsupportedVersion means the client's version is not spoken.
	ErrorUnsupportedVersion ErrorCode = 8
	// ErrorInternal means the server failed for a reason the client cannot
	// act on.
	ErrorInternal ErrorCode = 9
)

// String implements fmt.Stringer with stable, log-safe tokens.
func (c ErrorCode) String() string {
	switch c {
	case ErrorUnauthenticated:
		return "unauthenticated"
	case ErrorForbiddenDestination:
		return "forbidden-destination"
	case ErrorResolutionFailed:
		return "resolution-failed"
	case ErrorAddressRejected:
		return "address-rejected"
	case ErrorDialFailed:
		return "dial-failed"
	case ErrorLimitExceeded:
		return "limit-exceeded"
	case ErrorMalformed:
		return "malformed"
	case ErrorUnsupportedVersion:
		return "unsupported-version"
	case ErrorInternal:
		return "internal"
	default:
		return fmt.Sprintf("ErrorCode(%d)", uint16(c))
	}
}

// Valid reports whether the code is one this version defines.
func (c ErrorCode) Valid() bool {
	switch c {
	case ErrorUnauthenticated, ErrorForbiddenDestination, ErrorResolutionFailed,
		ErrorAddressRejected, ErrorDialFailed, ErrorLimitExceeded,
		ErrorMalformed, ErrorUnsupportedVersion, ErrorInternal:
		return true
	default:
		return false
	}
}

// ErrorCodeFor maps a policy denial onto the OPEN_ERROR code, so neither side
// invents its own mapping.
func ErrorCodeFor(reason policy.DenyReason) ErrorCode {
	switch reason {
	case policy.DenyResolutionFailed:
		return ErrorResolutionFailed
	case policy.DenyNonPublicAddress:
		return ErrorAddressRejected
	case policy.DenyMalformedAuthority, policy.DenyIPLiteral,
		policy.DenyPortNotAllowed, policy.DenyNotAllowlisted:
		return ErrorForbiddenDestination
	default:
		return ErrorInternal
	}
}
