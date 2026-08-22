// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package protocol

import (
	"errors"
	"fmt"
)

// Name is the protocol identifier and the inner TLS ALPN value. A peer that
// does not offer it fails the handshake rather than being guessed at.
const Name = "dproxy/1"

// ALPN is the inner-TLS application protocol negotiation value.
const ALPN = Name

// Version is the protocol version carried in HELLO, a distinct type so it
// cannot be confused with a length, a port, or a message type.
type Version uint8

// Version1 is the only version v1 speaks.
const Version1 Version = 1

// String implements fmt.Stringer.
func (v Version) String() string { return fmt.Sprintf("dproxy/%d", uint8(v)) }

// Supported reports whether this implementation speaks the version.
func (v Version) Supported() bool { return v == Version1 }

// MessageType identifies a control message. Framing exists only until OPEN_OK;
// after that the session is an uninterpreted byte stream.
type MessageType uint8

const (
	// MessageHello is the client's first message: version and token.
	MessageHello MessageType = 1
	// MessageHelloOK is the server's acceptance of HELLO.
	MessageHelloOK MessageType = 2
	// MessageOpen asks the server to connect to a destination.
	MessageOpen MessageType = 3
	// MessageOpenOK reports the destination connection is up. Last framed
	// message of a session.
	MessageOpenOK MessageType = 4
	// MessageOpenError refuses the destination, with a code and no free text.
	MessageOpenError MessageType = 5
)

// String implements fmt.Stringer with the wire names.
func (t MessageType) String() string {
	switch t {
	case MessageHello:
		return "HELLO"
	case MessageHelloOK:
		return "HELLO_OK"
	case MessageOpen:
		return "OPEN"
	case MessageOpenOK:
		return "OPEN_OK"
	case MessageOpenError:
		return "OPEN_ERROR"
	default:
		return fmt.Sprintf("MessageType(%d)", uint8(t))
	}
}

// Valid reports whether the type is one this version defines. An unknown type
// is a protocol error, never something to skip.
func (t MessageType) Valid() bool {
	switch t {
	case MessageHello, MessageHelloOK, MessageOpen, MessageOpenOK, MessageOpenError:
		return true
	default:
		return false
	}
}

// UnsupportedVersionError reports a version this build does not implement.
// Versions are not negotiated: a mismatch fails explicitly.
type UnsupportedVersionError struct {
	Offered Version
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("unsupported protocol version %d (this build speaks %s)", uint8(e.Offered), Version1)
}

// Sentinel errors the codec reports. Both sides use them when mapping a bad
// exchange onto a log-safe protocol failure.
var (
	// ErrMalformedMessage reports a message that does not decode.
	ErrMalformedMessage = errors.New("malformed control message")
	// ErrMessageTooLarge reports a length prefix beyond the configured
	// control-message limit.
	ErrMessageTooLarge = errors.New("control message exceeds the configured limit")
	// ErrUnknownMessageType reports a type byte this version does not
	// define.
	ErrUnknownMessageType = errors.New("unknown control message type")
	// ErrUnauthenticated reports an OPEN before the token was accepted.
	ErrUnauthenticated = errors.New("session is not authenticated")
)
