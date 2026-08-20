// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package protocol defines dproxy/1: the length-prefixed control messages
// (HELLO, HELLO_OK, OPEN, OPEN_OK, OPEN_ERROR) exchanged inside the inner
// TLS session, their encoding, and the state machine that governs them.
//
// Framing stops after OPEN_OK; everything after it is an uninterpreted byte
// stream. Unknown versions and malformed messages fail explicitly instead of
// being guessed at.
package protocol
