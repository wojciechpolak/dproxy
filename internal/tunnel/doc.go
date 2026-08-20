// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package tunnel builds and serves one dproxy tunnel: the outer WSS
// connection to the public front end, the WebSocket-to-net.Conn adapter, the
// inner TLS 1.3 session with a pinned remote identity, and the protocol
// exchange that authenticates the client and opens the remote connection.
//
// One tunnel corresponds to exactly one local CONNECT, one WSS connection,
// one inner TLS session, and one remote TCP connection. There is no
// multiplexing in v1.
package tunnel
