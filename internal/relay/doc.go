// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package relay copies bytes in both directions between the local
// connection and the tunnel once the remote side has answered OPEN_OK.
//
// It applies cancellation, deadlines, half-close, and backpressure, and it
// never interprets, buffers wholesale, logs, or modifies the bytes it moves.
package relay
