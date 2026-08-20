// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package localproxy implements the loopback HTTP/1.1 CONNECT listener.
//
// It parses and validates CONNECT requests, applies the destination policy,
// asks the tunnel package for one tunnel per accepted request, and maps every
// failure onto an accurate HTTP proxy response. It never serves ordinary
// forward HTTP proxy requests and never inspects the tunnelled bytes.
package localproxy
