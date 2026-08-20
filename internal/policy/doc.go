// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package policy decides whether a destination may be reached: authority
// canonicalization, allowlist matching, the port-443 restriction, and
// rejection of IP-literal and non-public resolved addresses.
//
// A check runs in this order, and the order matters — a refused destination
// costs no DNS query, and an allowed name is checked again after it resolves:
//
//	ParseAuthority → Allowlist.Permits → Resolver.LookupAddresses → CheckAddresses
//
// Both components apply this package independently; the remote never trusts a
// decision made by the local side.
package policy
