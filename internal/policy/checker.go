// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"context"
	"net/netip"
)

// Resolver resolves a destination hostname. It is implemented in
// internal/securetransport by the in-process DoH resolver.
//
// An implementation must never consult the OS resolver and never emit an
// ordinary UDP or TCP DNS query: it returns an error instead, and the
// destination is refused.
type Resolver interface {
	// LookupAddresses returns the addresses for a canonical hostname, or an
	// error if resolution failed.
	LookupAddresses(ctx context.Context, host string) ([]netip.Addr, error)
}

// Checker applies the destination policy. The local client checks a CONNECT
// authority before building a tunnel; the remote checks again after decoding
// OPEN, then resolves and checks what it resolved to.
//
// The zero value permits nothing.
type Checker struct {
	allowlist Allowlist
	resolver  Resolver
}

// NewChecker builds a checker over an allowlist and a resolver.
//
// resolver may be nil on the local side, which never resolves a destination.
// A nil resolver makes Resolve deny rather than dial.
func NewChecker(allowlist Allowlist, resolver Resolver) Checker {
	return Checker{allowlist: allowlist, resolver: resolver}
}

// Allowlist returns the patterns this checker enforces.
func (c Checker) Allowlist() Allowlist { return c.allowlist }

// CanResolve reports whether a resolver was configured.
func (c Checker) CanResolve() bool { return c.resolver != nil }

// CheckAuthority parses a CONNECT request target and decides whether it may be
// reached. The Destination is usable only when the decision permits.
func (c Checker) CheckAuthority(raw string) (Destination, Decision) {
	destination, err := ParseAuthority(raw)
	if err != nil {
		return Destination{}, Deny(DenyReasonOf(err))
	}
	return destination, c.CheckDestination(destination)
}

// CheckDestination decides whether a parsed destination may be reached,
// without touching the network.
func (c Checker) CheckDestination(destination Destination) Decision {
	return c.allowlist.Permits(destination)
}

// Resolve runs the remote side's complete check and returns the addresses it
// may dial. The steps are one function because they are only correct together:
// an allowed name resolving into private space is the SSRF path this closes.
// On refusal the addresses are nil.
func (c Checker) Resolve(ctx context.Context, destination Destination) ([]netip.Addr, Decision) {
	if decision := c.CheckDestination(destination); !decision.Allowed() {
		return nil, decision
	}
	if c.resolver == nil {
		return nil, DenyBecause(DenyResolutionFailed, ErrNoResolver)
	}
	addresses, err := c.resolver.LookupAddresses(ctx, destination.Host())
	if err != nil {
		return nil, DenyBecause(DenyResolutionFailed, err)
	}
	if decision := CheckAddresses(addresses); !decision.Allowed() {
		return nil, decision
	}
	return addresses, Allow()
}
