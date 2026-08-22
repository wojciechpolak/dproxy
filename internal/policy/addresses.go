// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"fmt"
	"net/netip"
)

// AddressClass is what a resolved address turned out to be. Only
// AddressPublic may be dialed. It is an enumeration rather than a bool so the
// remote can log which class it refused without logging the address itself.
type AddressClass uint8

const (
	// AddressPublic is global unicast in no reserved range: the only class
	// dproxy connects to.
	AddressPublic AddressClass = iota
	// AddressInvalid is the zero netip.Addr, so "we never looked" cannot be
	// mistaken for "we looked and it was fine".
	AddressInvalid
	// AddressUnspecified is 0.0.0.0 or ::.
	AddressUnspecified
	// AddressLoopback is 127.0.0.0/8 or ::1.
	AddressLoopback
	// AddressPrivate is RFC 1918 or RFC 4193 unique-local space.
	AddressPrivate
	// AddressLinkLocal is 169.254.0.0/16 or fe80::/10, unicast or multicast.
	AddressLinkLocal
	// AddressMulticast is any other multicast address.
	AddressMulticast
	// AddressNonGlobalUnicast is anything left that is not global unicast.
	AddressNonGlobalUnicast
	// AddressReserved is global unicast inside a reservedPrefixes entry.
	AddressReserved
)

// String returns a stable, log-safe token.
func (c AddressClass) String() string {
	switch c {
	case AddressPublic:
		return "public"
	case AddressInvalid:
		return "invalid"
	case AddressUnspecified:
		return "unspecified"
	case AddressLoopback:
		return "loopback"
	case AddressPrivate:
		return "private"
	case AddressLinkLocal:
		return "link-local"
	case AddressMulticast:
		return "multicast"
	case AddressNonGlobalUnicast:
		return "non-global-unicast"
	case AddressReserved:
		return "reserved"
	default:
		return fmt.Sprintf("AddressClass(%d)", uint8(c))
	}
}

// Public reports whether the class may be connected to.
func (c AddressClass) Public() bool { return c == AddressPublic }

// reservedPrefixes pass the global-unicast test but are not ordinary Internet
// destinations. Carried over unchanged from DUD. Checked last, so anything
// already caught as loopback, private, link-local, or multicast never gets here.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // RFC 1122 "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // RFC 6890 IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // RFC 5737 documentation (TEST-NET-1)
	netip.MustParsePrefix("192.88.99.0/24"),  // RFC 7526 deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // RFC 5737 documentation (TEST-NET-2)
	netip.MustParsePrefix("203.0.113.0/24"),  // RFC 5737 documentation (TEST-NET-3)
	netip.MustParsePrefix("240.0.0.0/4"),     // RFC 1112 reserved
	netip.MustParsePrefix("64:ff9b::/96"),    // RFC 6052 NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),  // RFC 8215 local-use NAT64
	netip.MustParsePrefix("100::/64"),        // RFC 6666 discard-only
	netip.MustParsePrefix("2001::/32"),       // RFC 4380 Teredo
	netip.MustParsePrefix("2001:2::/48"),     // RFC 5180 benchmarking
	netip.MustParsePrefix("2001:db8::/32"),   // RFC 3849 documentation
	netip.MustParsePrefix("2002::/16"),       // RFC 7526 deprecated 6to4
}

// ClassifyAddress reports what an address is. IPv4-mapped IPv6 addresses are
// unmapped first, so ::ffff:127.0.0.1 classifies as loopback rather than
// slipping through as an ordinary IPv6 address.
func ClassifyAddress(address netip.Addr) AddressClass {
	if !address.IsValid() {
		return AddressInvalid
	}
	classified := address.Unmap()
	switch {
	case classified.IsUnspecified():
		return AddressUnspecified
	case classified.IsLoopback():
		return AddressLoopback
	case classified.IsPrivate():
		return AddressPrivate
	case classified.IsLinkLocalUnicast(), classified.IsLinkLocalMulticast():
		return AddressLinkLocal
	case classified.IsMulticast():
		return AddressMulticast
	case !classified.IsGlobalUnicast():
		return AddressNonGlobalUnicast
	}
	for _, prefix := range reservedPrefixes {
		if prefix.Contains(classified) {
			return AddressReserved
		}
	}
	return AddressPublic
}

// FirstNonPublic returns the first address that may not be dialed and its
// class, and whether one was found.
func FirstNonPublic(addresses []netip.Addr) (netip.Addr, AddressClass, bool) {
	for _, address := range addresses {
		if class := ClassifyAddress(address); !class.Public() {
			return address, class, true
		}
	}
	return netip.Addr{}, AddressPublic, false
}

// CheckAddresses decides whether a complete resolution result may be dialed.
//
// One non-public address rejects the whole answer rather than being filtered
// out of it: a mixed public/private answer is the shape of a rebinding attempt,
// and the rest of it is no longer trustworthy either. An empty result denies
// as a resolution failure, never as "no address was forbidden".
func CheckAddresses(addresses []netip.Addr) Decision {
	if len(addresses) == 0 {
		return Deny(DenyResolutionFailed)
	}
	if _, _, found := FirstNonPublic(addresses); found {
		return Deny(DenyNonPublicAddress)
	}
	return Allow()
}
