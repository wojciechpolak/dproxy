// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestClassifyAddress(t *testing.T) {
	cases := []struct {
		address string
		want    AddressClass
	}{
		// The only class that may be dialed.
		{"1.1.1.1", AddressPublic},
		{"8.8.8.8", AddressPublic},
		{"104.18.0.1", AddressPublic},
		{"2606:4700::1111", AddressPublic},
		{"2a00:1450:4001:80f::200e", AddressPublic},

		{"0.0.0.0", AddressUnspecified},
		{"::", AddressUnspecified},

		{"127.0.0.1", AddressLoopback},
		{"127.255.255.254", AddressLoopback},
		{"::1", AddressLoopback},
		{"::ffff:127.0.0.1", AddressLoopback}, // unmapped before classifying

		{"10.0.0.1", AddressPrivate},
		{"172.16.0.1", AddressPrivate},
		{"172.31.255.255", AddressPrivate},
		{"192.168.1.1", AddressPrivate},
		{"fd00::1", AddressPrivate},
		{"fc00::1", AddressPrivate},
		{"::ffff:10.0.0.1", AddressPrivate},

		{"169.254.169.254", AddressLinkLocal}, // cloud metadata
		{"fe80::1", AddressLinkLocal},
		{"ff02::1", AddressLinkLocal},   // IPv6 link-local multicast
		{"224.0.0.1", AddressLinkLocal}, // 224.0.0.0/24 is link-local multicast

		{"224.0.1.1", AddressMulticast},
		{"239.255.255.250", AddressMulticast},
		{"ff0e::1", AddressMulticast},

		{"255.255.255.255", AddressNonGlobalUnicast},

		{"0.1.2.3", AddressReserved},          // 0.0.0.0/8
		{"100.64.0.1", AddressReserved},       // carrier-grade NAT
		{"192.0.0.1", AddressReserved},        // IETF protocol assignments
		{"192.0.2.1", AddressReserved},        // TEST-NET-1
		{"192.88.99.1", AddressReserved},      // deprecated 6to4 anycast
		{"198.18.0.1", AddressReserved},       // benchmarking
		{"198.51.100.1", AddressReserved},     // TEST-NET-2
		{"203.0.113.10", AddressReserved},     // TEST-NET-3
		{"240.0.0.1", AddressReserved},        // reserved
		{"64:ff9b::1.2.3.4", AddressReserved}, // NAT64
		{"64:ff9b:1::1", AddressReserved},
		{"100::1", AddressReserved},      // discard-only
		{"2001::1", AddressReserved},     // Teredo
		{"2001:2::1", AddressReserved},   // benchmarking
		{"2001:db8::1", AddressReserved}, // documentation
		{"2002::1", AddressReserved},     // deprecated 6to4
	}
	for _, tc := range cases {
		t.Run(tc.address, func(t *testing.T) {
			address := netip.MustParseAddr(tc.address)
			got := ClassifyAddress(address)
			if got != tc.want {
				t.Fatalf("ClassifyAddress(%s) = %s, want %s", address, got, tc.want)
			}
			if got.Public() != (tc.want == AddressPublic) {
				t.Errorf("Public() = %v for class %s", got.Public(), got)
			}
			decision := CheckAddress(address)
			if decision.Allowed() != (tc.want == AddressPublic) {
				t.Errorf("CheckAddress = %s for class %s", decision, got)
			}
			if !decision.Allowed() && decision.Reason() != DenyNonPublicAddress {
				t.Errorf("Reason() = %s, want %s", decision.Reason(), DenyNonPublicAddress)
			}
		})
	}
}

// TestClassifyInvalidAddress covers the address nobody resolved.
func TestClassifyInvalidAddress(t *testing.T) {
	var address netip.Addr
	if got := ClassifyAddress(address); got != AddressInvalid {
		t.Fatalf("ClassifyAddress(zero) = %s, want %s", got, AddressInvalid)
	}
	if CheckAddress(address).Allowed() {
		t.Error("the zero netip.Addr was permitted")
	}
}

// TestCheckAddressesRejectsMixedAnswers is the anti-rebinding property: one
// private address rejects the whole answer.
func TestCheckAddressesRejectsMixedAnswers(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("104.18.0.1"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("104.18.0.2"),
	}
	decision := CheckAddresses(addresses)
	if decision.Allowed() {
		t.Fatal("a mixed public/loopback answer was permitted")
	}
	if decision.Reason() != DenyNonPublicAddress {
		t.Errorf("Reason() = %s, want %s", decision.Reason(), DenyNonPublicAddress)
	}
	address, class, found := FirstNonPublic(addresses)
	if !found {
		t.Fatal("FirstNonPublic found nothing")
	}
	if address != netip.MustParseAddr("127.0.0.1") || class != AddressLoopback {
		t.Errorf("FirstNonPublic = %s (%s)", address, class)
	}
}

func TestCheckAddressesAllowsAnAllPublicAnswer(t *testing.T) {
	addresses := []netip.Addr{
		netip.MustParseAddr("104.18.0.1"),
		netip.MustParseAddr("2606:4700::1111"),
	}
	if decision := CheckAddresses(addresses); !decision.Allowed() {
		t.Fatalf("CheckAddresses = %s", decision)
	}
	if _, _, found := FirstNonPublic(addresses); found {
		t.Error("FirstNonPublic found a non-public address in an all-public answer")
	}
}

// TestCheckAddressesDeniesAnEmptyAnswer keeps "nothing resolved" from reading
// as "nothing was forbidden".
func TestCheckAddressesDeniesAnEmptyAnswer(t *testing.T) {
	for _, addresses := range [][]netip.Addr{nil, {}} {
		decision := CheckAddresses(addresses)
		if decision.Allowed() {
			t.Fatal("an empty answer was permitted")
		}
		if decision.Reason() != DenyResolutionFailed {
			t.Errorf("Reason() = %s, want %s", decision.Reason(), DenyResolutionFailed)
		}
	}
}

func TestAddressClassTokensAreStableAndDistinct(t *testing.T) {
	classes := []AddressClass{
		AddressPublic, AddressInvalid, AddressUnspecified, AddressLoopback,
		AddressPrivate, AddressLinkLocal, AddressMulticast,
		AddressNonGlobalUnicast, AddressReserved,
	}
	seen := map[string]bool{}
	for _, class := range classes {
		token := class.String()
		if strings.HasPrefix(token, "AddressClass(") {
			t.Errorf("class %d has no token", uint8(class))
		}
		if seen[token] {
			t.Errorf("token %q is used twice", token)
		}
		seen[token] = true
	}
	if got := AddressClass(200).String(); !strings.HasPrefix(got, "AddressClass(") {
		t.Errorf("unknown class rendered as %q", got)
	}
}
