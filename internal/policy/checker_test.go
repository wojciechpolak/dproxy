// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// stubResolver answers from a table and records what it was asked, so a test
// can prove a refused destination never produced a query.
type stubResolver struct {
	answers map[string][]netip.Addr
	err     error
	asked   []string
}

func (r *stubResolver) LookupAddresses(_ context.Context, host string) ([]netip.Addr, error) {
	r.asked = append(r.asked, host)
	if r.err != nil {
		return nil, r.err
	}
	addresses, found := r.answers[host]
	if !found {
		return nil, errors.New("no answer")
	}
	return addresses, nil
}

func addresses(t *testing.T, literals ...string) []netip.Addr {
	t.Helper()
	parsed := make([]netip.Addr, 0, len(literals))
	for _, literal := range literals {
		address, err := netip.ParseAddr(literal)
		if err != nil {
			t.Fatalf("netip.ParseAddr(%q) = error %v", literal, err)
		}
		parsed = append(parsed, address)
	}
	return parsed
}

func TestCheckerCheckAuthority(t *testing.T) {
	checker := NewChecker(mustAllowlist(t, "api.openai.com", "*.anthropic.com"), nil)
	cases := []struct {
		name string
		raw  string
		want DenyReason // DenyNone means the authority is permitted
	}{
		{"allowed exact", "api.openai.com:443", DenyNone},
		{"allowed wildcard", "api.anthropic.com:443", DenyNone},
		{"case folded", "API.OPENAI.COM:443", DenyNone},
		{"not allowlisted", "example.com:443", DenyNotAllowlisted},
		{"bare wildcard suffix", "anthropic.com:443", DenyNotAllowlisted},
		{"suffix confusion", "evilanthropic.com:443", DenyNotAllowlisted},
		{"allowed name on the wrong port", "api.openai.com:8443", DenyPortNotAllowed},
		{"IP literal", "203.0.113.10:443", DenyIPLiteral},
		{"malformed", "api.openai.com", DenyMalformedAuthority},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			destination, decision := checker.CheckAuthority(tc.raw)
			if tc.want == DenyNone {
				if !decision.Allowed() {
					t.Fatalf("CheckAuthority(%q) = %s, want allow", tc.raw, decision)
				}
				if destination.IsZero() {
					t.Error("a permitted authority produced the zero Destination")
				}
				return
			}
			if decision.Allowed() {
				t.Fatalf("CheckAuthority(%q) = allow, want deny:%s", tc.raw, tc.want)
			}
			if decision.Reason() != tc.want {
				t.Errorf("Reason() = %s, want %s", decision.Reason(), tc.want)
			}
		})
	}
}

// TestZeroCheckerPermitsNothing stops an unconfigured component from becoming
// a generic proxy.
func TestZeroCheckerPermitsNothing(t *testing.T) {
	var checker Checker
	if checker.CanResolve() {
		t.Error("the zero Checker claims a resolver")
	}
	_, decision := checker.CheckAuthority("api.openai.com:443")
	if decision.Allowed() {
		t.Fatal("the zero Checker permitted a destination")
	}
	if decision.Reason() != DenyNotAllowlisted {
		t.Errorf("Reason() = %s", decision.Reason())
	}
	if _, decision := checker.Resolve(t.Context(), mustDestination(t, "api.openai.com:443")); decision.Allowed() {
		t.Fatal("the zero Checker resolved a destination")
	}
}

func TestCheckerResolveAllowsPublicAddresses(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]netip.Addr{
		"api.openai.com": addresses(t, "104.18.0.1", "2606:4700::1111"),
	}}
	checker := NewChecker(mustAllowlist(t, "api.openai.com"), resolver)
	resolved, decision := checker.Resolve(t.Context(), mustDestination(t, "api.openai.com:443"))
	if !decision.Allowed() {
		t.Fatalf("Resolve = %s", decision)
	}
	if len(resolved) != 2 {
		t.Errorf("Resolve returned %d addresses, want 2", len(resolved))
	}
	if !checker.CanResolve() {
		t.Error("CanResolve() = false with a resolver configured")
	}
}

// TestCheckerResolveRejectsNonPublicAnswers is the SSRF check: an allowlisted
// name resolving into the remote's own network must not be dialed.
func TestCheckerResolveRejectsNonPublicAnswers(t *testing.T) {
	cases := []struct {
		name   string
		answer []string
	}{
		{"loopback", []string{"127.0.0.1"}},
		{"IPv6 loopback", []string{"::1"}},
		{"RFC1918", []string{"10.1.2.3"}},
		{"unique local", []string{"fd00::1"}},
		{"link-local metadata", []string{"169.254.169.254"}},
		{"unspecified", []string{"0.0.0.0"}},
		{"multicast", []string{"239.255.255.250"}},
		{"documentation range", []string{"203.0.113.10"}},
		{"IPv4-mapped loopback", []string{"::ffff:127.0.0.1"}},
		{"public first, private second", []string{"104.18.0.1", "192.168.1.1"}},
		{"private first, public second", []string{"192.168.1.1", "104.18.0.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &stubResolver{answers: map[string][]netip.Addr{
				"api.openai.com": addresses(t, tc.answer...),
			}}
			checker := NewChecker(mustAllowlist(t, "api.openai.com"), resolver)
			resolved, decision := checker.Resolve(t.Context(), mustDestination(t, "api.openai.com:443"))
			if decision.Allowed() {
				t.Fatalf("Resolve permitted %v", tc.answer)
			}
			if decision.Reason() != DenyNonPublicAddress {
				t.Errorf("Reason() = %s, want %s", decision.Reason(), DenyNonPublicAddress)
			}
			if resolved != nil {
				t.Errorf("a refused resolution returned %v", resolved)
			}
		})
	}
}

// TestCheckerResolveDoesNotQueryARefusedDestination proves the ordering: a
// refused name never reaches the resolver, so it leaks to nobody.
func TestCheckerResolveDoesNotQueryARefusedDestination(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]netip.Addr{
		"example.com": addresses(t, "104.18.0.1"),
	}}
	checker := NewChecker(mustAllowlist(t, "api.openai.com"), resolver)
	_, decision := checker.Resolve(t.Context(), mustDestination(t, "example.com:443"))
	if decision.Allowed() {
		t.Fatal("a non-allowlisted destination was permitted")
	}
	if decision.Reason() != DenyNotAllowlisted {
		t.Errorf("Reason() = %s", decision.Reason())
	}
	if len(resolver.asked) != 0 {
		t.Errorf("the resolver was queried for %v", resolver.asked)
	}
}

func TestCheckerResolveReportsAResolverFailure(t *testing.T) {
	failure := errors.New("DoH unreachable")
	resolver := &stubResolver{err: failure}
	checker := NewChecker(mustAllowlist(t, "api.openai.com"), resolver)
	resolved, decision := checker.Resolve(t.Context(), mustDestination(t, "api.openai.com:443"))
	if decision.Allowed() {
		t.Fatal("a failed resolution was permitted")
	}
	if decision.Reason() != DenyResolutionFailed {
		t.Errorf("Reason() = %s, want %s", decision.Reason(), DenyResolutionFailed)
	}
	if !errors.Is(decision.Cause(), failure) {
		t.Errorf("Cause() = %v, want %v", decision.Cause(), failure)
	}
	if resolved != nil {
		t.Errorf("a failed resolution returned %v", resolved)
	}
}

// TestCheckerWithoutResolverDeniesRatherThanFallingBack: there is no other way
// to resolve a name.
func TestCheckerWithoutResolverDeniesRatherThanFallingBack(t *testing.T) {
	checker := NewChecker(mustAllowlist(t, "api.openai.com"), nil)
	_, decision := checker.Resolve(t.Context(), mustDestination(t, "api.openai.com:443"))
	if decision.Allowed() {
		t.Fatal("a checker with no resolver permitted a destination")
	}
	if decision.Reason() != DenyResolutionFailed {
		t.Errorf("Reason() = %s, want %s", decision.Reason(), DenyResolutionFailed)
	}
	if !errors.Is(decision.Cause(), ErrNoResolver) {
		t.Errorf("Cause() = %v, want %v", decision.Cause(), ErrNoResolver)
	}
}

// TestBothSidesReachTheSameDecision: both roles run the same code over the
// same configuration, and the remote applies it to what it decoded.
func TestBothSidesReachTheSameDecision(t *testing.T) {
	entries := []string{"api.openai.com", "*.openai.com", "api.anthropic.com"}
	local := NewChecker(mustAllowlist(t, entries...), nil)
	remote := NewChecker(mustAllowlist(t, entries...), &stubResolver{
		answers: map[string][]netip.Addr{"api.openai.com": addresses(t, "104.18.0.1")},
	})

	authorities := []string{
		"api.openai.com:443", "cdn.openai.com:443", "api.anthropic.com:443",
		"openai.com:443", "evilopenai.com:443", "example.com:443",
		"api.openai.com:80", "203.0.113.10:443", "[::1]:443", "api.openai.com",
		"", " api.openai.com:443",
	}
	for _, authority := range authorities {
		t.Run(authority, func(t *testing.T) {
			localDestination, localDecision := local.CheckAuthority(authority)
			remoteDestination, remoteDecision := remote.CheckAuthority(authority)
			if localDecision.Allowed() != remoteDecision.Allowed() ||
				localDecision.Reason() != remoteDecision.Reason() {
				t.Fatalf("local = %s, remote = %s", localDecision, remoteDecision)
			}
			if localDestination != remoteDestination {
				t.Fatalf("local = %s, remote = %s", localDestination, remoteDestination)
			}
			if !localDecision.Allowed() {
				return
			}
			if decision := remote.CheckDestination(remoteDestination); !decision.Allowed() {
				t.Errorf("the remote refused what it had just permitted: %s", decision)
			}
		})
	}
}

// TestRemoteRefusesAForgedDestination covers a client that ignores its own
// allowlist.
func TestRemoteRefusesAForgedDestination(t *testing.T) {
	resolver := &stubResolver{answers: map[string][]netip.Addr{
		"internal.corp.test": addresses(t, "10.0.0.5"),
	}}
	remote := NewChecker(mustAllowlist(t, "api.openai.com"), resolver)
	forged := mustDestination(t, "internal.corp.test:443")
	resolved, decision := remote.Resolve(t.Context(), forged)
	if decision.Allowed() {
		t.Fatal("the remote relayed a destination its own allowlist refuses")
	}
	if decision.Reason() != DenyNotAllowlisted {
		t.Errorf("Reason() = %s", decision.Reason())
	}
	if resolved != nil || len(resolver.asked) != 0 {
		t.Errorf("the remote resolved %v for a refused destination", resolver.asked)
	}
}
