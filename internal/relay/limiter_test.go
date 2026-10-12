// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package relay

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthFailureLimiterBlocksAndResets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := newAuthFailureLimiter()
	limiter.now = func() time.Time { return now }

	for range authFailureLimit {
		if limiter.blocked("client") {
			t.Fatal("client blocked before reaching the failure limit")
		}
		limiter.record("client")
	}
	if !limiter.blocked("client") {
		t.Fatal("client not blocked at the failure limit")
	}
	if limiter.blocked("another-client") {
		t.Fatal("one client's failures blocked another client")
	}

	limiter.reset("client")
	if limiter.blocked("client") {
		t.Fatal("successful authentication did not reset the failure count")
	}

	for range authFailureLimit {
		limiter.record("client")
	}
	now = now.Add(authFailureWindow)
	if limiter.blocked("client") {
		t.Fatal("failure window did not expire")
	}
}

func TestAuthFailureLimiterMaintainsOrderAcrossRemovalAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := newAuthFailureLimiter()
	limiter.now = func() time.Time { return now }

	limiter.record("oldest")
	limiter.record("middle")
	limiter.record("newest")
	limiter.reset("middle")
	if limiter.oldest.source != "oldest" || limiter.oldest.newer.source != "newest" ||
		limiter.newest.source != "newest" || limiter.newest.older.source != "oldest" {
		t.Fatal("removing a middle entry broke the attribution order")
	}

	limiter.reset("newest")
	if limiter.oldest != limiter.newest || limiter.oldest.source != "oldest" {
		t.Fatal("removing the newest entry did not leave the oldest entry linked")
	}

	now = now.Add(authFailureWindow)
	limiter.record("oldest")
	if entry := limiter.entries["oldest"]; entry.count != 1 || !entry.start.Equal(now) {
		t.Fatalf("expired entry restarted as %+v, want a fresh one-failure window", entry)
	}
	limiter.record("next")
	limiter.reset("oldest")
	if limiter.oldest != limiter.newest || limiter.oldest.source != "next" {
		t.Fatal("removing the oldest entry did not promote the next entry")
	}
}

func TestAuthenticationSourceTrustsTunnelHeaderOnlyFromPrivatePeer(t *testing.T) {
	privateRequest := httptest.NewRequest("GET", "http://dproxy/v1/tunnel", nil)
	privateRequest.RemoteAddr = "127.0.0.1:12345"
	privateRequest.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if got := authenticationSource(privateRequest); got != "203.0.113.9" {
		t.Fatalf("private peer source = %q, want forwarded address", got)
	}

	publicRequest := httptest.NewRequest("GET", "http://dproxy/v1/tunnel", nil)
	publicRequest.RemoteAddr = "198.51.100.7:12345"
	publicRequest.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if got := authenticationSource(publicRequest); got != "198.51.100.7" {
		t.Fatalf("public peer source = %q, want direct peer", got)
	}

	invalidRequest := httptest.NewRequest("GET", "http://dproxy/v1/tunnel", nil)
	invalidRequest.RemoteAddr = "not-an-address"
	if got := authenticationSource(invalidRequest); got != "unknown" {
		t.Fatalf("invalid peer source = %q, want unknown", got)
	}
}

func TestAuthFailureLimiterBoundsTrackedSources(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("one expired entry is evicted per insertion", func(t *testing.T) {
		limiter := newAuthFailureLimiter()
		limiter.now = func() time.Time { return now }
		for index := range maxAuthSources {
			limiter.record(fmt.Sprintf("expired-%d", index))
		}
		now = now.Add(authFailureWindow)
		limiter.record("current")
		if len(limiter.entries) != maxAuthSources || limiter.entries["current"].count != 1 {
			t.Fatalf("entries after eviction = %d, want the fixed bound", len(limiter.entries))
		}
		if _, retained := limiter.entries["expired-0"]; retained {
			t.Fatal("oldest expired attribution was not evicted")
		}
		if _, retained := limiter.entries["expired-1"]; !retained {
			t.Fatal("one insertion performed more than one eviction")
		}
	})

	t.Run("a full current set evicts old attribution without a global block", func(t *testing.T) {
		limiter := newAuthFailureLimiter()
		limiter.now = func() time.Time { return now }
		for index := range maxAuthSources {
			limiter.record(fmt.Sprintf("current-%d", index))
		}
		limiter.record("overflowing-source")
		if len(limiter.entries) != maxAuthSources {
			t.Fatalf("entries = %d, want the fixed bound %d", len(limiter.entries), maxAuthSources)
		}
		if _, added := limiter.entries["overflowing-source"]; !added {
			t.Fatal("new source was not tracked after saturation")
		}
		if _, retained := limiter.entries["current-0"]; retained {
			t.Fatal("oldest attribution was not evicted")
		}
		for range authFailureLimit - 1 {
			limiter.record("overflowing-source")
		}
		if !limiter.blocked("overflowing-source") {
			t.Fatal("new source was not rate-limited after saturation")
		}
		if limiter.blocked("untracked-source") {
			t.Fatal("map saturation globally blocked an unrelated source")
		}
	})
}

func TestRotatingForwardedAddressesCannotTriggerAGlobalBlock(t *testing.T) {
	limiter := newAuthFailureLimiter()
	limiter.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	request := httptest.NewRequest("GET", "http://dproxy/v1/tunnel", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	for index := range maxAuthSources + 1 {
		request.Header.Set("CF-Connecting-IP", fmt.Sprintf("2001:db8::%x", index+1))
		limiter.record(authenticationSource(request))
	}
	request.Header.Set("CF-Connecting-IP", "2606:4700::1111")
	attacker := authenticationSource(request)
	for range authFailureLimit {
		limiter.record(attacker)
	}
	if !limiter.blocked(attacker) {
		t.Fatal("a stable forwarded identity escaped the limit after saturation")
	}
	request.Header.Set("CF-Connecting-IP", "2606:4700::2222")
	if legitimate := authenticationSource(request); limiter.blocked(legitimate) {
		t.Fatal("rotating forwarded identities globally blocked an unrelated source")
	}
}
