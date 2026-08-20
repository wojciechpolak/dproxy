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

	t.Run("expired entries are pruned", func(t *testing.T) {
		limiter := newAuthFailureLimiter()
		limiter.now = func() time.Time { return now }
		for index := range maxAuthSources {
			limiter.entries[fmt.Sprintf("expired-%d", index)] = authFailureEntry{
				count: 1,
				start: now.Add(-authFailureWindow),
			}
		}
		limiter.record("current")
		if len(limiter.entries) != 1 || limiter.entries["current"].count != 1 {
			t.Fatalf("entries after pruning = %d, want only the current source", len(limiter.entries))
		}
		if !limiter.overflow.IsZero() {
			t.Fatalf("pruning triggered overflow until %v", limiter.overflow)
		}
	})

	t.Run("a full current set fails closed", func(t *testing.T) {
		limiter := newAuthFailureLimiter()
		limiter.now = func() time.Time { return now }
		for index := range maxAuthSources {
			limiter.entries[fmt.Sprintf("current-%d", index)] = authFailureEntry{count: 1, start: now}
		}
		limiter.record("overflowing-source")
		if _, added := limiter.entries["overflowing-source"]; added {
			t.Fatal("source was added beyond the limiter's bound")
		}
		if !limiter.blocked("untracked-source") {
			t.Fatal("overflow did not temporarily fail closed")
		}
	})
}
