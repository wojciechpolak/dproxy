// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package relay

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	authFailureLimit  = 10
	authFailureWindow = time.Minute
	maxAuthSources    = 4096
)

type authFailureEntry struct {
	count int
	start time.Time
}

type authFailureLimiter struct {
	mu       sync.Mutex
	entries  map[string]authFailureEntry
	overflow time.Time
	now      func() time.Time
}

func newAuthFailureLimiter() *authFailureLimiter {
	return &authFailureLimiter{entries: make(map[string]authFailureEntry), now: time.Now}
}

func (l *authFailureLimiter) blocked(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Before(l.overflow) {
		return true
	}
	entry, found := l.entries[source]
	if !found {
		return false
	}
	if now.Sub(entry.start) >= authFailureWindow {
		delete(l.entries, source)
		return false
	}
	return entry.count >= authFailureLimit
}

func (l *authFailureLimiter) record(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, found := l.entries[source]
	if !found || now.Sub(entry.start) >= authFailureWindow {
		if len(l.entries) >= maxAuthSources {
			l.prune(now)
			if len(l.entries) >= maxAuthSources {
				l.overflow = now.Add(authFailureWindow)
				return
			}
		}
		entry = authFailureEntry{start: now}
	}
	entry.count++
	l.entries[source] = entry
}

func (l *authFailureLimiter) reset(source string) {
	l.mu.Lock()
	delete(l.entries, source)
	l.mu.Unlock()
}

func (l *authFailureLimiter) prune(now time.Time) {
	for source, entry := range l.entries {
		if now.Sub(entry.start) >= authFailureWindow {
			delete(l.entries, source)
		}
	}
}

// authenticationSource prefers Cloudflare's client address only when the
// direct peer is local or private, which is the expected Tunnel deployment.
// A public direct peer cannot choose its rate-limit key through a header.
func authenticationSource(request *http.Request) string {
	peer := remoteAddress(request.RemoteAddr)
	if peer.IsValid() && (peer.IsLoopback() || peer.IsPrivate()) {
		if forwarded, err := netip.ParseAddr(strings.TrimSpace(request.Header.Get("CF-Connecting-IP"))); err == nil {
			return forwarded.Unmap().String()
		}
	}
	if peer.IsValid() {
		return peer.Unmap().String()
	}
	return "unknown"
}

func remoteAddress(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return address
}
