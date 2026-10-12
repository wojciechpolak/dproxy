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
	source string
	count  int
	start  time.Time
	older  *authFailureEntry
	newer  *authFailureEntry
}

type authFailureLimiter struct {
	mu      sync.Mutex
	entries map[string]*authFailureEntry
	oldest  *authFailureEntry
	newest  *authFailureEntry
	now     func() time.Time
}

func newAuthFailureLimiter() *authFailureLimiter {
	return &authFailureLimiter{entries: make(map[string]*authFailureEntry), now: time.Now}
}

func (l *authFailureLimiter) blocked(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, found := l.entries[source]
	if !found {
		return false
	}
	if now.Sub(entry.start) >= authFailureWindow {
		l.remove(entry)
		return false
	}
	return entry.count >= authFailureLimit
}

func (l *authFailureLimiter) record(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, found := l.entries[source]
	if found && now.Sub(entry.start) >= authFailureWindow {
		l.remove(entry)
		found = false
	}
	if !found {
		if len(l.entries) >= maxAuthSources {
			// Evict one attribution instead of blocking the whole relay or
			// dropping the new failure. The list is ordered by window start,
			// so this is constant time and retains the newest source.
			l.remove(l.oldest)
		}
		entry = l.insert(source, now)
	}
	entry.count++
}

func (l *authFailureLimiter) reset(source string) {
	l.mu.Lock()
	if entry, found := l.entries[source]; found {
		l.remove(entry)
	}
	l.mu.Unlock()
}

func (l *authFailureLimiter) insert(source string, now time.Time) *authFailureEntry {
	entry := &authFailureEntry{source: source, start: now, older: l.newest}
	if l.newest == nil {
		l.oldest = entry
	} else {
		l.newest.newer = entry
	}
	l.newest = entry
	l.entries[source] = entry
	return entry
}

func (l *authFailureLimiter) remove(entry *authFailureEntry) {
	if entry.older == nil {
		l.oldest = entry.newer
	} else {
		entry.older.newer = entry.newer
	}
	if entry.newer == nil {
		l.newest = entry.older
	} else {
		entry.newer.older = entry.older
	}
	delete(l.entries, entry.source)
	entry.older = nil
	entry.newer = nil
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
