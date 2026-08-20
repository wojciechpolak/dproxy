// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package relay

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/policy"
)

func TestTCPDialerRejectsUnsafeInputsBeforeDialing(t *testing.T) {
	tests := []struct {
		name      string
		addresses []netip.Addr
		port      uint16
		timeout   time.Duration
		message   string
	}{
		{"no addresses", nil, 443, time.Second, "public"},
		{"private address", []netip.Addr{netip.MustParseAddr("10.0.0.1")}, 443, time.Second, "public"},
		{"mixed addresses", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}, 443, time.Second, "public"},
		{"wrong port", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 80, time.Second, "port"},
		{"zero timeout", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 443, 0, "timeout"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (TCPDialer{}).Dial(context.Background(), test.addresses, test.port, test.timeout)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Dial() = %v, want error containing %q", err, test.message)
			}
		})
	}
}

func TestTCPDialerReportsCanceledPublicAddressAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (TCPDialer{}).Dial(ctx, []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
	}, policy.AllowedPort, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want context cancellation", err)
	}
}
