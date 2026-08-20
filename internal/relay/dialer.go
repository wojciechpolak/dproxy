// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/wojciechpolak/dproxy/internal/policy"
)

// TargetDialer opens a connection only to addresses already returned by DoH
// and accepted by remote policy.
type TargetDialer interface {
	Dial(ctx context.Context, addresses []netip.Addr, port uint16, timeout time.Duration) (net.Conn, error)
}

// TCPDialer is the production target dialer. It never receives a hostname, so
// it cannot fall back to the operating system resolver.
type TCPDialer struct{}

// Dial tries each public address in resolver order.
func (TCPDialer) Dial(ctx context.Context, addresses []netip.Addr, port uint16, timeout time.Duration) (net.Conn, error) {
	if decision := policy.CheckAddresses(addresses); !decision.Allowed() {
		return nil, errors.New("target address set is not entirely public")
	}
	if port != policy.AllowedPort {
		return nil, fmt.Errorf("target port %d is not permitted", port)
	}
	if timeout <= 0 {
		return nil, errors.New("target dial timeout must be positive")
	}
	dialer := net.Dialer{Timeout: timeout}
	var failures []error
	for _, address := range addresses {
		endpoint := netip.AddrPortFrom(address, port)
		conn, err := dialer.DialContext(ctx, "tcp", endpoint.String())
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
	}
	return nil, fmt.Errorf("no resolved target address accepted a connection: %w", errors.Join(failures...))
}

var _ TargetDialer = TCPDialer{}
