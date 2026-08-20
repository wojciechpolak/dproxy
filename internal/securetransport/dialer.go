// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/policy"
)

// SecureDialer opens the outer connection to the WSS front end: DoH resolution,
// an ECHConfigList from the HTTPS record, TLS 1.3 only, ECH accepted, and the
// ordinary public chain validated.
//
// Every one of those is a precondition rather than a preference. There is no
// path through this type that retries without ECH, accepts TLS 1.2, or dials
// an address the resolver did not produce.
type SecureDialer struct {
	// Resolver is the in-process DoH resolver. Required.
	Resolver *Resolver
	// ECH decides whether a missing or rejected ECHConfig ends the dial.
	// Anything other than config.ECHInsecureDisabled is treated as required.
	ECH config.ECHMode
	// ALPN is offered on the outer handshake. Empty offers none.
	ALPN []string
	// Timeouts bounds the dial and the handshake.
	Timeouts config.Timeouts
	// roots replaces the system trust store. Tests set it to reach a local
	// terminator; production leaves it nil, which validates the ordinary
	// public certificate chain.
	roots *x509.CertPool
}

// echRequired reports whether the dial fails without accepted ECH.
func (d *SecureDialer) echRequired() bool { return d.ECH != config.ECHInsecureDisabled }

// DialHTTPS resolves a hostname and returns an established TLS 1.3 connection
// to it, along with what the handshake negotiated.
//
// The caller owns the connection. On any failure it returns a *Error naming the
// invariant that did not hold; none of them is retryable by design.
func (d *SecureDialer) DialHTTPS(ctx context.Context, hostname string) (net.Conn, *TransportInfo, error) {
	return d.DialPort(ctx, hostname, policy.AllowedPort)
}

// DialPort is DialHTTPS with an explicit port, for a relay URL that names one.
func (d *SecureDialer) DialPort(ctx context.Context, hostname string, port uint16) (net.Conn, *TransportInfo, error) {
	if d.Resolver == nil {
		return nil, nil, Fail(FailureDoH, errors.New("no DoH resolver is configured"))
	}
	resolution, err := d.Resolver.Resolve(ctx, hostname)
	if err != nil {
		return nil, nil, err
	}
	if d.echRequired() {
		if !resolution.HTTPSRecord {
			return nil, nil, Fail(FailureHTTPSRecord,
				fmt.Errorf("%s publishes no HTTPS record, so there is no ECH configuration to use: %w", hostname, ErrNoFallback))
		}
		if len(resolution.ECHConfig) == 0 {
			return nil, nil, Fail(FailureECHUnavailable,
				fmt.Errorf("the HTTPS record for %s carries no ECH configuration: %w", hostname, ErrNoFallback))
		}
		if err := validateECHConfigList(resolution.ECHConfig); err != nil {
			return nil, nil, Fail(FailureECHUnavailable, err)
		}
	}
	// The relay is reached over the public Internet like any destination, so
	// the same address rule applies: a name that resolves into private space
	// is refused rather than dialed.
	if decision := policy.CheckAddresses(resolution.Addresses); !decision.Allowed() {
		return nil, nil, Fail(FailureAddressRejected, addressRejection(resolution.Addresses))
	}
	return d.connect(ctx, hostname, resolution.Addresses, port, resolution.ECHConfig)
}

// connect dials every resolved address at one port.
func (d *SecureDialer) connect(
	ctx context.Context,
	serverName string,
	addresses []netip.Addr,
	port uint16,
	echConfig []byte,
) (net.Conn, *TransportInfo, error) {
	endpoints := make([]netip.AddrPort, 0, len(addresses))
	for _, address := range addresses {
		endpoints = append(endpoints, netip.AddrPortFrom(address, port))
	}
	return d.connectAll(ctx, serverName, endpoints, echConfig)
}

// connectAll performs the TCP dial and the TLS handshake against
// already-resolved and already-classified endpoints.
//
// It takes addresses rather than a name on purpose: no part of establishing a
// connection may turn a name back into a lookup, which is how a fallback to the
// operating system resolver would get in.
func (d *SecureDialer) connectAll(
	ctx context.Context,
	serverName string,
	endpoints []netip.AddrPort,
	echConfig []byte,
) (net.Conn, *TransportInfo, error) {
	if len(endpoints) == 0 {
		return nil, nil, Fail(FailureDoH, errors.New("the resolved address set is empty"))
	}
	timeouts := d.Timeouts
	if timeouts.Dial <= 0 || timeouts.TLSHandshake <= 0 {
		timeouts = config.DefaultTimeouts()
	}
	dialer := &net.Dialer{Timeout: timeouts.Dial}
	var failures []error
	for _, endpoint := range endpoints {
		raw, err := dialer.DialContext(ctx, "tcp", endpoint.String())
		if err != nil {
			failures = append(failures, err)
			continue
		}
		conn, info, err := d.handshake(ctx, raw, serverName, echConfig, timeouts.TLSHandshake)
		if err != nil {
			_ = raw.Close()
			// A handshake failure is a property of the endpoint, not of the
			// address: another address of the same name would fail the same
			// way, and retrying would only obscure which invariant broke.
			return nil, nil, err
		}
		return conn, info, nil
	}
	return nil, nil, Fail(FailureHandshake, fmt.Errorf("no resolved address accepted a connection: %w", errors.Join(failures...)))
}

// handshake runs the TLS handshake over an established connection and verifies
// what it produced.
func (d *SecureDialer) handshake(
	ctx context.Context,
	raw net.Conn,
	serverName string,
	echConfig []byte,
	timeout time.Duration,
) (net.Conn, *TransportInfo, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn := tls.Client(raw, newTLSConfig(serverName, echConfig, d.ALPN, d.roots))
	if err := conn.HandshakeContext(handshakeCtx); err != nil {
		return nil, nil, classifyHandshakeError(err)
	}
	info := transportInfoFrom(conn.ConnectionState(), echConfig)
	if err := verifyTransport(info, d.echRequired()); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, info, nil
}

// addressRejection names the class that caused a refusal without naming the
// address, so the reason can be logged in normal mode.
func addressRejection(addresses []netip.Addr) error {
	if _, class, found := policy.FirstNonPublic(addresses); found {
		return fmt.Errorf("the relay resolved to a %s address", class)
	}
	return errors.New("the relay did not resolve to any address")
}
