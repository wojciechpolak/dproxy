// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/protocol"
)

var (
	// ErrPinMismatch reports that inner TLS presented another remote key.
	ErrPinMismatch = errors.New("inner TLS server pin does not match")
	// ErrALPNMismatch reports that the peer did not negotiate dproxy/1.
	ErrALPNMismatch = errors.New("inner TLS did not negotiate dproxy/1")
)

// InnerTLSInfo is the authenticated state safe diagnostics need.
type InnerTLSInfo struct {
	Version            uint16
	NegotiatedProtocol string
	ServerPin          config.Pin
}

// DialInnerTLS completes a TLS 1.3 client handshake and authenticates the
// remote SPKI before it returns a connection. A caller cannot send HELLO or
// any other plaintext through the returned connection before pin verification.
func DialInnerTLS(ctx context.Context, conn net.Conn, pin config.Pin, timeout time.Duration) (*tls.Conn, *InnerTLSInfo, error) {
	if pin.IsZero() {
		return nil, nil, errors.New("inner TLS server pin is not configured")
	}
	configuration := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{protocol.ALPN},
		// The self-signed identity has no DNS name. VerifyConnection below
		// authenticates the exact SPKI configured by the operator.
		InsecureSkipVerify: true, // #nosec G402 -- mandatory SPKI verification below
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.Version != tls.VersionTLS13 {
				return fmt.Errorf("inner TLS negotiated version %#x, want TLS 1.3", state.Version)
			}
			if state.NegotiatedProtocol != protocol.ALPN {
				return fmt.Errorf("%w: got %q", ErrALPNMismatch, state.NegotiatedProtocol)
			}
			if len(state.PeerCertificates) != 1 || !pin.MatchesSPKI(state.PeerCertificates[0].RawSubjectPublicKeyInfo) {
				return ErrPinMismatch
			}
			return nil
		},
	}
	tlsConn := tls.Client(conn, configuration)
	if err := handshakeInnerTLS(ctx, tlsConn, timeout); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	state := tlsConn.ConnectionState()
	return tlsConn, &InnerTLSInfo{
		Version:            state.Version,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerPin:          pin,
	}, nil
}

// AcceptInnerTLS completes the server half and enforces TLS 1.3 plus the
// dproxy/1 ALPN before returning the connection.
func AcceptInnerTLS(ctx context.Context, conn net.Conn, identity *Identity, timeout time.Duration) (*tls.Conn, *InnerTLSInfo, error) {
	if identity == nil || len(identity.Certificate.Certificate) == 0 {
		return nil, nil, errors.New("inner TLS server identity is not configured")
	}
	configuration := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{protocol.ALPN},
		Certificates: []tls.Certificate{identity.Certificate},
	}
	tlsConn := tls.Server(conn, configuration)
	if err := handshakeInnerTLS(ctx, tlsConn, timeout); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		_ = tlsConn.Close()
		return nil, nil, fmt.Errorf("inner TLS negotiated version %#x, want TLS 1.3", state.Version)
	}
	if state.NegotiatedProtocol != protocol.ALPN {
		_ = tlsConn.Close()
		return nil, nil, fmt.Errorf("%w: got %q", ErrALPNMismatch, state.NegotiatedProtocol)
	}
	return tlsConn, &InnerTLSInfo{
		Version:            state.Version,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerPin:          identity.Pin,
	}, nil
}

func handshakeInnerTLS(ctx context.Context, conn *tls.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return errors.New("inner TLS handshake timeout must be positive")
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set inner TLS handshake deadline: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("inner TLS handshake: %w", err)
	}
	return nil
}
