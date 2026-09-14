// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	// ErrClientPinMismatch reports that inner TLS presented an unpinned client
	// key, or no client key where the remote requires one.
	ErrClientPinMismatch = errors.New("inner TLS client pin does not match")
)

// rejectedCertificateAlerts are the TLS alerts a remote sends when it refuses
// a client certificate. crypto/tls delivers a received alert as a *net.OpError
// wrapping an unexported type, so tls.AlertError does not match it; only sent
// alerts carry that type.
var rejectedCertificateAlerts = []string{
	"tls: bad certificate",
	"tls: certificate required",
	"tls: unknown certificate authority",
}

// InnerTLSInfo is the authenticated state safe diagnostics need.
type InnerTLSInfo struct {
	Version            uint16
	NegotiatedProtocol string
	ServerPin          config.Pin
	// ClientPin is zero when no client certificate was involved. On the client
	// it reports the identity that was offered: TLS 1.3 completes the client
	// handshake before the remote validates it, so acceptance is not yet known.
	ClientPin config.Pin
}

// DialInnerTLS completes a TLS 1.3 client handshake and authenticates the
// remote SPKI before it returns a connection. A caller cannot send HELLO or
// any other plaintext through the returned connection before pin verification.
// A non-nil identity is presented only if the remote requests one.
func DialInnerTLS(ctx context.Context, conn net.Conn, pin config.Pin, identity *Identity, timeout time.Duration) (*tls.Conn, *InnerTLSInfo, error) {
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
	clientPin := config.Pin{}
	if identity != nil && len(identity.Certificate.Certificate) > 0 {
		// GetClientCertificate rather than Certificates: the latter filters the
		// chain against the request and can silently send an empty certificate.
		// It runs only when the remote sent a CertificateRequest, so a
		// configured identity is a no-op against a remote that requires none.
		certificate := identity.Certificate
		configuration.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &certificate, nil
		}
		clientPin = identity.Pin
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
		ClientPin:          clientPin,
	}, nil
}

// AcceptInnerTLS completes the server half and enforces TLS 1.3 plus the
// dproxy/1 ALPN before returning the connection. A non-empty clients set
// additionally requires a pinned client certificate; it never replaces the
// token check that follows.
func AcceptInnerTLS(ctx context.Context, conn net.Conn, identity *Identity, clients config.PinSet, timeout time.Duration) (*tls.Conn, *InnerTLSInfo, error) {
	if identity == nil || len(identity.Certificate.Certificate) == 0 {
		return nil, nil, errors.New("inner TLS server identity is not configured")
	}
	configuration := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{protocol.ALPN},
		Certificates: []tls.Certificate{identity.Certificate},
	}
	if clients.Len() > 0 {
		// RequireAnyClientCert, not RequireAndVerifyClientCert: the latter
		// builds a chain before the callback runs, and pins are not a CA.
		// crypto/tls still verifies CertificateVerify against the leaf, so a
		// pin match proves possession of the private key.
		//
		// Rejecting inside the callback aborts before the client's Finished is
		// read. After the handshake the remote would hold a usable connection
		// and could decrypt the client's HELLO.
		configuration.ClientAuth = tls.RequireAnyClientCert
		configuration.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) != 1 {
				return ErrClientPinMismatch
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return ErrClientPinMismatch
			}
			if !clients.ContainsSPKI(leaf.RawSubjectPublicKeyInfo) {
				return ErrClientPinMismatch
			}
			return nil
		}
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
	clientPin := config.Pin{}
	if len(state.PeerCertificates) == 1 {
		clientPin = config.PinFromSPKI(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	}
	return tlsConn, &InnerTLSInfo{
		Version:            state.Version,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerPin:          identity.Pin,
		ClientPin:          clientPin,
	}, nil
}

// ClientCertificateRejected reports whether err is the remote refusing this
// client's inner-TLS identity. TLS 1.3 completes the client handshake before
// the remote validates the certificate, so the refusal arrives as an alert on
// the first control-message read rather than from the handshake. This only
// labels an error that already failed; it makes no security decision.
func ClientCertificateRejected(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrClientPinMismatch) || errors.Is(err, ErrClientCertificateRejected) {
		return true
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "remote error" || opErr.Err == nil {
		return false
	}
	for _, alert := range rejectedCertificateAlerts {
		if opErr.Err.Error() == alert {
			return true
		}
	}
	return false
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
