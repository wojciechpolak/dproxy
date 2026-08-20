// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// TransportInfo describes what a completed handshake negotiated.
//
// It is a plain struct rather than a tls.ConnectionState so a diagnostic can
// print it, a test can fabricate one, and nothing downstream can reach the
// certificates or the session keys through it.
//
// It carries no private hostname: the outer SNI is the public name from the
// configured ECHConfig rather than the relay's name.
type TransportInfo struct {
	// Version is the negotiated TLS version. Anything but TLS 1.3 is a
	// failure, so this exists to be reported, not branched on.
	Version uint16
	// CipherSuite is the negotiated suite.
	CipherSuite uint16
	// NegotiatedProtocol is the ALPN result, empty when none was offered.
	NegotiatedProtocol string
	// ServerName is the name the certificate was validated against. It is
	// the relay hostname on the outer session, so it is printed only when
	// the operator opted into recording destinations.
	ServerName string
	// ECHAccepted reports that the server decrypted the inner ClientHello.
	ECHAccepted bool
	// ECHPublicName is the outer SNI: the public name of the ECHConfig the
	// handshake used, read from the configuration rather than a capture.
	ECHPublicName string
	// CertificateIssuer is the issuer common name of the leaf certificate.
	CertificateIssuer string
	// CertificateExpiry is when the leaf certificate stops being valid.
	CertificateExpiry time.Time
}

// TLS13 reports whether the negotiated version is TLS 1.3.
func (i *TransportInfo) TLS13() bool { return i.Version == tls.VersionTLS13 }

// VersionName renders the negotiated version the way a diagnostic prints it.
func (i *TransportInfo) VersionName() string { return tlsVersionName(i.Version) }

// CipherSuiteName renders the negotiated suite.
func (i *TransportInfo) CipherSuiteName() string { return tls.CipherSuiteName(i.CipherSuite) }

// tlsVersionName maps a version constant onto its usual spelling.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	case 0:
		return "none"
	default:
		return fmt.Sprintf("TLS(%#04x)", version)
	}
}

// newTLSConfig builds the one TLS configuration dproxy uses.
//
// TLS 1.3 is both the minimum and the maximum: there is no version to fall
// back to, so a server that will not speak it ends the tunnel. An ECHConfigList
// is set when one was resolved, and crypto/tls then fails the handshake rather
// than completing it in the clear if the server rejects ECH.
func newTLSConfig(serverName string, echConfig []byte, alpn []string, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:                     tls.VersionTLS13,
		MaxVersion:                     tls.VersionTLS13,
		ServerName:                     serverName,
		NextProtos:                     alpn,
		RootCAs:                        roots,
		EncryptedClientHelloConfigList: append([]byte(nil), echConfig...),
	}
}

// transportInfoFrom describes a completed handshake.
func transportInfoFrom(state tls.ConnectionState, echConfig []byte) *TransportInfo {
	info := &TransportInfo{
		Version:            state.Version,
		CipherSuite:        state.CipherSuite,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerName:         state.ServerName,
		ECHAccepted:        state.ECHAccepted,
	}
	if state.ECHAccepted {
		info.ECHPublicName = echPublicName(echConfig)
	}
	if len(state.PeerCertificates) != 0 {
		leaf := state.PeerCertificates[0]
		info.CertificateIssuer = leaf.Issuer.CommonName
		info.CertificateExpiry = leaf.NotAfter
	}
	return info
}

// verifyTransport re-checks what the handshake produced.
//
// crypto/tls has already enforced every one of these, given the configuration
// above. They are checked again because the configuration is the only thing
// standing between a working tunnel and a silent downgrade, and a check that
// costs nothing is worth having where a future edit could remove the guarantee.
func verifyTransport(info *TransportInfo, echRequired bool) error {
	if !info.TLS13() {
		return Fail(FailureTLSVersion, fmt.Errorf("the server negotiated %s", info.VersionName()))
	}
	if echRequired && !info.ECHAccepted {
		return Fail(FailureECHRejected, ErrNoFallback)
	}
	return nil
}

// classifyHandshakeError maps a failed handshake onto the invariant that did
// not hold, so a caller sees "ECH was rejected" rather than "handshake failed".
//
// A rejected ECH handshake carries a retry configuration; it is deliberately
// not used. Retrying is the downgrade this design exists to prevent.
func classifyHandshakeError(err error) error {
	var echRejection *tls.ECHRejectionError
	if errors.As(err, &echRejection) {
		return Fail(FailureECHRejected, fmt.Errorf("%w: %w", err, ErrNoFallback))
	}
	var unknownAuthority x509.UnknownAuthorityError
	var invalidCertificate x509.CertificateInvalidError
	var hostnameMismatch x509.HostnameError
	var certificateVerification *tls.CertificateVerificationError
	if errors.As(err, &certificateVerification) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &invalidCertificate) ||
		errors.As(err, &hostnameMismatch) {
		return Fail(FailureCertificate, err)
	}
	return Fail(FailureHandshake, err)
}
