// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// A local TLS terminator that really speaks ECH, so the transport tests
// exercise crypto/tls rather than a mock of it. It is the closest a unit test
// gets to Cloudflare without a network.

// testTerminator is a running TLS server.
type testTerminator struct {
	address netip.AddrPort
	roots   *x509.CertPool
	// handshakes counts accepted connections, so a test can prove the
	// client did not quietly try again after a refusal.
	handshakes atomic.Int32
}

// terminatorOptions configures the terminator.
type terminatorOptions struct {
	// names are the certificate's subject alternative names.
	names []string
	// echKeys are the ECH keys it will decrypt with. Empty serves plain TLS.
	echKeys []tls.EncryptedClientHelloKey
	// maxVersion caps the version it will negotiate. Zero means TLS 1.3.
	maxVersion uint16
	// untrusted returns a trust pool that does not contain the issuer, for
	// the chain-validation path.
	untrusted bool
}

// startTerminator brings up a TLS listener on loopback for the test's lifetime.
func startTerminator(t *testing.T, options terminatorOptions) *testTerminator {
	t.Helper()
	certificate, pool := newTestCertificate(t, options.names)
	maxVersion := options.maxVersion
	if maxVersion == 0 {
		maxVersion = tls.VersionTLS13
	}
	minVersion := uint16(tls.VersionTLS12)
	if maxVersion < tls.VersionTLS12 {
		minVersion = maxVersion
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:             []tls.Certificate{certificate},
		MinVersion:               minVersion,
		MaxVersion:               maxVersion,
		EncryptedClientHelloKeys: options.echKeys,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	terminator := &testTerminator{
		address: netip.MustParseAddrPort(listener.Addr().String()),
		roots:   pool,
	}
	if options.untrusted {
		_, terminator.roots = newTestCertificate(t, options.names)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			terminator.handshakes.Add(1)
			go func() {
				defer func() { _ = conn.Close() }()
				if err := conn.(*tls.Conn).HandshakeContext(t.Context()); err != nil {
					return
				}
				// Echo, so a test can prove the stream still works after
				// everything the transport checked.
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return terminator
}

// addr returns the terminator's address.
func (s *testTerminator) addr() netip.Addr { return s.address.Addr() }

// port returns the terminator's port.
func (s *testTerminator) port() uint16 { return s.address.Port() }

// closedPort returns a loopback port nothing is listening on.
func closedPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := netip.MustParseAddrPort(listener.Addr().String())
	if err := listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return address.Port()
}

// newTestCertificate issues a self-signed certificate for the given names and
// returns a pool that trusts it.
func newTestCertificate(t *testing.T, names []string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dproxy test"},
		Issuer:                pkix.Name{CommonName: "dproxy test issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              names,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
