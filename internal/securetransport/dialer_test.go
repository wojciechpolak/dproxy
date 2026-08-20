// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"context"
	"crypto/tls"
	"net/netip"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
)

// newDialer builds a dialer over a stub resolver and a terminator's trust pool.
func newDialer(resolver *Resolver, roots *testTerminator, ech config.ECHMode) *SecureDialer {
	dialer := &SecureDialer{Resolver: resolver, ECH: ech, Timeouts: config.DefaultTimeouts()}
	if roots != nil {
		dialer.roots = roots.roots
	}
	return dialer
}

func TestConnectNegotiatesTLS13WithECH(t *testing.T) {
	key := newECHKey(t, "cloudflare-ech.com")
	terminator := startTerminator(t, terminatorOptions{
		names:   []string{relayName, key.publicName},
		echKeys: []tls.EncryptedClientHelloKey{{Config: key.config, PrivateKey: key.private}},
	})
	dialer := newDialer(nil, terminator, config.ECHRequired)
	dialer.ALPN = []string{"h2"}

	conn, info, err := dialer.connect(t.Context(), relayName,
		[]netip.Addr{terminator.addr()}, terminator.port(), key.list)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if !info.TLS13() || info.VersionName() != "TLSv1.3" {
		t.Errorf("version = %s", info.VersionName())
	}
	if !info.ECHAccepted {
		t.Error("ECH was not accepted")
	}
	if info.ECHPublicName != key.publicName {
		t.Errorf("outer SNI = %q, want %q", info.ECHPublicName, key.publicName)
	}
	if info.ServerName != relayName {
		t.Errorf("server name = %q, want the inner name", info.ServerName)
	}
	if info.CertificateIssuer == "" || info.CertificateExpiry.IsZero() {
		t.Errorf("certificate diagnostics = %q, %s", info.CertificateIssuer, info.CertificateExpiry)
	}
	if info.CipherSuiteName() == "" {
		t.Error("no cipher suite was reported")
	}

	// The connection is a working stream, not just a completed handshake.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buffer := make([]byte, 4)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Read(buffer); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buffer) != "ping" {
		t.Errorf("echo = %q", buffer)
	}
}

// A server that cannot decrypt the ClientHello ends the tunnel. crypto/tls
// offers a retry configuration at that point; dproxy must not take it, and
// must not fall back to a handshake in the clear.
func TestConnectFailsWhenECHIsRejected(t *testing.T) {
	served := newECHKey(t, "cloudflare-ech.com")
	published := newECHKey(t, "cloudflare-ech.com")
	terminator := startTerminator(t, terminatorOptions{
		names:   []string{relayName, served.publicName},
		echKeys: []tls.EncryptedClientHelloKey{{Config: served.config, PrivateKey: served.private}},
	})
	dialer := newDialer(nil, terminator, config.ECHRequired)

	conn, _, err := dialer.connect(t.Context(), relayName,
		[]netip.Addr{terminator.addr()}, terminator.port(), published.list)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a rejected ECH handshake produced a connection")
	}
	if reason := ReasonOf(err); reason != FailureECHRejected {
		t.Fatalf("reason = %s, want ech-rejected", reason)
	}
	if handshakes := terminator.handshakes.Load(); handshakes != 1 {
		t.Errorf("the terminator saw %d connections; a rejection must not be retried", handshakes)
	}
}

func TestConnectFailsOnAnUntrustedChain(t *testing.T) {
	key := newECHKey(t, "cloudflare-ech.com")
	terminator := startTerminator(t, terminatorOptions{
		names:     []string{relayName, key.publicName},
		echKeys:   []tls.EncryptedClientHelloKey{{Config: key.config, PrivateKey: key.private}},
		untrusted: true,
	})
	dialer := newDialer(nil, terminator, config.ECHRequired)

	conn, _, err := dialer.connect(t.Context(), relayName,
		[]netip.Addr{terminator.addr()}, terminator.port(), key.list)
	if err == nil {
		_ = conn.Close()
		t.Fatal("an untrusted chain was accepted")
	}
	if reason := ReasonOf(err); reason != FailureCertificate {
		t.Errorf("reason = %s, want certificate", reason)
	}
}

func TestConnectFailsOnACertificateForAnotherName(t *testing.T) {
	key := newECHKey(t, "cloudflare-ech.com")
	terminator := startTerminator(t, terminatorOptions{
		names:   []string{"someone-else.example", key.publicName},
		echKeys: []tls.EncryptedClientHelloKey{{Config: key.config, PrivateKey: key.private}},
	})
	dialer := newDialer(nil, terminator, config.ECHRequired)

	conn, _, err := dialer.connect(t.Context(), relayName,
		[]netip.Addr{terminator.addr()}, terminator.port(), key.list)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a certificate for another name was accepted")
	}
	if reason := ReasonOf(err); reason != FailureCertificate {
		t.Errorf("reason = %s, want certificate", reason)
	}
}

// A server that will not speak TLS 1.3 gets no second attempt at TLS 1.2.
func TestConnectRefusesAServerWithoutTLS13(t *testing.T) {
	terminator := startTerminator(t, terminatorOptions{
		names:      []string{relayName},
		maxVersion: tls.VersionTLS12,
	})
	dialer := newDialer(nil, terminator, config.ECHInsecureDisabled)

	conn, _, err := dialer.connect(t.Context(), relayName,
		[]netip.Addr{terminator.addr()}, terminator.port(), nil)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a TLS 1.2 server was accepted")
	}
	if ReasonOf(err) == FailureNone {
		t.Errorf("err = %v, want a classified transport failure", err)
	}
	if handshakes := terminator.handshakes.Load(); handshakes != 1 {
		t.Errorf("the terminator saw %d connections; TLS 1.2 must not be retried", handshakes)
	}
}

// Without ECH the handshake still has to be TLS 1.3 and still has to validate.
// This is the development escape hatch, and it gives up exactly one guarantee.
func TestConnectWithECHDisabled(t *testing.T) {
	terminator := startTerminator(t, terminatorOptions{names: []string{relayName}})
	dialer := newDialer(nil, terminator, config.ECHInsecureDisabled)

	conn, info, err := dialer.connect(t.Context(), relayName,
		[]netip.Addr{terminator.addr()}, terminator.port(), nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if !info.TLS13() {
		t.Errorf("version = %s", info.VersionName())
	}
	if info.ECHAccepted || info.ECHPublicName != "" {
		t.Error("ECH was reported for a handshake that did not use it")
	}
}

// The same server without ECH keys, dialed in required mode, is a rejection.
// Its certificate covers the public name, so the refusal is the ECH decision
// and not a chain failure that happened to arrive first.
func TestConnectRequiresECHWhenTheServerHasNone(t *testing.T) {
	key := newECHKey(t, "cloudflare-ech.com")
	terminator := startTerminator(t, terminatorOptions{names: []string{relayName, key.publicName}})
	dialer := newDialer(nil, terminator, config.ECHRequired)

	conn, _, err := dialer.connect(t.Context(), relayName,
		[]netip.Addr{terminator.addr()}, terminator.port(), key.list)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a server that ignored ECH was accepted in required mode")
	}
	if reason := ReasonOf(err); reason != FailureECHRejected {
		t.Errorf("reason = %s, want ech-rejected", reason)
	}
}

func TestConnectTriesEveryResolvedAddress(t *testing.T) {
	key := newECHKey(t, "cloudflare-ech.com")
	terminator := startTerminator(t, terminatorOptions{
		names:   []string{relayName, key.publicName},
		echKeys: []tls.EncryptedClientHelloKey{{Config: key.config, PrivateKey: key.private}},
	})
	dialer := newDialer(nil, terminator, config.ECHRequired)
	dead := closedPort(t)
	if dead == terminator.port() {
		t.Skip("the closed port was reused by the terminator")
	}

	// Two addresses, the first unreachable: the connection attempt moves on,
	// while a handshake failure would not have.
	conn, _, err := dialer.connectAll(t.Context(), relayName, []netip.AddrPort{
		netip.AddrPortFrom(terminator.addr(), dead),
		netip.AddrPortFrom(terminator.addr(), terminator.port()),
	}, key.list)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_ = conn.Close()
}

func TestConnectReportsWhenNoAddressAccepts(t *testing.T) {
	dialer := newDialer(nil, nil, config.ECHRequired)
	dead := closedPort(t)
	conn, _, err := dialer.connect(t.Context(), relayName,
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")}, dead, nil)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a dial to a closed port produced a connection")
	}
	if reason := ReasonOf(err); reason != FailureHandshake {
		t.Errorf("reason = %s, want handshake", reason)
	}
}

func TestDialRejectsANonPublicRelayAddress(t *testing.T) {
	list := testECHConfigList(t, "cloudflare-ech.com")
	resolver, _ := newStubResolver(t, zone{
		ask(relayName, typeHTTPS): {answer(relayName, typeHTTPS, httpsData(t, 1, "", svcParam(svcParamECH, list)))},
		ask(relayName, typeA):     {answer(relayName, typeA, addressData(t, "127.0.0.1"))},
	})
	dialer := newDialer(resolver, nil, config.ECHRequired)

	conn, _, err := dialer.DialHTTPS(t.Context(), relayName)
	if err == nil {
		_ = conn.Close()
		t.Fatal("a relay resolving to loopback was dialed")
	}
	if reason := ReasonOf(err); reason != FailureAddressRejected {
		t.Fatalf("reason = %s, want address-rejected", reason)
	}
	if got := err.Error(); !contains(got, "loopback") {
		t.Errorf("err = %q, want the class named", got)
	}
}

func TestDialRequiresAUsableECHConfig(t *testing.T) {
	address := answer(relayName, typeA, addressData(t, "203.0.113.10"))
	cases := map[string]struct {
		records zone
		reason  FailureReason
	}{
		"no HTTPS record at all": {
			records: zone{ask(relayName, typeA): {address}},
			reason:  FailureHTTPSRecord,
		},
		"an HTTPS record without ECH": {
			records: zone{
				ask(relayName, typeHTTPS): {answer(relayName, typeHTTPS, httpsData(t, 1, ""))},
				ask(relayName, typeA):     {address},
			},
			reason: FailureECHUnavailable,
		},
		"an ECHConfigList this build cannot use": {
			records: zone{
				ask(relayName, typeHTTPS): {answer(relayName, typeHTTPS,
					httpsData(t, 1, "", svcParam(svcParamECH, testUnsupportedECHConfigList(t))))},
				ask(relayName, typeA): {address},
			},
			reason: FailureECHUnavailable,
		},
	}
	for description, testCase := range cases {
		t.Run(description, func(t *testing.T) {
			resolver, stub := newStubResolver(t, testCase.records)
			dialer := newDialer(resolver, nil, config.ECHRequired)
			conn, _, err := dialer.DialHTTPS(t.Context(), relayName)
			if err == nil {
				_ = conn.Close()
				t.Fatal("a relay without usable ECH was dialed")
			}
			if reason := ReasonOf(err); reason != testCase.reason {
				t.Errorf("reason = %s, want %s", reason, testCase.reason)
			}
			for _, question := range stub.questions() {
				if question.qtype == typeA || question.qtype == typeAAAA {
					continue
				}
				if question.qtype != typeHTTPS {
					t.Errorf("the dialer asked an unexpected question %+v", question)
				}
			}
		})
	}
}

func TestDialWithoutAResolver(t *testing.T) {
	dialer := &SecureDialer{ECH: config.ECHRequired}
	if _, _, err := dialer.DialHTTPS(context.Background(), relayName); ReasonOf(err) != FailureDoH {
		t.Errorf("err = %v, want a DoH failure", err)
	}
}

func TestVerifyTransportEnforcesTheInvariants(t *testing.T) {
	tls12 := &TransportInfo{Version: tls.VersionTLS12, ECHAccepted: true}
	if err := verifyTransport(tls12, true); ReasonOf(err) != FailureTLSVersion {
		t.Errorf("err = %v, want tls-version", err)
	}
	noECH := &TransportInfo{Version: tls.VersionTLS13}
	if err := verifyTransport(noECH, true); ReasonOf(err) != FailureECHRejected {
		t.Errorf("err = %v, want ech-rejected", err)
	}
	if err := verifyTransport(noECH, false); err != nil {
		t.Errorf("err = %v, want acceptance when ECH is not required", err)
	}
}

// contains avoids pulling strings in for one assertion.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
