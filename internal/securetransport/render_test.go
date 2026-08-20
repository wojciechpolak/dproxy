// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package securetransport

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestDNSValuesRenderEveryDefinedCase(t *testing.T) {
	for value, want := range map[dnsType]string{
		typeA: "A", typeCNAME: "CNAME", typeAAAA: "AAAA", typeHTTPS: "HTTPS", 99: "TYPE99",
	} {
		if got := value.String(); got != want {
			t.Errorf("dnsType(%d) = %q, want %q", value, got, want)
		}
	}
	for value, want := range map[dnsRCode]string{
		rcodeSuccess: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", rcodeNameError: "NXDOMAIN",
		4: "NOTIMP", 5: "REFUSED", 15: "RCODE15",
	} {
		if got := value.String(); got != want {
			t.Errorf("dnsRCode(%d) = %q, want %q", value, got, want)
		}
	}
}

func TestECHParameterKeysRenderEveryRegistryName(t *testing.T) {
	for key, want := range map[svcParamKey]string{
		svcParamMandatory: "mandatory", svcParamALPN: "alpn", 2: "no-default-alpn",
		svcParamPort: "port", 4: "ipv4hint", svcParamECH: "ech", 6: "ipv6hint", 99: "key99",
	} {
		if got := key.String(); got != want {
			t.Errorf("svcParamKey(%d) = %q, want %q", key, got, want)
		}
	}
}

func TestTLSVersionNamesCoverLegacyAndUnknownValues(t *testing.T) {
	for version, want := range map[uint16]string{
		tls.VersionTLS13: "TLSv1.3",
		tls.VersionTLS12: "TLSv1.2",
		tls.VersionTLS11: "TLSv1.1",
		tls.VersionTLS10: "TLSv1.0",
		0:                "none",
		0x9999:           "TLS(0x9999)",
	} {
		if got := tlsVersionName(version); got != want {
			t.Errorf("tlsVersionName(%#x) = %q, want %q", version, got, want)
		}
	}
}

func TestTransportErrorWithoutCause(t *testing.T) {
	message := (&Error{Reason: FailureHandshake}).Error()
	if !strings.Contains(message, "handshake") {
		t.Errorf("transport error = %q", message)
	}
}
