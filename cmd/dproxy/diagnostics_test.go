// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/protocol"
	"github.com/wojciechpolak/dproxy/internal/securetransport"
	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

func TestCheckForFailureNamesTheRightLine(t *testing.T) {
	cases := map[securetransport.FailureReason]string{
		securetransport.FailureDoH:             checkDoH,
		securetransport.FailureHTTPSRecord:     checkHTTPSRecord,
		securetransport.FailureECHUnavailable:  checkECH,
		securetransport.FailureECHRejected:     checkECH,
		securetransport.FailureCertificate:     checkCertificate,
		securetransport.FailureTLSVersion:      checkTLS,
		securetransport.FailureHandshake:       checkTLS,
		securetransport.FailureAddressRejected: checkTLS,
	}
	for reason, want := range cases {
		if got := checkForFailure(securetransport.Fail(reason, errors.New("cause"))); got != want {
			t.Errorf("checkForFailure(%s) = %q, want %q", reason, got, want)
		}
	}
}

func TestAttributeMarksOneLineAndSkipsTheRest(t *testing.T) {
	result := &report{}
	result.attribute(securetransport.Fail(securetransport.FailureECHRejected, errors.New("rejected")), checkECH, dialChecks...)

	if !result.failed {
		t.Error("the report does not record a failure")
	}
	if len(result.checks) != len(dialChecks) {
		t.Fatalf("checks = %d, want one per label", len(result.checks))
	}
	failures := 0
	for _, entry := range result.checks {
		if entry.status == statusFailed {
			failures++
			if entry.label != checkECH {
				t.Errorf("the failure landed on %q", entry.label)
			}
		}
	}
	if failures != 1 {
		t.Errorf("failures = %d, want exactly one", failures)
	}
}

// A failure whose reason names no line in the set lands on the fallback rather
// than going unreported.
func TestAttributeUsesTheFallback(t *testing.T) {
	result := &report{}
	failure := securetransport.Fail(securetransport.FailureHTTPSRecord, errors.New("no record"))
	result.attribute(failure, checkECH, dialChecks...)
	for _, entry := range result.checks {
		if entry.status == statusFailed && entry.label != checkECH {
			t.Errorf("the failure landed on %q", entry.label)
		}
	}
	if !result.failed {
		t.Error("the failure was not reported at all")
	}
}

func TestReportRendersEachStatus(t *testing.T) {
	result := &report{}
	result.ok("plain", "")
	result.ok("valued", "TLSv1.3")
	result.fail("broken", securetransport.Fail(securetransport.FailureDoH, errors.New("no answer")))
	result.skip("untouched")

	var out strings.Builder
	result.write(&out)
	for _, want := range []string{"plain            OK", "valued           TLSv1.3", "broken           FAILED — doh: no answer", "untouched        not checked"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report omits %q:\n%s", want, out.String())
		}
	}
}

func TestReportRedactsRelayHostnameInsideFailures(t *testing.T) {
	result := &report{redactions: []string{"relay.private.example"}}
	result.fail(checkECH, securetransport.Fail(
		securetransport.FailureECHUnavailable,
		errors.New("relay.private.example publishes no usable ECH configuration"),
	))
	var out strings.Builder
	result.write(&out)
	if strings.Contains(out.String(), "relay.private.example") || !strings.Contains(out.String(), "[redacted]") {
		t.Fatalf("report did not redact the relay hostname:\n%s", out.String())
	}
}

func TestAuthenticateDiagnosticCompletesHELLOWithoutOPEN(t *testing.T) {
	token, err := config.NewToken([]byte("diagnostic-token-0123456789abcdef"))
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	inner, serverResult := diagnosticInnerPair(t, func(inner net.Conn) error {
		message, decodeErr := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes).Decode()
		if decodeErr != nil {
			return decodeErr
		}
		hello, ok := message.(protocol.Hello)
		if !ok || !hello.Token.Equal(token) {
			return errors.New("unexpected HELLO")
		}
		return protocol.NewEncoder(inner, config.DefaultLimits().MaxControlMessageBytes).Encode(
			protocol.HelloOK{Version: protocol.Version1},
		)
	})
	defer func() { _ = inner.Close() }()
	if err := authenticateDiagnostic(t.Context(), inner, token, time.Second); err != nil {
		t.Fatalf("authenticate diagnostic: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

func TestDiagnoseInnerReportsPinnedAuthentication(t *testing.T) {
	identity, err := tunnel.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	tokenText := "diagnostic-token-0123456789abcdef"
	token, err := config.NewToken([]byte(tokenText))
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(tokenText), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	clientRaw, serverRaw := net.Pipe()
	serverResult := make(chan error, 1)
	go func() {
		inner, _, err := tunnel.AcceptInnerTLS(context.Background(), serverRaw, identity, time.Second)
		if err != nil {
			serverResult <- err
			return
		}
		defer func() { _ = inner.Close() }()
		message, err := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes).Decode()
		if err != nil {
			serverResult <- err
			return
		}
		hello, ok := message.(protocol.Hello)
		if !ok || !hello.Token.Equal(token) {
			serverResult <- errors.New("unexpected HELLO")
			return
		}
		serverResult <- protocol.NewEncoder(inner, config.DefaultLimits().MaxControlMessageBytes).Encode(
			protocol.HelloOK{Version: protocol.Version1},
		)
	}()
	settings := &config.ClientConfig{
		ServerPin: identity.Pin,
		TokenFile: config.TokenFile(tokenPath),
		Timeouts:  config.DefaultTimeouts(),
	}
	result := &report{}
	diagnoseInner(t.Context(), clientRaw, settings, result)
	if err := <-serverResult; err != nil {
		t.Fatalf("server: %v", err)
	}
	if result.failed || len(result.checks) != 4 {
		t.Fatalf("inner diagnostic = %+v", result)
	}
	for _, entry := range result.checks {
		if entry.status != statusOK {
			t.Errorf("%s = %s", entry.label, entry.render())
		}
	}
}

func TestAuthenticateDiagnosticRejectsBadResponses(t *testing.T) {
	token, err := config.NewToken([]byte("diagnostic-token-0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("remote closes", func(t *testing.T) {
		inner, serverResult := diagnosticInnerPair(t, func(inner net.Conn) error {
			_, err := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes).Decode()
			return err
		})
		err := authenticateDiagnostic(t.Context(), inner, token, time.Second)
		_ = inner.Close()
		if !errors.Is(err, tunnel.ErrAuthenticationFailed) {
			t.Fatalf("authentication error = %v", err)
		}
		if err := <-serverResult; err != nil {
			t.Fatalf("server: %v", err)
		}
	})
	t.Run("unexpected message", func(t *testing.T) {
		inner, serverResult := diagnosticInnerPair(t, func(inner net.Conn) error {
			if _, err := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes).Decode(); err != nil {
				return err
			}
			return protocol.NewEncoder(inner, config.DefaultLimits().MaxControlMessageBytes).Encode(protocol.OpenOK{})
		})
		err := authenticateDiagnostic(t.Context(), inner, token, time.Second)
		_ = inner.Close()
		if err == nil || !strings.Contains(err.Error(), "unexpected HELLO") {
			t.Fatalf("authentication error = %v", err)
		}
		if err := <-serverResult; err != nil {
			t.Fatalf("server: %v", err)
		}
	})
}

func diagnosticInnerPair(t *testing.T, serve func(net.Conn) error) (*tls.Conn, <-chan error) {
	t.Helper()
	identity, err := tunnel.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	clientRaw, serverRaw := net.Pipe()
	serverResult := make(chan error, 1)
	go func() {
		inner, _, acceptErr := tunnel.AcceptInnerTLS(context.Background(), serverRaw, identity, time.Second)
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer func() { _ = inner.Close() }()
		serverResult <- serve(inner)
	}()
	inner, info, err := tunnel.DialInnerTLS(t.Context(), clientRaw, identity.Pin, time.Second)
	if err != nil {
		t.Fatalf("dial inner TLS: %v", err)
	}
	if info.Version == 0 || info.NegotiatedProtocol != protocol.ALPN {
		t.Fatalf("inner TLS info = %+v", info)
	}
	return inner, serverResult
}

func TestSafeTokenFileErrorDoesNotRevealThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sensitive-location", "token")
	_, err := config.TokenFile(path).Read()
	if err == nil {
		t.Fatal("missing token file was readable")
	}
	detail := safeTokenFileError(err).Error()
	if strings.Contains(detail, path) || detail != "token file could not be read" {
		t.Fatalf("safe token error = %q", detail)
	}

	tooOpen := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tooOpen, []byte(strings.Repeat("x", config.MinTokenBytes)), 0o644); err != nil {
		t.Fatalf("write token: %v", err)
	}
	_, err = config.TokenFile(tooOpen).Read()
	if got := safeTokenFileError(err).Error(); got != "token file permissions are too open; use 0600" {
		t.Fatalf("permission error = %q", got)
	}

	t.Run("short", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := config.TokenFile(path).Read()
		if got := safeTokenFileError(err).Error(); got != "token is shorter than 32 bytes" {
			t.Fatalf("short token error = %q", got)
		}
	})
	t.Run("directory", func(t *testing.T) {
		_, err := config.TokenFile(t.TempDir()).Read()
		if got := safeTokenFileError(err).Error(); got != "token file path names a directory" {
			t.Fatalf("directory error = %q", got)
		}
	})
	t.Run("large", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte(strings.Repeat("x", 5000)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := config.TokenFile(path).Read()
		if got := safeTokenFileError(err).Error(); got != "token file is too large" {
			t.Fatalf("large token error = %q", got)
		}
	})
}

func TestDiagnosticTransportSummaries(t *testing.T) {
	relay, err := url.Parse("wss://relay.example:8443/v1/tunnel")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if got := relayPort(relay); got != 8443 {
		t.Errorf("relayPort(explicit) = %d, want 8443", got)
	}
	relay.Host = "relay.example"
	if got := relayPort(relay); got != 443 {
		t.Errorf("relayPort(default) = %d, want 443", got)
	}
	relay.Host = "relay.example:70000"
	if got := relayPort(relay); got != 443 {
		t.Errorf("relayPort(invalid) = %d, want 443", got)
	}

	info := &securetransport.TransportInfo{}
	if got := echPublicNameOrUnknown(info); got != "accepted, public name not readable" {
		t.Errorf("empty ECH public name = %q", got)
	}
	info.ECHPublicName = "cloudflare-ech.com"
	if got := echPublicNameOrUnknown(info); got != "cloudflare-ech.com" {
		t.Errorf("ECH public name = %q", got)
	}
	if got := certificateSummary(info); got != "valid" {
		t.Errorf("certificate without expiry = %q", got)
	}
	info.CertificateExpiry = time.Date(2030, time.January, 2, 23, 0, 0, 0, time.FixedZone("test", 2*60*60))
	if got := certificateSummary(info); got != "valid until 2030-01-02" {
		t.Errorf("certificate expiry = %q", got)
	}
	info.CertificateIssuer = "Example CA"
	if got := certificateSummary(info); got != "valid until 2030-01-02, issued by Example CA" {
		t.Errorf("certificate summary = %q", got)
	}
}

func TestPlural(t *testing.T) {
	for _, test := range []struct {
		count int
		want  string
	}{
		{count: 0, want: "0 addresses"},
		{count: 1, want: "1 address"},
		{count: 2, want: "2 addresses"},
	} {
		if got := plural(test.count, "address", "addresses"); got != test.want {
			t.Errorf("plural(%d) = %q, want %q", test.count, got, test.want)
		}
	}
}
