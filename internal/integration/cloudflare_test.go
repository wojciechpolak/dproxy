// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build cloudflare

package integration_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/protocol"
	"github.com/wojciechpolak/dproxy/internal/securetransport"
	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

const defaultCloudflareTarget = "example.com"

func TestCloudflareIntegration(t *testing.T) {
	settings := loadCloudflareSettings(t)
	timeouts := config.DefaultTimeouts()
	timeouts.Dial = 10 * time.Second
	timeouts.TLSHandshake = 10 * time.Second
	timeouts.Control = 10 * time.Second
	timeouts.Idle = 30 * time.Second
	timeouts.Shutdown = 5 * time.Second

	resolver, err := securetransport.NewResolver(securetransport.ResolverOptions{
		URL: settings.dohURL, Bootstrap: settings.bootstrap, Timeouts: timeouts,
	})
	if err != nil {
		t.Fatalf("build DoH resolver: %v", err)
	}
	outer, info, err := (&securetransport.SecureDialer{
		Resolver: resolver, ECH: config.ECHRequired, Timeouts: timeouts,
	}).DialPort(context.Background(), settings.relayURL.Hostname(), relayPort(t, settings.relayURL))
	if err != nil {
		t.Fatalf("establish Cloudflare TLS: %v", err)
	}
	_ = outer.Close()
	if !info.TLS13() {
		t.Fatalf("outer TLS = %s, want TLSv1.3", info.VersionName())
	}
	if !info.ECHAccepted {
		t.Fatal("Cloudflare did not accept ECH")
	}
	if info.ECHPublicName == "" {
		t.Fatal("accepted ECH handshake reported no public name")
	}
	if settings.outerSNI != "" && info.ECHPublicName != settings.outerSNI {
		t.Fatalf("outer SNI = %q, want %q", info.ECHPublicName, settings.outerSNI)
	}
	if strings.EqualFold(info.ECHPublicName, settings.relayURL.Hostname()) {
		t.Fatalf("outer SNI exposes relay hostname %q", info.ECHPublicName)
	}

	allowlist, err := policy.ParseAllowlist([]string{settings.target})
	if err != nil {
		t.Fatalf("parse target allowlist: %v", err)
	}
	clientConfig := &config.ClientConfig{
		Listen:       "127.0.0.1:1",
		RelayURL:     settings.relayURL,
		ServerPin:    settings.pin,
		TokenFile:    config.TokenFile(settings.tokenFile),
		DoHURL:       settings.dohURL,
		DoHBootstrap: settings.bootstrap,
		ECH:          config.ECHRequired,
		Allowlist:    allowlist,
		Timeouts:     timeouts,
		Log:          config.DefaultLogOptions(),
	}
	client, err := tunnel.NewClient(tunnel.ClientOptions{Config: clientConfig})
	if err != nil {
		t.Fatalf("build tunnel client: %v", err)
	}
	destination, err := policy.NewDestination(settings.target, policy.AllowedPort)
	if err != nil {
		t.Fatalf("build target: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	inner, err := client.Open(ctx, destination)
	if err != nil {
		t.Fatalf("open pinned inner tunnel: %v", err)
	}
	defer func() { _ = inner.Close() }()
	innerTLS, ok := inner.(*tls.Conn)
	if !ok {
		t.Fatalf("inner connection type = %T, want *tls.Conn", inner)
	}
	innerState := innerTLS.ConnectionState()
	if innerState.Version != tls.VersionTLS13 {
		t.Fatalf("inner TLS version = %#x, want TLS 1.3", innerState.Version)
	}
	if innerState.NegotiatedProtocol != protocol.ALPN {
		t.Fatalf("inner ALPN = %q, want %q", innerState.NegotiatedProtocol, protocol.ALPN)
	}

	originTLS := tls.Client(inner, &tls.Config{
		ServerName: settings.target,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	if err := originTLS.HandshakeContext(ctx); err != nil {
		t.Fatalf("origin TLS handshake: %v", err)
	}
	defer func() { _ = originTLS.Close() }()
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+settings.target+"/", nil)
	if err != nil {
		t.Fatalf("build origin request: %v", err)
	}
	request.Close = true
	if err := request.Write(originTLS); err != nil {
		t.Fatalf("write origin request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(originTLS), request)
	if err != nil {
		t.Fatalf("read origin response: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("origin status = %d, want 200", response.StatusCode)
	}
}

type cloudflareSettings struct {
	relayURL  *url.URL
	pin       config.Pin
	tokenFile string
	dohURL    *url.URL
	bootstrap []netip.Addr
	target    string
	outerSNI  string
}

func TestCloudflareSettingsUseSelfContainedDefaults(t *testing.T) {
	t.Setenv("DPROXY_CF_URL", "wss://relay.example/v1/tunnel")
	t.Setenv("DPROXY_CF_PIN", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	t.Setenv("DPROXY_CF_TOKEN_FILE", "/tmp/dproxy-test-token")
	t.Setenv("DPROXY_CF_DOH_URL", "")
	t.Setenv("DPROXY_CF_DOH_BOOTSTRAP", "")
	t.Setenv("DPROXY_CF_TARGET", "")
	t.Setenv("DPROXY_CF_EXPECTED_OUTER_SNI", "")

	settings := loadCloudflareSettings(t)
	if settings.dohURL.String() != config.DefaultDoHURL {
		t.Fatalf("DoH URL = %q, want %q", settings.dohURL, config.DefaultDoHURL)
	}
	if len(settings.bootstrap) == 0 {
		t.Fatal("built-in DoH bootstrap addresses are empty")
	}
	if settings.target != defaultCloudflareTarget {
		t.Fatalf("target = %q, want %q", settings.target, defaultCloudflareTarget)
	}
	if settings.outerSNI != "" {
		t.Fatalf("outer SNI override = %q, want empty", settings.outerSNI)
	}
}

func loadCloudflareSettings(t *testing.T) cloudflareSettings {
	t.Helper()
	required := map[string]string{
		"DPROXY_CF_URL":        os.Getenv("DPROXY_CF_URL"),
		"DPROXY_CF_PIN":        os.Getenv("DPROXY_CF_PIN"),
		"DPROXY_CF_TOKEN_FILE": os.Getenv("DPROXY_CF_TOKEN_FILE"),
	}
	var missing []string
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		message := "Cloudflare integration settings are missing: " + strings.Join(missing, ", ")
		if os.Getenv("DPROXY_REQUIRE_CLOUDFLARE") == "1" {
			t.Fatal(message)
		}
		t.Skip(message)
	}
	relayURL := parseURL(t, "DPROXY_CF_URL", required["DPROXY_CF_URL"])
	if relayURL.Scheme != "wss" {
		t.Fatalf("DPROXY_CF_URL scheme = %q, want wss", relayURL.Scheme)
	}
	dohText := strings.TrimSpace(os.Getenv("DPROXY_CF_DOH_URL"))
	if dohText == "" {
		dohText = config.DefaultDoHURL
	}
	dohURL := parseURL(t, "DPROXY_CF_DOH_URL", dohText)
	pin, err := config.ParsePin(required["DPROXY_CF_PIN"])
	if err != nil {
		t.Fatalf("DPROXY_CF_PIN: %v", err)
	}
	var bootstrap []netip.Addr
	bootstrapText := strings.TrimSpace(os.Getenv("DPROXY_CF_DOH_BOOTSTRAP"))
	if bootstrapText == "" {
		bootstrap = config.DefaultDoHBootstrap(dohURL)
	} else {
		for _, text := range strings.Split(bootstrapText, ",") {
			address, err := netip.ParseAddr(strings.TrimSpace(text))
			if err != nil {
				t.Fatalf("DPROXY_CF_DOH_BOOTSTRAP address %q: %v", text, err)
			}
			bootstrap = append(bootstrap, address)
		}
	}
	if len(bootstrap) == 0 {
		t.Fatal("DPROXY_CF_DOH_BOOTSTRAP is required for an unknown DoH endpoint")
	}
	target := strings.TrimSpace(os.Getenv("DPROXY_CF_TARGET"))
	if target == "" {
		target = defaultCloudflareTarget
	}
	return cloudflareSettings{
		relayURL: relayURL, pin: pin, tokenFile: required["DPROXY_CF_TOKEN_FILE"],
		dohURL: dohURL, bootstrap: bootstrap, target: target,
		outerSNI: strings.TrimSpace(os.Getenv("DPROXY_CF_EXPECTED_OUTER_SNI")),
	}
}

func parseURL(t *testing.T, name, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return parsed
}

func relayPort(t *testing.T, relayURL *url.URL) uint16 {
	t.Helper()
	if relayURL.Port() == "" {
		return policy.AllowedPort
	}
	port, err := strconv.ParseUint(relayURL.Port(), 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("relay URL port %q is invalid", relayURL.Port())
	}
	return uint16(port)
}
