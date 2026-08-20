// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q) = %v", raw, err)
	}
	return parsed
}

func validClient(t *testing.T) *ClientConfig {
	t.Helper()
	pin, err := ParsePin("sha256:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("ParsePin = %v", err)
	}
	return &ClientConfig{
		Listen:       DefaultClientListen,
		RelayURL:     mustURL(t, "wss://dproxy.example.com/v1/tunnel"),
		ServerPin:    pin,
		TokenFile:    "/run/secrets/dproxy-token",
		DoHURL:       mustURL(t, DefaultDoHURL),
		DoHBootstrap: DefaultDoHBootstrap(mustURL(t, DefaultDoHURL)),
		ECH:          ECHRequired,
		Allowlist:    DefaultAllowlist(),
		Timeouts:     DefaultTimeouts(),
		Log:          DefaultLogOptions(),
	}
}

func TestClientConfigValid(t *testing.T) {
	config := validClient(t)
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if config.Mode() != ModeClient {
		t.Errorf("Mode() = %v", config.Mode())
	}
}

func TestClientConfigRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ClientConfig)
		message string
	}{
		{"non-loopback listener", func(c *ClientConfig) { c.Listen = "0.0.0.0:18080" }, "loopback"},
		{"public listener", func(c *ClientConfig) { c.Listen = "192.168.1.5:18080" }, "loopback"},
		{"named listener", func(c *ClientConfig) { c.Listen = "localhost:18080" }, "IP literal"},
		{"listener without port", func(c *ClientConfig) { c.Listen = "127.0.0.1" }, "host:port"},
		{"missing relay", func(c *ClientConfig) { c.RelayURL = nil }, "required"},
		{"https relay", func(c *ClientConfig) { c.RelayURL = mustURL(t, "https://dproxy.example.com/v1/tunnel") }, "not wss"},
		{"ws relay", func(c *ClientConfig) { c.RelayURL = mustURL(t, "ws://dproxy.example.com/v1/tunnel") }, "not wss"},
		{"relay with query", func(c *ClientConfig) { c.RelayURL = mustURL(t, "wss://dproxy.example.com/t?token=x") }, "query"},
		{"relay with userinfo", func(c *ClientConfig) { c.RelayURL = mustURL(t, "wss://user:pass@dproxy.example.com/t") }, "userinfo"},
		{"relay by IP", func(c *ClientConfig) { c.RelayURL = mustURL(t, "wss://203.0.113.10/v1/tunnel") }, "IP literal"},
		{"relay on odd port", func(c *ClientConfig) { c.RelayURL = mustURL(t, "wss://dproxy.example.com:8443/t") }, "not 443"},
		{"missing pin", func(c *ClientConfig) { c.ServerPin = Pin{} }, "pin is required"},
		{"missing token file", func(c *ClientConfig) { c.TokenFile = "" }, "token file is required"},
		{"plaintext DoH", func(c *ClientConfig) { c.DoHURL = mustURL(t, "http://cloudflare-dns.com/dns-query") }, "not https"},
		{"DoH with query", func(c *ClientConfig) { c.DoHURL = mustURL(t, "https://cloudflare-dns.com/dns-query?dns=x") }, "query"},
		{"unknown ECH mode", func(c *ClientConfig) { c.ECH = "maybe" }, "unknown ECH mode"},
		{"empty allowlist", func(c *ClientConfig) { c.Allowlist = policyEmpty() }, "allowlist is empty"},
		{"zero dial timeout", func(c *ClientConfig) { c.Timeouts.Dial = 0 }, "dial timeout"},
		{"negative idle timeout", func(c *ClientConfig) { c.Timeouts.Idle = -time.Second }, "idle timeout"},
		{"bad log level", func(c *ClientConfig) { c.Log.Level = "trace" }, "unknown log level"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := validClient(t)
			tc.mutate(config)
			err := config.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			if !strings.Contains(err.Error(), tc.message) {
				t.Errorf("Validate() = %v, want it to mention %q", err, tc.message)
			}
		})
	}
}

func TestServerConfigAllowsNonLoopbackListener(t *testing.T) {
	config := &ServerConfig{
		Listen:       "0.0.0.0:8686",
		IdentityFile: "/var/lib/dproxy/identity.pem",
		TokenFile:    "/run/secrets/dproxy-token",
		DoHURL:       mustURL(t, DefaultDoHURL),
		DoHBootstrap: DefaultDoHBootstrap(mustURL(t, DefaultDoHURL)),
		Allowlist:    DefaultAllowlist(),
		Timeouts:     DefaultTimeouts(),
		Limits:       DefaultLimits(),
		Log:          DefaultLogOptions(),
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if config.Mode() != ModeServer {
		t.Errorf("Mode() = %v", config.Mode())
	}
	config.IdentityFile = ""
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "identity file") {
		t.Fatalf("Validate() without an identity file = %v", err)
	}
	config.IdentityFile = "/var/lib/dproxy/identity.pem"
	config.Limits.MaxSessions = 0
	if err := config.Validate(); err == nil {
		t.Fatal("Validate() accepted an unbounded session limit")
	}
	config.Limits = DefaultLimits()
	config.Limits.MaxControlMessageBytes = 16
	if err := config.Validate(); err == nil {
		t.Fatal("Validate() accepted a control-message limit below the floor")
	}
}

func TestTimeoutsValidate(t *testing.T) {
	timeouts := DefaultTimeouts()
	if err := timeouts.Validate(); err != nil {
		t.Fatalf("DefaultTimeouts is invalid: %v", err)
	}
	timeouts.MaxLifetime = time.Second
	timeouts.Idle = time.Minute
	if err := timeouts.Validate(); err == nil {
		t.Fatal("Validate() accepted a lifetime shorter than the idle timeout")
	}
	timeouts = DefaultTimeouts()
	timeouts.Shutdown = 0
	if err := timeouts.Validate(); err == nil {
		t.Fatal("Validate() accepted a zero shutdown timeout")
	}
}

func TestECHModeSecure(t *testing.T) {
	if !ECHRequired.Secure() {
		t.Error("ECHRequired.Secure() = false")
	}
	if ECHInsecureDisabled.Secure() {
		t.Error("ECHInsecureDisabled.Secure() = true")
	}
	if _, err := ParseECHMode("off"); err == nil {
		t.Error(`ParseECHMode("off") = nil error; the escape hatch must be spelled conspicuously`)
	}
}

// TestCheckersShareOneAllowlist: both roles build the destination policy from
// the same allowlist, through the same type.
func TestCheckersShareOneAllowlist(t *testing.T) {
	client := validClient(t)
	server := &ServerConfig{Allowlist: client.Allowlist}

	local := client.Checker()
	remote := server.Checker(nil)

	if local.CanResolve() {
		t.Error("the local checker has a resolver; the local side never resolves a destination")
	}
	if got, want := local.Allowlist().String(), remote.Allowlist().String(); got != want {
		t.Fatalf("local allowlist %q, remote allowlist %q", got, want)
	}
	for _, authority := range []string{
		"api.openai.com:443", "cdn.openai.com:443", "example.com:443",
		"api.openai.com:80", "203.0.113.10:443",
	} {
		_, localDecision := local.CheckAuthority(authority)
		_, remoteDecision := remote.CheckAuthority(authority)
		if localDecision.Allowed() != remoteDecision.Allowed() ||
			localDecision.Reason() != remoteDecision.Reason() {
			t.Errorf("%s: local = %s, remote = %s", authority, localDecision, remoteDecision)
		}
	}
}

// TestCheckerOfAnUnconfiguredServerPermitsNothing keeps the fail-closed
// default at the configuration seam.
func TestCheckerOfAnUnconfiguredServerPermitsNothing(t *testing.T) {
	server := &ServerConfig{Allowlist: policyEmpty()}
	if _, decision := server.Checker(nil).CheckAuthority("api.openai.com:443"); decision.Allowed() {
		t.Fatal("a server with an empty allowlist permitted a destination")
	}
}
