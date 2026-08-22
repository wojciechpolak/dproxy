// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"bytes"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigurationValueAccessorsReturnCopies(t *testing.T) {
	if ModeClient.String() != "client" || LogLevelWarn.String() != "warn" || LogFormatJSON.String() != "json" {
		t.Fatal("configuration enum string changed")
	}
	pin := PinFromSPKI([]byte("server key"))
	digest := pin.Digest()
	digest[0] ^= 0xff
	if pin.Matches(digest) {
		t.Fatal("Pin.Digest returned mutable pin storage")
	}
	token, err := NewToken(bytes.Repeat([]byte{'s'}, MinTokenBytes))
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	raw := token.Bytes()
	raw[0] = 'x'
	if token.EqualBytes(raw) {
		t.Fatal("Token.Bytes returned mutable token storage")
	}
	if token.Equal(Token{}) || (Token{}).Equal(token) {
		t.Fatal("an unloaded token compared equal")
	}
	if _, err := NewTokenSet(); err == nil {
		t.Fatal("NewTokenSet accepted no tokens")
	}
	if _, err := NewTokenSet(Token{}); err == nil {
		t.Fatal("NewTokenSet accepted an unloaded token")
	}
	if (TokenSet{}).Contains(token) {
		t.Fatal("empty TokenSet accepted a token")
	}
}

func TestRemainingConfigurationValidationBranches(t *testing.T) {
	timeouts := DefaultTimeouts()
	timeouts.MaxLifetime = -time.Second
	if err := timeouts.Validate(); err == nil {
		t.Fatal("negative maximum lifetime was accepted")
	}
	limits := DefaultLimits()
	limits.MaxControlMessageBytes = 1<<20 + 1
	if err := limits.Validate(); err == nil {
		t.Fatal("oversized control-message limit was accepted")
	}

	server := &ServerConfig{
		Listen: "127.0.0.1:8686", IdentityFile: "/identity", TokenFile: "/token",
		DoHURL: mustURL(t, DefaultDoHURL), DoHBootstrap: DefaultDoHBootstrap(mustURL(t, DefaultDoHURL)),
		Allowlist: DefaultAllowlist(), Timeouts: DefaultTimeouts(), Limits: DefaultLimits(), Log: DefaultLogOptions(),
	}
	mutations := []func(*ServerConfig){
		func(c *ServerConfig) { c.TokenFile = "" },
		func(c *ServerConfig) {
			c.DoHBootstrap = nil
			c.DoHURL = mustURL(t, "https://dns.example.org/dns-query")
		},
		func(c *ServerConfig) { c.Allowlist = policyEmpty() },
		func(c *ServerConfig) { c.Timeouts.Control = 0 },
		func(c *ServerConfig) { c.Log.Format = "xml" },
	}
	for index, mutate := range mutations {
		candidate := *server
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Errorf("server mutation %d was accepted", index)
		}
	}
}

func TestAddressAndURLValidationEdgeCases(t *testing.T) {
	for _, address := range []string{"127.0.0.1:", "127.0.0.1:http", "127.0.0.1:0", "127.0.0.1:65536"} {
		if err := validateListenAddress(address); err == nil {
			t.Errorf("validateListenAddress(%q) succeeded", address)
		}
	}
	if err := validateListenAddress(":8686"); err != nil {
		t.Errorf("wildcard listener: %v", err)
	}
	for _, raw := range []string{
		"wss://relay.example/v1/tunnel#fragment",
		"wss:///v1/tunnel",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse: %v", err)
		}
		if err := validateRelayURL(parsed); err == nil {
			t.Errorf("validateRelayURL(%q) succeeded", raw)
		}
	}
	relative := &url.URL{Scheme: "wss", Host: "relay.example", Path: "relative"}
	if err := validateRelayURL(relative); err == nil {
		t.Fatal("relative relay path was accepted")
	}
	for _, raw := range []string{
		"https://user@dns.example/dns-query",
		"https://dns.example/dns-query#fragment",
		"https:///dns-query",
		"https://dns.example/a%2Fb",
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse: %v", err)
		}
		if err := validateDoHURL(parsed); err == nil {
			t.Errorf("validateDoHURL(%q) succeeded", raw)
		}
	}
	if DefaultDoHBootstrap(nil) != nil || DefaultDoHBootstrap(mustURL(t, "https://dns.example/dns-query")) != nil {
		t.Fatal("unknown DoH endpoint received built-in bootstrap addresses")
	}
	for _, address := range []netip.Addr{netip.Addr{}, netip.IPv4Unspecified(), netip.MustParseAddr("224.0.0.1")} {
		if err := validateBootstrapAddress(address); err == nil {
			t.Errorf("bootstrap address %s was accepted", address)
		}
	}
	if err := validateDoHBootstrap(mustURL(t, "https://1.1.1.1/dns-query"), nil); err != nil {
		t.Errorf("IP-literal DoH endpoint needs no bootstrap: %v", err)
	}
	if err := validateDoHBootstrap(nil, nil); err == nil {
		t.Error("missing DoH endpoint was accepted without bootstrap addresses")
	}
	if err := validateDoHBootstrap(mustURL(t, "https://dns.example/dns-query"), []netip.Addr{netip.IPv4Unspecified()}); err == nil {
		t.Error("undialable DoH bootstrap address was accepted")
	}
}

func TestTokenSetFileErrorPaths(t *testing.T) {
	if _, err := (TokenFile("")).ReadSet(); err == nil {
		t.Fatal("empty token path was accepted")
	}
	if _, err := TokenFile(filepath.Join(t.TempDir(), "missing")).ReadSet(); err == nil {
		t.Fatal("missing token file was accepted")
	}
	if _, err := TokenFile(t.TempDir()).ReadSet(); err == nil {
		t.Fatal("token directory was accepted")
	}
	open := writeToken(t, secret, 0o644)
	if _, err := open.ReadSet(); err == nil {
		t.Fatal("open token-file permissions were accepted")
	}
	oversized := filepath.Join(t.TempDir(), "oversized")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, MaxServerTokens*(maxTokenBytes+1)+1), 0o600); err != nil {
		t.Fatalf("write oversized token file: %v", err)
	}
	if _, err := TokenFile(oversized).ReadSet(); err == nil {
		t.Fatal("oversized token file was accepted")
	}
	empty := writeToken(t, "\n\n", 0o600)
	if _, err := empty.ReadSet(); err == nil {
		t.Fatal("empty token set was accepted")
	}
	short := writeToken(t, "\nshort\n", 0o600)
	if _, err := short.ReadSet(); err == nil {
		t.Fatal("short token in set was accepted")
	}
}

func TestExpandPathHandlesHomeItself(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := expandPath("~")
	if err != nil {
		t.Fatalf("expandPath: %v", err)
	}
	if got != home {
		t.Errorf("expandPath(~) = %q, want %q", got, home)
	}
}
