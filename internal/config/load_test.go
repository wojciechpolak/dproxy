// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPin = "sha256:LcXsSs3Y9wKDL2wq6+YFTNQnP0M5N1F8k2p6iH1Dg9E="

func loadClient(t *testing.T, args ...string) (*ClientConfig, error) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(&strings.Builder{})
	options := RegisterClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse(%v) = %v", args, err)
	}
	return options.Load()
}

func loadServer(t *testing.T, args ...string) (*ServerConfig, error) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(&strings.Builder{})
	options := RegisterServerFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse(%v) = %v", args, err)
	}
	return options.Load()
}

func TestLoadClientDefaults(t *testing.T) {
	config, err := loadClient(t,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/run/secrets/dproxy-token",
	)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if config.Listen != DefaultClientListen {
		t.Errorf("Listen = %q, want %q", config.Listen, DefaultClientListen)
	}
	if config.ECH != ECHRequired {
		t.Errorf("ECH = %q, want %q", config.ECH, ECHRequired)
	}
	if config.DoHURL.String() != DefaultDoHURL {
		t.Errorf("DoHURL = %q", config.DoHURL)
	}
	if config.Timeouts != DefaultTimeouts() {
		t.Errorf("Timeouts = %+v", config.Timeouts)
	}
	if config.Log.IncludeTargets {
		t.Error("Log.IncludeTargets defaults to true; hostnames must be an opt-in")
	}
	if !config.Allowlist.AllowsAll() {
		t.Errorf("Allowlist = %s, want all destinations", config.Allowlist)
	}
}

func TestLoadClientRequiresServerAndPin(t *testing.T) {
	if _, err := loadClient(t, "--token-file", "/tmp/token"); err == nil {
		t.Fatal("Load() accepted a client with no relay URL")
	}
	_, err := loadClient(t, "--server", "wss://dproxy.example.com/v1/tunnel", "--token-file", "/tmp/token")
	if err == nil || !strings.Contains(err.Error(), "pin is required") {
		t.Fatalf("Load() = %v, want a missing-pin error", err)
	}
}

func TestLoadClientRejectsBadPin(t *testing.T) {
	_, err := loadClient(t,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", "deadbeef",
		"--token-file", "/tmp/token",
	)
	if err == nil || !strings.Contains(err.Error(), "algorithm prefix") {
		t.Fatalf("Load() = %v, want an unprefixed-pin error", err)
	}
}

func TestLoadClientECHOptOutIsExplicit(t *testing.T) {
	config, err := loadClient(t,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/tmp/token",
		"--insecure-disable-ech",
	)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if config.ECH.Secure() {
		t.Error("--insecure-disable-ech left ECH required")
	}
}

func TestLoadClientFlagsOverrideFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.toml")
	write(t, configPath, `
# a comment, which is the whole reason this file is TOML
listen     = "127.0.0.1:9999"
server     = "wss://from-file.example.com/v1/tunnel"
server_pin = "`+testPin+`"   # rotated 2026-08-19
token_file = "/run/secrets/dproxy-token"
allowlist  = ["api.openai.com", "*.anthropic.com"]

[timeouts]
dial = "3s"
idle = "0s"

[log]
level           = "debug"
format          = "json"
include_targets = true
`)

	config, err := loadClient(t, "--config", configPath)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if config.Listen != "127.0.0.1:9999" {
		t.Errorf("Listen = %q", config.Listen)
	}
	if config.RelayURL.Host != "from-file.example.com" {
		t.Errorf("RelayURL = %q", config.RelayURL)
	}
	if config.Timeouts.Dial != 3*time.Second || config.Timeouts.Idle != 0 {
		t.Errorf("Timeouts = %+v", config.Timeouts)
	}
	if config.Log.Level != LogLevelDebug || config.Log.Format != LogFormatJSON || !config.Log.IncludeTargets {
		t.Errorf("Log = %+v", config.Log)
	}
	if got, want := config.Allowlist.String(), "api.openai.com *.anthropic.com"; got != want {
		t.Errorf("Allowlist = %q, want %q", got, want)
	}

	config, err = loadClient(t, "--config", configPath, "--listen", "127.0.0.1:18081", "--dial-timeout", "7s")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if config.Listen != "127.0.0.1:18081" {
		t.Errorf("flag did not override the file: Listen = %q", config.Listen)
	}
	if config.Timeouts.Dial != 7*time.Second {
		t.Errorf("flag did not override the file: Dial = %s", config.Timeouts.Dial)
	}
	if config.Timeouts.Idle != 0 {
		t.Errorf("unset flag overrode the file: Idle = %s", config.Timeouts.Idle)
	}
}

func TestLoadClientRejectsUnknownConfigKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "client.toml")
	write(t, configPath, "listen = \"127.0.0.1:18080\"\nech_mode = \"off\"\n")
	_, err := loadClient(t, "--config", configPath)
	if err == nil || !strings.Contains(err.Error(), "ech_mode") {
		t.Fatalf("Load() = %v, want an unknown-field error naming ech_mode", err)
	}
}

func TestLoadAllowlistFromFile(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "allow")
	write(t, listPath, "# providers\napi.openai.com\n*.anthropic.com\n")
	config, err := loadClient(t,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/tmp/token",
		"--allowlist-file", listPath,
	)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if got, want := config.Allowlist.String(), "api.openai.com *.anthropic.com"; got != want {
		t.Errorf("Allowlist = %q, want %q", got, want)
	}
}

func TestLoadAllowFlagReplacesDefault(t *testing.T) {
	config, err := loadClient(t,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/tmp/token",
		"--allow", "api.openai.com",
		"--allow", "*.anthropic.com",
	)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if got, want := config.Allowlist.String(), "api.openai.com *.anthropic.com"; got != want {
		t.Errorf("Allowlist = %q, want %q (an allowlist replaces the default, never merges)", got, want)
	}
}

func TestLoadServerDefaults(t *testing.T) {
	config, err := loadServer(t, "--token-file", "/run/secrets/dproxy-token")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if config.Listen != DefaultServerListen {
		t.Errorf("Listen = %q", config.Listen)
	}
	if config.Limits != DefaultLimits() {
		t.Errorf("Limits = %+v", config.Limits)
	}
	if config.IdentityFile == "" {
		t.Error("IdentityFile has no persistent default")
	}
	if !config.Allowlist.AllowsAll() {
		t.Errorf("Allowlist = %s, want all destinations", config.Allowlist)
	}
	if _, err := loadServer(t); err == nil {
		t.Fatal("Load() accepted a server with no token file")
	}
}

func TestLoadServerLimitsFromFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "server.toml")
	write(t, configPath, `
listen     = "127.0.0.1:8686"
token_file = "/run/secrets/dproxy-token"
identity_file = "~/dproxy-test-identity.pem"

[limits]
max_sessions              = 8
max_control_message_bytes = 512
`)
	config, err := loadServer(t, "--config", configPath)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if config.Limits.MaxSessions != 8 || config.Limits.MaxControlMessageBytes != 512 {
		t.Errorf("Limits = %+v", config.Limits)
	}
	if !strings.HasSuffix(config.IdentityFile, "dproxy-test-identity.pem") || strings.HasPrefix(config.IdentityFile, "~") {
		t.Errorf("IdentityFile = %q", config.IdentityFile)
	}
	config, err = loadServer(t, "--config", configPath, "--max-sessions", "3")
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if config.Limits.MaxSessions != 3 {
		t.Errorf("flag did not override the file: MaxSessions = %d", config.Limits.MaxSessions)
	}
}

func TestExpandPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	got, err := expandPath("~/.config/dproxy/token")
	if err != nil {
		t.Fatalf("expandPath = %v", err)
	}
	if want := filepath.Join(home, ".config", "dproxy", "token"); got != want {
		t.Errorf("expandPath = %q, want %q", got, want)
	}
	if _, err := expandPath("~other/token"); err == nil {
		t.Error("expandPath accepted ~user syntax")
	}
	if got, err := expandPath("/absolute/path"); err != nil || got != "/absolute/path" {
		t.Errorf("expandPath = %q, %v", got, err)
	}
}

func TestShippedAllowlistIsAnOptionalRestrictionExample(t *testing.T) {
	handle, err := os.Open(filepath.Join("..", "..", "configs", "allowlist.example"))
	if err != nil {
		t.Fatalf("open shipped allowlist: %v", err)
	}
	defer func() { _ = handle.Close() }()
	shipped, err := readAllowlistForTest(handle)
	if err != nil {
		t.Fatalf("parse shipped allowlist: %v", err)
	}
	if shipped.IsEmpty() || shipped.AllowsAll() {
		t.Errorf("shipped example = %s, want a non-empty restriction", shipped)
	}
	if !DefaultAllowlist().AllowsAll() {
		t.Errorf("default allowlist = %s, want all destinations", DefaultAllowlist())
	}
}

func TestLoadDiscoversRoleConfigFromXDGConfigHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	configDir := filepath.Join(dir, "dproxy")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(configDir, "client.toml"), `
server = "wss://client-file.example.com/v1/tunnel"
server_pin = "`+testPin+`"
token_file = "/run/secrets/client-token"
`)
	write(t, filepath.Join(configDir, "server.toml"), `
token_file = "/run/secrets/server-token"

[limits]
max_sessions = 7
`)

	clientFlags := flag.NewFlagSet("client", flag.ContinueOnError)
	clientFlags.SetOutput(&strings.Builder{})
	clientOptions := RegisterClientFlags(clientFlags)
	if err := clientFlags.Parse(nil); err != nil {
		t.Fatal(err)
	}
	client, err := clientOptions.Load()
	if err != nil {
		t.Fatalf("client Load() = %v", err)
	}
	if client.RelayURL.Hostname() != "client-file.example.com" {
		t.Errorf("client relay = %s", client.RelayURL)
	}

	serverFlags := flag.NewFlagSet("server", flag.ContinueOnError)
	serverFlags.SetOutput(&strings.Builder{})
	serverOptions := RegisterServerFlags(serverFlags)
	if err := serverFlags.Parse(nil); err != nil {
		t.Fatal(err)
	}
	server, err := serverOptions.Load()
	if err != nil {
		t.Fatalf("server Load() = %v", err)
	}
	if server.Limits.MaxSessions != 7 || server.TokenFile != "/run/secrets/server-token" {
		t.Errorf("server config = %+v", server)
	}
}

func TestUserConfigDirFallsBackToDotConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	dir, err := userConfigDir()
	if err != nil {
		t.Fatalf("userConfigDir() = %v", err)
	}
	if want := filepath.Join(home, ".config"); dir != want {
		t.Errorf("userConfigDir() = %q, want %q", dir, want)
	}
}

func TestLoadExplicitMissingConfigIsAnError(t *testing.T) {
	_, err := loadClient(t, "--config", filepath.Join(t.TempDir(), "missing.toml"))
	if err == nil || !strings.Contains(err.Error(), "config file") {
		t.Fatalf("Load() = %v, want a missing config error", err)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestShippedExamplesMatchTheSchema keeps documented and accepted configuration
// from drifting apart.
func TestShippedExamplesMatchTheSchema(t *testing.T) {
	cases := []struct {
		file   string
		schema []string
	}{
		{"client.example.toml", clientKeys},
		{"server.example.toml", serverKeys},
		{"server.container.toml", serverKeys},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join("..", "..", "configs", tc.file)
			if _, err := readConfigFile(path, tc.schema); err != nil {
				t.Fatalf("readConfigFile(%s) = %v", tc.file, err)
			}
		})
	}
}

// The shipped resolver ships with its addresses, because the one name DoH
// cannot resolve is its own, and asking the operating system for it would emit
// the plaintext query the whole design avoids.
func TestLoadClientUsesTheBuiltInBootstrap(t *testing.T) {
	config, err := loadClient(t,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/run/secrets/dproxy-token",
	)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(config.DoHBootstrap) == 0 {
		t.Fatal("the default DoH endpoint has no bootstrap addresses")
	}
	if config.DoHBootstrap[0].String() != "1.1.1.1" {
		t.Errorf("DoHBootstrap = %v", config.DoHBootstrap)
	}
}

func TestLoadClientRequiresBootstrapForAnUnknownResolver(t *testing.T) {
	_, err := loadClient(t,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/run/secrets/dproxy-token",
		"--doh-url", "https://dns.example.org/dns-query",
	)
	if err == nil {
		t.Fatal("Load() accepted a resolver it could only reach through the OS resolver")
	}
	if !strings.Contains(err.Error(), "operating system resolver") {
		t.Errorf("Load() = %v", err)
	}
}

func TestLoadClientAcceptsExplicitBootstrapAddresses(t *testing.T) {
	config, err := loadClient(t,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/run/secrets/dproxy-token",
		"--doh-url", "https://dns.example.org/dns-query",
		"--doh-bootstrap", "9.9.9.9",
		"--doh-bootstrap", "2620:fe::fe",
	)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(config.DoHBootstrap) != 2 {
		t.Fatalf("DoHBootstrap = %v", config.DoHBootstrap)
	}
}

func TestLoadClientRejectsUnusableBootstrapAddresses(t *testing.T) {
	for _, address := range []string{"not-an-address", "dns.example.org", "0.0.0.0", "224.0.0.1"} {
		_, err := loadClient(t,
			"--server", "wss://dproxy.example.com/v1/tunnel",
			"--server-pin", testPin,
			"--token-file", "/run/secrets/dproxy-token",
			"--doh-bootstrap", address,
		)
		if err == nil {
			t.Errorf("Load() accepted the bootstrap address %q", address)
		}
	}
}

// A resolver named by address needs no bootstrap: there is nothing to resolve.
func TestLoadClientAcceptsAnIPLiteralResolver(t *testing.T) {
	config, err := loadClient(t,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/run/secrets/dproxy-token",
		"--doh-url", "https://1.1.1.1/dns-query",
	)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(config.DoHBootstrap) != 0 {
		t.Errorf("DoHBootstrap = %v, want none", config.DoHBootstrap)
	}
}

func TestLoadServerBootstrapFromAConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.toml")
	contents := `token_file = "/run/secrets/dproxy-token"
doh_url = "https://dns.example.org/dns-query"
doh_bootstrap = [
    "9.9.9.9",       # Quad9
    "2620:fe::fe",
]
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	config, err := loadServer(t, "--config", path)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(config.DoHBootstrap) != 2 || config.DoHBootstrap[0].String() != "9.9.9.9" {
		t.Errorf("DoHBootstrap = %v", config.DoHBootstrap)
	}
}

func TestLoadClientAppliesEveryCommonFlag(t *testing.T) {
	config, err := loadClient(t,
		"--listen", "127.0.0.1:18081",
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/run/secrets/client-token",
		"--doh-url", "https://dns.example.org/dns-query",
		"--doh-bootstrap", "9.9.9.9",
		"--allow", "api.openai.com",
		"--dial-timeout", "1s",
		"--tls-handshake-timeout", "2s",
		"--control-timeout", "3s",
		"--idle-timeout", "4s",
		"--max-lifetime", "5s",
		"--shutdown-timeout", "6s",
		"--log-level", "debug",
		"--log-format", "json",
		"--log-targets",
	)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if config.Listen != "127.0.0.1:18081" || config.TokenFile != "/run/secrets/client-token" {
		t.Errorf("client paths = %q, %q", config.Listen, config.TokenFile)
	}
	if config.Timeouts != (Timeouts{
		Dial: time.Second, TLSHandshake: 2 * time.Second, Control: 3 * time.Second,
		Idle: 4 * time.Second, MaxLifetime: 5 * time.Second, Shutdown: 6 * time.Second,
	}) {
		t.Errorf("timeouts = %+v", config.Timeouts)
	}
	if config.Log != (LogOptions{Level: LogLevelDebug, Format: LogFormatJSON, IncludeTargets: true}) {
		t.Errorf("log options = %+v", config.Log)
	}
}

func TestLoadServerAppliesEveryRoleFlag(t *testing.T) {
	config, err := loadServer(t,
		"--listen", "127.0.0.1:8788",
		"--identity-file", "/var/lib/dproxy/test-identity.pem",
		"--token-file", "/run/secrets/server-token",
		"--doh-url", "https://dns.example.org/dns-query",
		"--doh-bootstrap", "9.9.9.9",
		"--allow", "api.openai.com",
		"--max-sessions", "7",
		"--max-control-message", "512",
		"--control-timeout", "3s",
		"--log-level", "warn",
	)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if config.Listen != "127.0.0.1:8788" || config.IdentityFile != "/var/lib/dproxy/test-identity.pem" {
		t.Errorf("server paths = %q, %q", config.Listen, config.IdentityFile)
	}
	if config.Limits != (Limits{MaxSessions: 7, MaxControlMessageBytes: 512}) {
		t.Errorf("limits = %+v", config.Limits)
	}
	if config.Timeouts.Control != 3*time.Second || config.Log.Level != LogLevelWarn {
		t.Errorf("server common options = %+v, %+v", config.Timeouts, config.Log)
	}
}

func TestLoadRejectsInvalidCommonFlags(t *testing.T) {
	base := []string{
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", testPin,
		"--token-file", "/run/secrets/client-token",
	}
	for _, args := range [][]string{
		{"--log-level", "trace"},
		{"--log-format", "xml"},
	} {
		if _, err := loadClient(t, append(base, args...)...); err == nil {
			t.Fatalf("Load accepted %v", args)
		}
	}
}
