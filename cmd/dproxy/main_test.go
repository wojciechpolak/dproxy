// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "dproxy-test-config-")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("XDG_CONFIG_HOME", dir); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type capture struct {
	stdout strings.Builder
	stderr strings.Builder
}

func invoke(args ...string) (exitCode, *capture) {
	out := &capture{}
	return run(args, &out.stdout, &out.stderr), out
}

func TestNoArgumentsIsAUsageError(t *testing.T) {
	code, out := invoke()
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(out.stderr.String(), "Usage:") {
		t.Errorf("stderr = %q", out.stderr.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	code, out := invoke("proxy")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(out.stderr.String(), `unknown command "proxy"`) {
		t.Errorf("stderr = %q", out.stderr.String())
	}
}

func TestHelpGoesToStdout(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		code, out := invoke(arg)
		if code != exitOK {
			t.Errorf("%s: exit code = %d, want %d", arg, code, exitOK)
		}
		for _, command := range []string{"client", "server", "test", "version"} {
			if !strings.Contains(out.stdout.String(), command) {
				t.Errorf("%s: help does not list %q", arg, command)
			}
		}
		help := out.stdout.String()
		if !strings.HasPrefix(help, "dproxy is a discreet proxy\n\n") {
			t.Errorf("%s: help heading = %q", arg, strings.SplitN(help, "\n", 2)[0])
		}
		if strings.Contains(help, "daemon suffix") || strings.Contains(help, "—") {
			t.Errorf("%s: help repeats or overstyles the name: %q", arg, help)
		}
	}
}

func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "-V", "--version"} {
		code, out := invoke(arg)
		if code != exitOK {
			t.Errorf("%s: exit code = %d, want %d", arg, code, exitOK)
		}
		line := strings.TrimSpace(out.stdout.String())
		if !strings.HasPrefix(line, "dproxy ") {
			t.Errorf("%s: version line = %q", arg, line)
		}
		if !strings.Contains(line, "go1.") {
			t.Errorf("%s: version line omits the toolchain: %q", arg, line)
		}
	}
}

func TestConfiguredReleaseVersionWins(t *testing.T) {
	previous := version
	version = "v9.8.7-test"
	t.Cleanup(func() { version = previous })
	if got := resolveVersion(); got != version {
		t.Fatalf("resolveVersion = %q, want %q", got, version)
	}
	if line := versionLine(); !strings.Contains(line, version) {
		t.Fatalf("versionLine = %q", line)
	}
}

func TestSourceVersionMatchesVersionFile(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	want := "v" + strings.TrimSpace(string(contents))
	if sourceVersion != want {
		t.Fatalf("sourceVersion = %q, want %q", sourceVersion, want)
	}
	if got := resolveVersion(); got != sourceVersion {
		t.Fatalf("resolveVersion = %q, want %q", got, sourceVersion)
	}
}

func TestClientRejectsIncompleteConfiguration(t *testing.T) {
	code, out := invoke("client")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(out.stderr.String(), "relay URL is required") {
		t.Errorf("stderr = %q", out.stderr.String())
	}
}

func TestClientRejectsANonLoopbackListener(t *testing.T) {
	code, out := invoke("client",
		"--listen", "0.0.0.0:18080",
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", "sha256:"+strings.Repeat("ab", 32),
		"--token-file", "/run/secrets/dproxy-token",
	)
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(out.stderr.String(), "loopback") {
		t.Errorf("stderr = %q", out.stderr.String())
	}
}

func TestClientStartsAndStopsOnContextCancellation(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	token := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free address: %v", err)
	}
	address := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stderr strings.Builder
	code := runClientContext(ctx, []string{
		"--listen", address,
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", "sha256:" + strings.Repeat("ab", 32),
		"--token-file", tokenPath,
	}, &stderr)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "client configuration loaded") {
		t.Errorf("startup log missing: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "dproxy.example.com") || strings.Contains(stderr.String(), token) {
		t.Errorf("startup log leaked a protected value: %q", stderr.String())
	}
}

func TestClientReportsStartupAndBindFailures(t *testing.T) {
	base := []string{
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", "sha256:" + strings.Repeat("ab", 32),
	}
	var stderr strings.Builder
	code := runClientContext(t.Context(), append(base, "--token-file", filepath.Join(t.TempDir(), "missing")), &stderr)
	if code != exitFailure || !strings.Contains(stderr.String(), "token file") {
		t.Fatalf("missing token = code %d, stderr %q", code, stderr.String())
	}

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	stderr.Reset()
	args := append(base, "--token-file", tokenPath, "--listen", occupied.Addr().String())
	if code := runClientContext(t.Context(), args, &stderr); code != exitFailure || !strings.Contains(stderr.String(), "listen") {
		t.Fatalf("occupied listener = code %d, stderr %q", code, stderr.String())
	}
}

func TestServerRequiresATokenFile(t *testing.T) {
	code, out := invoke("server")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(out.stderr.String(), "token file is required") {
		t.Errorf("stderr = %q", out.stderr.String())
	}
}

func TestServerStartsAndStopsOnContextCancellation(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	token := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	identityPath := filepath.Join(t.TempDir(), "identity.pem")
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free address: %v", err)
	}
	address := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stderr strings.Builder
	code := runServerContext(ctx, []string{
		"--listen", address,
		"--token-file", tokenPath,
		"--identity-file", identityPath,
	}, &stderr)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "identity_pin=\"sha256:") {
		t.Errorf("startup log omitted identity pin: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), token) {
		t.Errorf("startup log leaked token: %s", stderr.String())
	}
}

func TestServerReportsStartupAndBindFailures(t *testing.T) {
	var stderr strings.Builder
	missing := filepath.Join(t.TempDir(), "missing-token")
	code := runServerContext(t.Context(), []string{"--token-file", missing}, &stderr)
	if code != exitFailure || !strings.Contains(stderr.String(), "token file") {
		t.Fatalf("missing token = code %d, stderr %q", code, stderr.String())
	}

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	stderr.Reset()
	args := []string{
		"--listen", occupied.Addr().String(), "--token-file", tokenPath,
		"--identity-file", filepath.Join(t.TempDir(), "identity.pem"),
	}
	if code := runServerContext(t.Context(), args, &stderr); code != exitFailure || !strings.Contains(stderr.String(), "listen") {
		t.Fatalf("occupied listener = code %d, stderr %q", code, stderr.String())
	}
}

func TestTestCommandRejectsIncompleteConfiguration(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := runTest(nil, &stdout, &stderr); code != exitUsage {
		t.Fatalf("runTest = %d, stderr %q", code, stderr.String())
	}
}

// The diagnostics are driven against a resolver on loopback that nothing is
// serving, so the test exercises the report and the fail-closed path without
// touching a network.
func testCommandArgs(extra ...string) []string {
	return append([]string{
		"test",
		"--server", "wss://dproxy.example.com/v1/tunnel",
		"--server-pin", "sha256:" + strings.Repeat("ab", 32),
		"--token-file", "/run/secrets/dproxy-token",
		"--doh-url", "https://127.0.0.1/dns-query",
		"--dial-timeout", "1s",
		"--control-timeout", "1s",
	}, extra...)
}

func TestTestCommandListsItsChecks(t *testing.T) {
	code, out := invoke(testCommandArgs()...)
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
	report := out.stdout.String()
	for _, check := range []string{"DoH", "HTTPS RR", "TLS", "ECH", "outer SNI", "certificate", "websocket", "server pin", "remote relay"} {
		if !strings.Contains(report, check) {
			t.Errorf("report omits %q:\n%s", check, report)
		}
	}
	if strings.Contains(report, "dproxy.example.com") {
		t.Errorf("report leaked the relay hostname without --log-targets:\n%s", report)
	}
}

// A resolver that cannot be reached ends the run: nothing after it is reported
// as having passed, and the command exits non-zero.
func TestTestCommandFailsClosed(t *testing.T) {
	code, out := invoke(testCommandArgs()...)
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
	report := out.stdout.String()
	if !strings.Contains(report, "FAILED") {
		t.Errorf("report does not name a failure:\n%s", report)
	}
	for _, line := range strings.Split(report, "\n") {
		if strings.HasPrefix(line, "TLS ") || strings.HasPrefix(line, "websocket ") {
			if !strings.Contains(line, "not checked") {
				t.Errorf("a check ran after the transport failed: %q", line)
			}
		}
	}
}

func TestTestCommandShowsTheRelayWhenOptedIn(t *testing.T) {
	code, out := invoke(testCommandArgs("--log-targets")...)
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(out.stdout.String(), "dproxy.example.com") {
		t.Errorf("opt-in report withheld the relay hostname:\n%s", out.stdout.String())
	}
}

func TestUnexpectedPositionalArgument(t *testing.T) {
	code, out := invoke("client", "start")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(out.stderr.String(), "unexpected argument") {
		t.Errorf("stderr = %q", out.stderr.String())
	}
}

func TestUnknownFlagIsAUsageError(t *testing.T) {
	code, _ := invoke("client", "--not-a-flag")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestCommandHelpExitsZero(t *testing.T) {
	for _, command := range []string{"client", "server", "test"} {
		code, _ := invoke(command, "--help")
		if code != exitOK {
			t.Errorf("%s --help: exit code = %d, want %d", command, code, exitOK)
		}
	}
}

func TestConfigFileDrivesTheClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.toml")
	content := `
server     = "wss://dproxy.example.com/v1/tunnel"
server_pin = "sha256:` + strings.Repeat("ab", 32) + `"
token_file = "/run/secrets/dproxy-token"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	code, out := invoke("client", "--config", path)
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d; stderr: %s", code, exitFailure, out.stderr.String())
	}
}
