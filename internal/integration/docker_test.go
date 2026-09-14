// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build docker_e2e

package integration_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/localproxy"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/relay"
	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

func TestDockerizedRemoteEndToEnd(t *testing.T) {
	scenario(t, "the production remote image relays a stream from a real container")
	topology := newDockerTopology(t)
	origin := topology.openTLS(t)
	payload := []byte("dockerized remote relay payload 9f0b5ff6")
	echo := make([]byte, len(payload))
	if err := benchmarkRoundTrip(origin, payload, echo); err != nil {
		t.Fatalf("relay payload: %v", err)
	}
}

func TestDockerizedRemoteStreamsWithAPinnedClientIdentity(t *testing.T) {
	if !dockerMutualTLS() {
		t.Skip("DPROXY_E2E_CLIENT_PINS=1 runs the container with client_pins")
	}
	scenario(t, "mTLS: the production remote image accepts a pinned client identity")
	topology := newDockerTopology(t)
	origin := topology.openTLS(t)
	payload := []byte("dockerized pinned client payload 4c1de0a7")
	echo := make([]byte, len(payload))
	if err := benchmarkRoundTrip(origin, payload, echo); err != nil {
		t.Fatalf("relay payload: %v", err)
	}
}

func TestDockerizedRemoteRejectsAnUnpinnedClientIdentity(t *testing.T) {
	if !dockerMutualTLS() {
		t.Skip("DPROXY_E2E_CLIENT_PINS=1 runs the container with client_pins")
	}
	scenario(t, "mTLS: the production remote image refuses an identity outside client_pins")
	clientConfig := newDockerClientConfig(t, dockerDirectory(t))
	// A real identity the operator never pinned, rather than no identity at
	// all. This proves the container checks the pin value, not only that a
	// certificate arrived.
	clientConfig.ClientIdentityFile = filepath.Join(t.TempDir(), "unpinned-identity.pem")
	client, err := tunnel.NewClient(tunnel.ClientOptions{
		Config:       clientConfig,
		StreamDialer: newDockerStreamDialer(clientConfig.RelayURL),
	})
	if err != nil {
		t.Fatalf("build tunnel client: %v", err)
	}
	destination, err := policy.NewDestination(testDockerOriginHost, 443)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Open(ctx, destination)
	if err == nil {
		_ = conn.Close()
		t.Fatal("the remote opened a tunnel for an unpinned client identity")
	}
	if !errors.Is(err, tunnel.ErrClientCertificateRejected) {
		t.Fatalf("Open error = %v, want %v", err, tunnel.ErrClientCertificateRejected)
	}
}

const (
	testDockerOriginHost       = "origin.e2e.test"
	dockerBenchmarkPayloadSize = 1 << 20
)

type dockerTopology struct {
	localAt string
	roots   *x509.CertPool
}

// dockerMutualTLS reports whether the container runs with client_pins.
// scripts/docker-e2e.sh sets the same variable for `fixture init`, so the
// container's server.toml and this client always use the same configuration.
func dockerMutualTLS() bool { return os.Getenv("DPROXY_E2E_CLIENT_PINS") == "1" }

// dockerDirectory returns the directory holding the generated credentials.
func dockerDirectory(t testing.TB) string {
	t.Helper()
	directory := os.Getenv("DPROXY_E2E_DIR")
	if directory == "" {
		t.Fatal("DPROXY_E2E_DIR is required")
	}
	return directory
}

// newDockerClientConfig builds the client half of the Dockerized topology.
// When the container requires client pins, the client presents the identity
// the fixture generated and pinned.
func newDockerClientConfig(t testing.TB, directory string) *config.ClientConfig {
	t.Helper()
	pinText, err := os.ReadFile(filepath.Join(directory, "pin"))
	if err != nil {
		t.Fatalf("read remote pin: %v", err)
	}
	pin, err := config.ParsePin(string(pinText))
	if err != nil {
		t.Fatalf("parse remote pin: %v", err)
	}
	allowlist, err := policy.ParseAllowlist([]string{testDockerOriginHost})
	if err != nil {
		t.Fatal(err)
	}
	relayURL, _ := url.Parse("wss://docker-remote.e2e.test" + relay.TunnelPath)
	dohURL, _ := url.Parse("https://resolver.e2e.test/dns-query")
	timeouts := config.DefaultTimeouts()
	timeouts.Dial = 2 * time.Second
	timeouts.TLSHandshake = 2 * time.Second
	timeouts.Control = 2 * time.Second
	timeouts.Idle = 10 * time.Second
	timeouts.Shutdown = 2 * time.Second
	clientConfig := &config.ClientConfig{
		Listen:       "127.0.0.1:1",
		RelayURL:     relayURL,
		ServerPin:    pin,
		TokenFile:    config.TokenFile(filepath.Join(directory, "token")),
		DoHURL:       dohURL,
		DoHBootstrap: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		ECH:          config.ECHInsecureDisabled,
		Allowlist:    allowlist,
		Timeouts:     timeouts,
		Log:          config.DefaultLogOptions(),
	}
	if dockerMutualTLS() {
		clientConfig.ClientIdentityFile = filepath.Join(directory, "client-identity.pem")
	}
	return clientConfig
}

func newDockerTopology(t testing.TB) *dockerTopology {
	t.Helper()
	directory := dockerDirectory(t)
	clientConfig := newDockerClientConfig(t, directory)
	client, err := tunnel.NewClient(tunnel.ClientOptions{
		Config:       clientConfig,
		StreamDialer: newDockerStreamDialer(clientConfig.RelayURL),
	})
	if err != nil {
		t.Fatalf("build tunnel client: %v", err)
	}
	local, err := localproxy.NewServer(localproxy.ServerOptions{Config: clientConfig, Opener: client})
	if err != nil {
		t.Fatalf("build local proxy: %v", err)
	}
	listener := listenDockerLoopback(t)
	served := make(chan error, 1)
	go func() { served <- local.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := local.Shutdown(ctx); err != nil {
			t.Errorf("shut down local proxy: %v", err)
		}
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("serve local proxy: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("local proxy did not stop")
		}
	})
	roots, err := readRoots(filepath.Join(directory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return &dockerTopology{localAt: listener.Addr().String(), roots: roots}
}

func (t *dockerTopology) connect(tb testing.TB) net.Conn {
	tb.Helper()
	raw, err := net.DialTimeout("tcp", t.localAt, time.Second)
	if err != nil {
		tb.Fatalf("connect to local proxy: %v", err)
	}
	authority := testDockerOriginHost + ":443"
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		_ = raw.Close()
		tb.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(raw)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = raw.Close()
		tb.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		_ = raw.Close()
		tb.Fatalf("CONNECT status = %d, want 200", response.StatusCode)
	}
	return &dockerBufferedConn{Conn: raw, reader: reader}
}

func (t *dockerTopology) openTLS(tb testing.TB) *tls.Conn {
	tb.Helper()
	origin := tls.Client(t.connect(tb), &tls.Config{
		RootCAs: t.roots, ServerName: testDockerOriginHost,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := origin.HandshakeContext(ctx); err != nil {
		_ = origin.Close()
		tb.Fatalf("origin TLS handshake through Dockerized remote: %v", err)
	}
	tb.Cleanup(func() { _ = origin.Close() })
	return origin
}

func BenchmarkDockerizedRemoteTunnelSetup(b *testing.B) {
	topology := newDockerTopology(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		conn := topology.connect(b)
		if err := conn.Close(); err != nil {
			b.Fatalf("close tunnel: %v", err)
		}
	}
}

func BenchmarkDockerizedRemoteThroughput(b *testing.B) {
	topology := newDockerTopology(b)
	conn := topology.openTLS(b)
	payload := bytePattern(dockerBenchmarkPayloadSize)
	scratch := make([]byte, len(payload))
	b.SetBytes(int64(2 * len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := benchmarkRoundTrip(conn, payload, scratch); err != nil {
			b.Fatal(err)
		}
	}
}

func listenDockerLoopback(t testing.TB) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for local proxy: %v", err)
	}
	return listener
}

type plainStreamDialer struct {
	address  string
	endpoint *url.URL
}

// newDockerStreamDialer dials the port the compose file publishes for the
// remote container, in place of the public front end.
func newDockerStreamDialer(endpoint *url.URL) plainStreamDialer {
	address := os.Getenv("DPROXY_E2E_REMOTE_ADDR")
	if address == "" {
		address = "127.0.0.1:18686"
	}
	return plainStreamDialer{address: address, endpoint: endpoint}
}

func (d plainStreamDialer) DialStream(ctx context.Context) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	reader, err := (&tunnel.Upgrader{URL: d.endpoint, Timeout: 2 * time.Second}).Upgrade(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tunnel.NewClientWebSocketConn(conn, reader), nil
}

type dockerBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *dockerBufferedConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

func readRoots(path string) (*x509.CertPool, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(encoded) {
		return nil, fmt.Errorf("%s contains no certificates", path)
	}
	return roots, nil
}

var (
	_ tunnel.StreamDialer = plainStreamDialer{}
)
