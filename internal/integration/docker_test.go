// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build docker_e2e

package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
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
	directory := os.Getenv("DPROXY_E2E_DIR")
	if directory == "" {
		t.Fatal("DPROXY_E2E_DIR is required")
	}
	remoteAddress := os.Getenv("DPROXY_E2E_REMOTE_ADDR")
	if remoteAddress == "" {
		remoteAddress = "127.0.0.1:18686"
	}
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
	client, err := tunnel.NewClient(tunnel.ClientOptions{
		Config:       clientConfig,
		StreamDialer: plainStreamDialer{address: remoteAddress, endpoint: relayURL},
	})
	if err != nil {
		t.Fatalf("build tunnel client: %v", err)
	}
	local, err := localproxy.NewServer(localproxy.ServerOptions{Config: clientConfig, Opener: client})
	if err != nil {
		t.Fatalf("build local proxy: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for local proxy: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- local.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := local.Shutdown(ctx); err != nil {
			t.Errorf("shut down local proxy: %v", err)
		}
		if err := <-served; err != nil {
			t.Errorf("serve local proxy: %v", err)
		}
	})

	raw, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("connect to local proxy: %v", err)
	}
	authority := testDockerOriginHost + ":443"
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(raw)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", response.StatusCode)
	}
	roots, err := readRoots(filepath.Join(directory, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	origin := tls.Client(&dockerBufferedConn{Conn: raw, reader: reader}, &tls.Config{
		RootCAs: roots, ServerName: testDockerOriginHost,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	if err := origin.Handshake(); err != nil {
		t.Fatalf("origin TLS handshake through Dockerized remote: %v", err)
	}
	defer func() { _ = origin.Close() }()
	payload := []byte("dockerized remote relay payload 9f0b5ff6")
	if _, err := origin.Write(payload); err != nil {
		t.Fatalf("write origin payload: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(origin, echo); err != nil {
		t.Fatalf("read origin echo: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
}

const testDockerOriginHost = "origin.e2e.test"

type plainStreamDialer struct {
	address  string
	endpoint *url.URL
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
