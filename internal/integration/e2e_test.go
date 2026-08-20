// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build e2e

package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- application WebSocket fixture follows RFC 6455
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/localproxy"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/relay"
	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

const (
	testOriginHost = "origin.e2e.test"
	testRelayHost  = "relay.e2e.test"
)

func TestEndToEndStreams(t *testing.T) {
	t.Run("arbitrary bytes", func(t *testing.T) {
		topology := newTopology(t, topologyOptions{})
		conn, _ := topology.openTLS(t)
		payload := bytePattern(257 << 10)
		writeAndReadEcho(t, conn, payload, 16<<10)
	})

	t.Run("large stream", func(t *testing.T) {
		topology := newTopology(t, topologyOptions{})
		conn, _ := topology.openTLS(t)
		payload := bytePattern(8 << 20)
		writeAndReadEcho(t, conn, payload, 32<<10)
	})

	t.Run("one byte writes", func(t *testing.T) {
		topology := newTopology(t, topologyOptions{})
		conn, _ := topology.openTLS(t)
		payload := bytePattern(8 << 10)
		writeAndReadEcho(t, conn, payload, 1)
	})

	t.Run("simultaneous reads and writes", func(t *testing.T) {
		topology := newTopology(t, topologyOptions{})
		conn, _ := topology.openTLS(t)
		payload := bytePattern(2 << 20)
		writeAndReadEcho(t, conn, payload, 997)
	})

	t.Run("half close", func(t *testing.T) {
		topology := newTopology(t, topologyOptions{})
		conn, _ := topology.openTLS(t)
		payload := bytePattern(192 << 10)
		readResult := readAllAsync(conn)
		writeChunks(t, conn, payload, 733)
		if err := conn.CloseWrite(); err != nil {
			t.Fatalf("half-close application TLS: %v", err)
		}
		result := awaitRead(t, readResult)
		if result.err != nil {
			t.Fatalf("read after half-close: %v", result.err)
		}
		if !bytes.Equal(result.data, payload) {
			t.Fatalf("half-close changed stream: got %d bytes, want %d", len(result.data), len(payload))
		}
	})
}

func TestProviderStyleLongRunningHTTPStream(t *testing.T) {
	chunks := []string{
		"data: first\n\n",
		"data: second\n\n",
		"data: third\n\n",
		"data: fourth\n\n",
		"data: fifth\n\n",
	}
	originResult := make(chan error, 1)
	topology := newTopology(t, topologyOptions{
		remoteIdleTimeout: 120 * time.Millisecond,
		originHandler: func(conn *tls.Conn) {
			request, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				originResult <- err
				return
			}
			_ = request.Body.Close()
			if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"); err != nil {
				originResult <- err
				return
			}
			for _, chunk := range chunks {
				if _, err := fmt.Fprintf(conn, "%x\r\n%s\r\n", len(chunk), chunk); err != nil {
					originResult <- err
					return
				}
				time.Sleep(60 * time.Millisecond)
			}
			_, err = io.WriteString(conn, "0\r\n\r\n")
			originResult <- err
		},
	})

	conn, _ := topology.openTLS(t)
	started := time.Now()
	if _, err := fmt.Fprintf(conn, "GET /v1/responses HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", testOriginHost); err != nil {
		t.Fatalf("write streaming request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read streaming response: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read streaming body: %v", err)
	}
	if got, want := string(body), strings.Join(chunks, ""); got != want {
		t.Fatalf("streaming body = %q, want %q", got, want)
	}
	if elapsed := time.Since(started); elapsed < 4*60*time.Millisecond {
		t.Fatalf("stream completed too quickly to exercise the idle deadline: %s", elapsed)
	}
	if err := <-originResult; err != nil {
		t.Fatalf("streaming origin: %v", err)
	}
}

func TestProviderStyleApplicationWebSocket(t *testing.T) {
	originResult := make(chan error, 1)
	topology := newTopology(t, topologyOptions{originHandler: func(conn *tls.Conn) {
		reader := bufio.NewReader(conn)
		request, err := http.ReadRequest(reader)
		if err != nil {
			originResult <- err
			return
		}
		_ = request.Body.Close()
		key := request.Header.Get("Sec-WebSocket-Key")
		if request.Header.Get("Upgrade") != "websocket" || key == "" {
			originResult <- errors.New("application WebSocket upgrade headers are missing")
			return
		}
		if _, err := fmt.Fprintf(conn,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			applicationWebSocketAccept(key),
		); err != nil {
			originResult <- err
			return
		}
		payload, err := readApplicationWebSocketFrame(reader, true)
		if err == nil {
			err = writeApplicationWebSocketFrame(conn, payload, false)
		}
		originResult <- err
	}})

	conn, _ := topology.openTLS(t)
	key := base64.StdEncoding.EncodeToString([]byte("provider-test-01"))
	if _, err := fmt.Fprintf(conn,
		"GET /v1/realtime HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		testOriginHost, key,
	); err != nil {
		t.Fatalf("write application WebSocket upgrade: %v", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read application WebSocket upgrade: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("application WebSocket status = %d", response.StatusCode)
	}
	payload := []byte(`{"type":"provider.event","delta":"hello"}`)
	if err := writeApplicationWebSocketFrame(conn, payload, true); err != nil {
		t.Fatalf("write application WebSocket frame: %v", err)
	}
	echo, err := readApplicationWebSocketFrame(reader, false)
	if err != nil {
		t.Fatalf("read application WebSocket frame: %v", err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("application WebSocket payload = %q, want %q", echo, payload)
	}
	if err := <-originResult; err != nil {
		t.Fatalf("application WebSocket origin: %v", err)
	}
}

func TestEndToEndDisconnectsAndTimeouts(t *testing.T) {
	t.Run("abrupt client disconnect", func(t *testing.T) {
		originClosed := make(chan struct{})
		topology := newTopology(t, topologyOptions{originHandler: func(conn *tls.Conn) {
			_, _ = io.Copy(io.Discard, conn)
			close(originClosed)
		}})
		conn, raw := topology.openTLS(t)
		if _, err := conn.Write([]byte("before abrupt close")); err != nil {
			t.Fatalf("write before abrupt close: %v", err)
		}
		if err := raw.Close(); err != nil {
			t.Fatalf("abrupt close: %v", err)
		}
		awaitSignal(t, originClosed, "origin did not observe the disconnect")
	})

	t.Run("local cancellation", func(t *testing.T) {
		originClosed := make(chan struct{})
		topology := newTopology(t, topologyOptions{originHandler: func(conn *tls.Conn) {
			_, _ = io.Copy(io.Discard, conn)
			close(originClosed)
		}})
		_, _ = topology.openTLS(t)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if err := topology.local.Shutdown(ctx); err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("forced shutdown error = %v, want deadline exceeded", err)
		}
		awaitSignal(t, originClosed, "origin did not observe cancellation")
	})

	t.Run("remote maximum lifetime", func(t *testing.T) {
		topology := newTopology(t, topologyOptions{remoteMaxLifetime: 150 * time.Millisecond})
		conn, _ := topology.openTLS(t)
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		buffer := make([]byte, 1)
		if _, err := conn.Read(buffer); err == nil {
			t.Fatal("connection remained open after the remote maximum lifetime")
		}
	})

	t.Run("slow reader applies backpressure", func(t *testing.T) {
		payload := bytePattern(12 << 20)
		writeStarted := make(chan struct{})
		writeDone := make(chan struct{})
		topology := newTopology(t, topologyOptions{originHandler: func(conn *tls.Conn) {
			close(writeStarted)
			_, _ = conn.Write(payload)
			_ = conn.CloseWrite()
			close(writeDone)
		}})
		conn, raw := topology.openTLS(t)
		if buffered, ok := raw.(*bufferedConn); ok {
			if tcp, ok := buffered.Conn.(*net.TCPConn); ok {
				// Keep the receive window below the payload without making the
				// drain depend on Linux's delayed-ACK behavior for tiny windows.
				if err := tcp.SetReadBuffer(64 << 10); err != nil {
					t.Fatalf("set client receive buffer: %v", err)
				}
			}
		}
		awaitSignal(t, writeStarted, "origin did not start writing")
		select {
		case <-writeDone:
			t.Fatal("origin drained 12 MiB before the deliberately slow reader resumed")
		case <-time.After(100 * time.Millisecond):
		}
		result := awaitRead(t, readAllAsync(conn))
		if result.err != nil {
			t.Fatalf("read slow stream: %v", result.err)
		}
		if !bytes.Equal(result.data, payload) {
			t.Fatalf("slow-reader stream changed: got %d bytes, want %d", len(result.data), len(payload))
		}
		awaitSignal(t, writeDone, "origin remained blocked after the client drained the stream")
	})
}

func TestEndToEndPolicyRefusalsNeverDialOrigin(t *testing.T) {
	topology := newTopology(t, topologyOptions{resolvedAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	cases := []struct {
		name      string
		authority string
		want      int
	}{
		{name: "host", authority: "not-allowed.e2e.test:443", want: http.StatusForbidden},
		{name: "port", authority: testOriginHost + ":8443", want: http.StatusForbidden},
		{name: "resolved private address", authority: testOriginHost + ":443", want: http.StatusForbidden},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response, conn := topology.connect(t, test.authority)
			_ = conn.Close()
			if response.StatusCode != test.want {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.want)
			}
		})
	}
	if got := topology.dialer.calls.Load(); got != 0 {
		t.Fatalf("target dialer called %d times for refused destinations", got)
	}
	if got := topology.origin.accepted.Load(); got != 0 {
		t.Fatalf("origin accepted %d connections for refused destinations", got)
	}
}

func TestFrontEndVisiblePayloadIsInnerTLSCiphertext(t *testing.T) {
	topology := newTopology(t, topologyOptions{recordWSS: true})
	conn, _ := topology.openTLS(t)
	payload := []byte("application payload marker 8d58640842f4")
	writeAndReadEcho(t, conn, payload, len(payload))
	visible := topology.stream.recorded()
	for _, secret := range [][]byte{
		[]byte(testOriginHost),
		topology.token.Bytes(),
		payload,
	} {
		if bytes.Contains(visible, secret) {
			t.Fatalf("front-end-visible WSS bytes contain plaintext %q", secret)
		}
	}
}

func TestHTTPSProxyCompatibility(t *testing.T) {
	t.Run("curl", func(t *testing.T) {
		requests := make(chan *http.Request, 1)
		topology := newTopology(t, topologyOptions{originHandler: compatibilityHTTPHandler(requests, http.StatusNoContent, nil)})
		caFile := topology.writeOriginCA(t)
		path := requireExecutable(t, "curl")
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, path,
			"--fail", "--silent", "--show-error", "--cacert", caFile,
			"https://"+testOriginHost+"/compatibility/curl",
		)
		command.Env = compatibilityEnvironment(topology.localAt, caFile)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("curl through HTTPS_PROXY: %v\n%s", err, output)
		}
		request := awaitRequest(t, requests)
		if request.Method != http.MethodGet || request.URL.Path != "/compatibility/curl" {
			t.Fatalf("curl request = %s %s", request.Method, request.URL.Path)
		}
	})

	t.Run("git", func(t *testing.T) {
		body := []byte("001e# service=git-upload-pack\n00000000")
		requests := make(chan *http.Request, 1)
		topology := newTopology(t, topologyOptions{originHandler: compatibilityHTTPHandler(requests, http.StatusOK, body)})
		caFile := topology.writeOriginCA(t)
		path := requireExecutable(t, "git")
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, path, "ls-remote", "https://"+testOriginHost+"/repository.git")
		command.Env = append(compatibilityEnvironment(topology.localAt, caFile),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0",
			"GIT_SSL_CAINFO="+caFile,
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git through HTTPS_PROXY: %v\n%s", err, output)
		}
		request := awaitRequest(t, requests)
		if request.Method != http.MethodGet || request.URL.Path != "/repository.git/info/refs" {
			t.Fatalf("git request = %s %s", request.Method, request.URL.Path)
		}
	})
}

// These tests invoke optional provider CLIs. They are deterministic and use
// fake credentials plus a local API endpoint, but the binaries are too large to
// install as product or CI dependencies. `make provider-compat` opts in.
func TestProviderCLICompatibility(t *testing.T) {
	if os.Getenv("DPROXY_PROVIDER_COMPAT") != "1" {
		t.Skip("set DPROXY_PROVIDER_COMPAT=1 or run make provider-compat")
	}
	t.Run("Codex CLI", func(t *testing.T) {
		path := requireExecutable(t, "codex")
		requests := make(chan *http.Request, 1)
		topology := newTopology(t, topologyOptions{originHandler: compatibilityHTTPHandler(requests, http.StatusUnauthorized, []byte(`{"error":{"message":"fixture"}}`))})
		caFile := topology.writeOriginCA(t)
		args := []string{
			"exec", "--skip-git-repo-check", "--sandbox", "read-only",
			"-c", `model_provider="dproxy_test"`,
			"-c", `model_providers.dproxy_test.name="dproxy test"`,
			"-c", `model_providers.dproxy_test.base_url="https://` + testOriginHost + `/v1"`,
			"-c", `model_providers.dproxy_test.env_key="OPENAI_API_KEY"`,
			"-c", `model_providers.dproxy_test.wire_api="responses"`,
			"Reply with ok.",
		}
		assertCommandUsesProxy(t, path, args, compatibilityEnvironment(topology.localAt, caFile), topology)
	})

	t.Run("Claude Code", func(t *testing.T) {
		path := requireExecutable(t, "claude")
		requests := make(chan *http.Request, 1)
		topology := newTopology(t, topologyOptions{originHandler: compatibilityHTTPHandler(requests, http.StatusUnauthorized, []byte(`{"type":"error","error":{"type":"authentication_error","message":"fixture"}}`))})
		caFile := topology.writeOriginCA(t)
		environment := append(compatibilityEnvironment(topology.localAt, caFile),
			"ANTHROPIC_BASE_URL=https://"+testOriginHost,
			"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		)
		args := []string{"--bare", "--print", "--no-session-persistence", "Reply with ok."}
		assertCommandUsesProxy(t, path, args, environment, topology)
	})
}

type topologyOptions struct {
	originHandler     func(*tls.Conn)
	remoteIdleTimeout time.Duration
	remoteMaxLifetime time.Duration
	resolvedAddresses []netip.Addr
	recordWSS         bool
}

type testTopology struct {
	local   *localproxy.Server
	localAt string
	remote  *relay.Server
	origin  *originServer
	dialer  *recordingDialer
	stream  *fixtureStreamDialer
	token   config.Token
}

func newTopology(t *testing.T, options topologyOptions) *testTopology {
	t.Helper()
	token, err := config.NewToken([]byte("e2e-token-7eeb9c6404c141d48fb83d8ed6747f82"))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := config.NewTokenSet(token)
	if err != nil {
		t.Fatal(err)
	}
	allowlist, err := policy.ParseAllowlist([]string{testOriginHost})
	if err != nil {
		t.Fatal(err)
	}
	timeouts := config.DefaultTimeouts()
	timeouts.Dial = time.Second
	timeouts.TLSHandshake = 2 * time.Second
	timeouts.Control = 2 * time.Second
	timeouts.Idle = 5 * time.Second
	if options.remoteIdleTimeout > 0 {
		timeouts.Idle = options.remoteIdleTimeout
	}
	timeouts.Shutdown = 2 * time.Second
	timeouts.MaxLifetime = options.remoteMaxLifetime
	if options.remoteMaxLifetime > 0 {
		timeouts.Idle = 0
	}

	origin := startOrigin(t, options.originHandler)
	dialer := &recordingDialer{address: origin.listener.Addr().String()}
	addresses := options.resolvedAddresses
	if addresses == nil {
		addresses = []netip.Addr{netip.MustParseAddr("8.8.8.8")}
	}
	identity, err := tunnel.LoadOrCreateIdentity(t.TempDir() + "/identity.pem")
	if err != nil {
		t.Fatalf("create remote identity: %v", err)
	}
	dohURL := mustURL(t, "https://resolver.e2e.test/dns-query")
	remoteConfig := &config.ServerConfig{
		Listen:       "127.0.0.1:1",
		IdentityFile: "unused",
		TokenFile:    "unused",
		DoHURL:       dohURL,
		DoHBootstrap: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Allowlist:    allowlist,
		Timeouts:     timeouts,
		Limits:       config.DefaultLimits(),
		Log:          config.DefaultLogOptions(),
	}
	remote, err := relay.NewServer(relay.ServerOptions{
		Config: remoteConfig, Identity: identity, Tokens: tokens,
		Resolver: staticResolver{addresses: addresses}, Dialer: dialer,
	})
	if err != nil {
		t.Fatalf("build remote server: %v", err)
	}
	outerCertificate, outerRoots := testCertificate(t, testRelayHost)
	remoteTCP := listenLoopback(t)
	remoteTLS := tls.NewListener(remoteTCP, &tls.Config{
		Certificates: []tls.Certificate{outerCertificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	serveRemote := make(chan error, 1)
	go func() { serveRemote <- remote.Serve(remoteTLS) }()
	stream := &fixtureStreamDialer{
		address: remoteTCP.Addr().String(), roots: outerRoots,
		endpoint: mustURL(t, "wss://"+testRelayHost+relay.TunnelPath), record: options.recordWSS,
	}
	clientConfig := &config.ClientConfig{
		Listen:       "127.0.0.1:1",
		RelayURL:     stream.endpoint,
		ServerPin:    identity.Pin,
		TokenFile:    "unused",
		DoHURL:       dohURL,
		DoHBootstrap: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		ECH:          config.ECHInsecureDisabled,
		Allowlist:    allowlist,
		Timeouts:     timeouts,
		Log:          config.DefaultLogOptions(),
	}
	client, err := tunnel.NewClient(tunnel.ClientOptions{Config: clientConfig, Token: token, StreamDialer: stream})
	if err != nil {
		t.Fatalf("build tunnel client: %v", err)
	}
	local, err := localproxy.NewServer(localproxy.ServerOptions{Config: clientConfig, Opener: client})
	if err != nil {
		t.Fatalf("build local proxy: %v", err)
	}
	localListener := listenLoopback(t)
	serveLocal := make(chan error, 1)
	go func() { serveLocal <- local.Serve(localListener) }()

	topology := &testTopology{
		local: local, localAt: localListener.Addr().String(), remote: remote,
		origin: origin, dialer: dialer, stream: stream, token: token,
	}
	t.Cleanup(func() {
		shutdownServer(t, local.Shutdown, serveLocal, "local proxy")
		shutdownServer(t, remote.Shutdown, serveRemote, "remote proxy")
		origin.close()
	})
	return topology
}

func (t *testTopology) connect(tb *testing.T, authority string) (*http.Response, net.Conn) {
	tb.Helper()
	conn, err := net.DialTimeout("tcp", t.localAt, time.Second)
	if err != nil {
		tb.Fatalf("connect to local proxy: %v", err)
	}
	request := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		tb.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = conn.Close()
		tb.Fatalf("read CONNECT response: %v", err)
	}
	return response, &bufferedConn{Conn: conn, reader: reader}
}

func (t *testTopology) openTLS(tb *testing.T) (*tls.Conn, net.Conn) {
	tb.Helper()
	response, raw := t.connect(tb, testOriginHost+":443")
	if response.StatusCode != http.StatusOK {
		_ = raw.Close()
		tb.Fatalf("CONNECT status = %d, want 200", response.StatusCode)
	}
	conn := tls.Client(raw, &tls.Config{
		RootCAs: t.origin.roots, ServerName: testOriginHost,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		tb.Fatalf("application TLS handshake: %v", err)
	}
	if got := conn.ConnectionState().Version; got != tls.VersionTLS13 {
		tb.Fatalf("application TLS version = %#x, want TLS 1.3", got)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return conn, raw
}

func (t *testTopology) writeOriginCA(tb *testing.T) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "origin-ca.pem")
	if err := os.WriteFile(path, t.origin.caPEM, 0o600); err != nil {
		tb.Fatalf("write origin CA: %v", err)
	}
	return path
}

func compatibilityHTTPHandler(requests chan<- *http.Request, status int, body []byte) func(*tls.Conn) {
	return func(conn *tls.Conn) {
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_ = request.Body.Close()
		requests <- request
		contentType := "application/json"
		if strings.Contains(request.URL.RawQuery, "service=git-upload-pack") {
			contentType = "application/x-git-upload-pack-advertisement"
		}
		_, _ = fmt.Fprintf(conn,
			"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
			status, http.StatusText(status), contentType, len(body),
		)
		_, _ = conn.Write(body)
	}
}

func compatibilityEnvironment(proxyAddress, caFile string) []string {
	blocked := map[string]bool{
		"ALL_PROXY": true, "HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
		"OPENAI_API_KEY": true, "OPENAI_BASE_URL": true,
		"ANTHROPIC_API_KEY": true, "ANTHROPIC_AUTH_TOKEN": true, "ANTHROPIC_BASE_URL": true,
		"CLAUDE_CODE_OAUTH_TOKEN": true, "SSL_CERT_FILE": true, "NODE_EXTRA_CA_CERTS": true,
	}
	environment := make([]string, 0, len(os.Environ())+12)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !blocked[strings.ToUpper(key)] {
			environment = append(environment, entry)
		}
	}
	proxy := "http://" + proxyAddress
	return append(environment,
		"HTTPS_PROXY="+proxy,
		"https_proxy="+proxy,
		"HTTP_PROXY="+proxy,
		"http_proxy="+proxy,
		"ALL_PROXY=",
		"all_proxy=",
		"NO_PROXY=",
		"no_proxy=",
		"SSL_CERT_FILE="+caFile,
		"NODE_EXTRA_CA_CERTS="+caFile,
		"OPENAI_API_KEY=dproxy-fixture-key",
		"ANTHROPIC_API_KEY=dproxy-fixture-key",
	)
}

func requireExecutable(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s is required for provider compatibility: %v", name, err)
	}
	return path
}

func awaitRequest(t *testing.T, requests <-chan *http.Request) *http.Request {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(3 * time.Second):
		t.Fatal("origin did not receive the client request")
		return nil
	}
}

func assertCommandUsesProxy(t *testing.T, path string, args, environment []string, topology *testTopology) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, args...)
	command.Env = environment
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatalf("start %s: %v", filepath.Base(path), err)
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	poll := time.NewTicker(20 * time.Millisecond)
	defer poll.Stop()
	for {
		if topology.dialer.calls.Load() > 0 {
			cancel()
			<-finished
			return
		}
		select {
		case <-poll.C:
		case err := <-finished:
			if topology.dialer.calls.Load() == 0 {
				t.Fatalf("%s exited before using HTTPS_PROXY: %v\n%s", filepath.Base(path), err, output.String())
			}
			return
		case <-ctx.Done():
			cancel()
			<-finished
			t.Fatalf("%s did not use HTTPS_PROXY\n%s", filepath.Base(path), output.String())
		}
	}
}

type staticResolver struct{ addresses []netip.Addr }

func (r staticResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.addresses...), nil
}

type recordingDialer struct {
	address string
	calls   atomic.Int64
}

func (d *recordingDialer) Dial(ctx context.Context, _ []netip.Addr, _ uint16, timeout time.Duration) (net.Conn, error) {
	d.calls.Add(1)
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", d.address)
}

type fixtureStreamDialer struct {
	address  string
	roots    *x509.CertPool
	endpoint *url.URL
	record   bool
	mu       sync.Mutex
	visible  bytes.Buffer
}

func (d *fixtureStreamDialer) DialStream(ctx context.Context) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	outer := tls.Client(raw, &tls.Config{
		RootCAs: d.roots, ServerName: testRelayHost,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	if err := outer.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	var transport net.Conn = outer
	if d.record {
		transport = &writeRecorder{Conn: outer, record: d.appendVisible}
	}
	reader, err := (&tunnel.Upgrader{URL: d.endpoint, Timeout: 2 * time.Second}).Upgrade(ctx, transport)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	return tunnel.NewClientWebSocketConn(transport, reader), nil
}

func (d *fixtureStreamDialer) appendVisible(data []byte) {
	d.mu.Lock()
	_, _ = d.visible.Write(data)
	d.mu.Unlock()
}

func (d *fixtureStreamDialer) recorded() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.visible.Bytes()...)
}

type writeRecorder struct {
	net.Conn
	record func([]byte)
}

func (c *writeRecorder) Write(data []byte) (int, error) {
	c.record(data)
	return c.Conn.Write(data)
}

type originServer struct {
	listener net.Listener
	roots    *x509.CertPool
	caPEM    []byte
	accepted atomic.Int64
	closed   chan struct{}
	connsMu  sync.Mutex
	conns    map[net.Conn]struct{}
}

func startOrigin(t *testing.T, handler func(*tls.Conn)) *originServer {
	t.Helper()
	certificate, roots := testCertificate(t, testOriginHost)
	listener := listenLoopback(t)
	server := &originServer{
		listener: listener,
		roots:    roots,
		caPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}),
		closed:   make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	if handler == nil {
		handler = func(conn *tls.Conn) { _, _ = io.Copy(conn, conn) }
	}
	go func() {
		defer close(server.closed)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			server.accepted.Add(1)
			server.connsMu.Lock()
			server.conns[raw] = struct{}{}
			server.connsMu.Unlock()
			go func() {
				defer func() {
					_ = raw.Close()
					server.connsMu.Lock()
					delete(server.conns, raw)
					server.connsMu.Unlock()
				}()
				conn := tls.Server(raw, &tls.Config{
					Certificates: []tls.Certificate{certificate},
					MinVersion:   tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
				})
				if err := conn.Handshake(); err == nil {
					handler(conn)
				}
			}()
		}
	}()
	return server
}

func (s *originServer) close() {
	_ = s.listener.Close()
	s.connsMu.Lock()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.connsMu.Unlock()
	<-s.closed
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

type readResult struct {
	data []byte
	err  error
}

func readAllAsync(reader io.Reader) <-chan readResult {
	result := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(reader)
		result <- readResult{data: data, err: err}
	}()
	return result
}

func writeAndReadEcho(t *testing.T, conn *tls.Conn, payload []byte, chunkSize int) {
	t.Helper()
	result := make(chan readResult, 1)
	go func() {
		data := make([]byte, len(payload))
		_, err := io.ReadFull(conn, data)
		result <- readResult{data: data, err: err}
	}()
	writeChunks(t, conn, payload, chunkSize)
	read := awaitRead(t, result)
	if read.err != nil {
		t.Fatalf("read echo: %v", read.err)
	}
	if !bytes.Equal(read.data, payload) {
		t.Fatalf("stream changed: got %d bytes, want %d", len(read.data), len(payload))
	}
}

func writeChunks(t *testing.T, writer io.Writer, payload []byte, chunkSize int) {
	t.Helper()
	for offset := 0; offset < len(payload); {
		end := min(offset+chunkSize, len(payload))
		written, err := writer.Write(payload[offset:end])
		if err != nil {
			t.Fatalf("write payload at byte %d: %v", offset, err)
		}
		if written == 0 {
			t.Fatalf("write payload at byte %d made no progress", offset)
		}
		offset += written
	}
}

func awaitRead(t *testing.T, result <-chan readResult) readResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for stream")
		return readResult{}
	}
}

func awaitSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal(message)
	}
}

func applicationWebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) // #nosec G401 -- fixed by RFC 6455
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeApplicationWebSocketFrame(writer io.Writer, payload []byte, masked bool) error {
	header := []byte{0x82}
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch {
	case len(payload) < 126:
		header = append(header, maskBit|byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, maskBit|126, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(len(payload)))
	default:
		return errors.New("application WebSocket fixture payload is too large")
	}
	encoded := append([]byte(nil), payload...)
	if masked {
		mask := [4]byte{0x12, 0x34, 0x56, 0x78}
		header = append(header, mask[:]...)
		for index := range encoded {
			encoded[index] ^= mask[index%len(mask)]
		}
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(encoded)
	return err
}

func readApplicationWebSocketFrame(reader io.Reader, wantMasked bool) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	masked := header[1]&0x80 != 0
	if header[0] != 0x82 || masked != wantMasked {
		return nil, errors.New("unexpected application WebSocket frame header")
	}
	length := int(header[1] & 0x7f)
	if length == 126 {
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint16(extended[:]))
	} else if length == 127 {
		return nil, errors.New("application WebSocket fixture frame is too large")
	}
	var mask [4]byte
	if wantMasked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	if wantMasked {
		for index := range payload {
			payload[index] ^= mask[index%len(mask)]
		}
	}
	return payload, nil
}

func bytePattern(size int) []byte {
	data := make([]byte, size)
	for index := range data {
		data[index] = byte((index*131 + index/251) & 0xff)
	}
	return data
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return listener
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return parsed
}

func testCertificate(t *testing.T, hostname string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate certificate serial: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	certificate.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Leaf)
	return certificate, roots
}

func shutdownServer(t *testing.T, shutdown func(context.Context) error, served <-chan error, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("shut down %s: %v", name, err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("serve %s: %v", name, err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("%s did not stop", name)
	}
}

var (
	_ relay.TargetDialer  = (*recordingDialer)(nil)
	_ policy.Resolver     = staticResolver{}
	_ tunnel.StreamDialer = (*fixtureStreamDialer)(nil)
)
