// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package relay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/logging"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/protocol"
	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

type testResolver struct {
	mu        sync.Mutex
	addresses []netip.Addr
	err       error
	calls     int
}

func (r *testResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return append([]netip.Addr(nil), r.addresses...), r.err
}

func (r *testResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type testDialer struct {
	mu    sync.Mutex
	calls int
	peers chan net.Conn
}

func newTestDialer() *testDialer { return &testDialer{peers: make(chan net.Conn, 4)} }

func (d *testDialer) Dial(context.Context, []netip.Addr, uint16, time.Duration) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	relaySide, peer := net.Pipe()
	d.peers <- peer
	return relaySide, nil
}

func (d *testDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

type runningServer struct {
	server    *Server
	address   string
	token     config.Token
	serveDone chan error
}

func startTestServer(t *testing.T, resolver policy.Resolver, dialer TargetDialer) *runningServer {
	return startTestServerWithConfig(t, resolver, dialer, nil)
}

func startTestServerWithConfig(
	t *testing.T,
	resolver policy.Resolver,
	dialer TargetDialer,
	mutate func(*config.ServerConfig),
) *runningServer {
	return startTestServerWithConfigAndLogger(t, resolver, dialer, mutate, nil)
}

func startTestServerWithConfigAndLogger(
	t *testing.T,
	resolver policy.Resolver,
	dialer TargetDialer,
	mutate func(*config.ServerConfig),
	logger *logging.Logger,
) *runningServer {
	t.Helper()
	token, err := config.NewToken([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	tokens, err := config.NewTokenSet(token)
	if err != nil {
		t.Fatalf("NewTokenSet: %v", err)
	}
	identity, err := tunnel.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	dohURL, err := url.Parse(config.DefaultDoHURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	allowlist, err := policy.ParseAllowlist([]string{"api.openai.com"})
	if err != nil {
		t.Fatalf("parse test allowlist: %v", err)
	}
	settings := &config.ServerConfig{
		Listen:       "127.0.0.1:8686",
		IdentityFile: filepath.Join(t.TempDir(), "unused.pem"),
		TokenFile:    "unused-token-file",
		DoHURL:       dohURL,
		DoHBootstrap: config.DefaultDoHBootstrap(dohURL),
		Allowlist:    allowlist,
		Timeouts:     config.DefaultTimeouts(),
		Limits:       config.DefaultLimits(),
		Log:          config.DefaultLogOptions(),
	}
	settings.Timeouts.TLSHandshake = time.Second
	settings.Timeouts.Control = time.Second
	settings.Timeouts.Idle = time.Second
	settings.Timeouts.Shutdown = time.Second
	if mutate != nil {
		mutate(settings)
	}
	server, err := NewServer(ServerOptions{
		Config: settings, Identity: identity, Tokens: tokens, Resolver: resolver, Dialer: dialer, Logger: logger,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	running := &runningServer{
		server: server, address: listener.Addr().String(), token: token, serveDone: make(chan error, 1),
	}
	go func() { running.serveDone <- server.Serve(listener) }()
	waitForServerStart(t, server, running.serveDone)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		select {
		case <-running.serveDone:
		case <-time.After(time.Second):
			t.Error("remote server did not stop")
		}
	})
	return running
}

func waitForServerStart(t *testing.T, server *Server, serveDone <-chan error) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		server.serveMu.Lock()
		serving := server.serving
		server.serveMu.Unlock()
		if serving {
			return
		}
		select {
		case err := <-serveDone:
			t.Fatalf("remote server stopped during startup: %v", err)
		case <-deadline.C:
			t.Fatal("remote server did not start")
		case <-ticker.C:
		}
	}
}

func (s *runningServer) dialInner(t *testing.T) net.Conn {
	t.Helper()
	websocket := s.dialWebSocket(t)
	inner, _, err := tunnel.DialInnerTLS(t.Context(), websocket, s.server.IdentityPin(), time.Second)
	if err != nil {
		_ = websocket.Close()
		t.Fatalf("DialInnerTLS: %v", err)
	}
	return inner
}

func (s *runningServer) dialWebSocket(t *testing.T) net.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", s.address, time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	endpoint, err := url.Parse("wss://" + s.address + TunnelPath)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	reader, err := (&tunnel.Upgrader{URL: endpoint, Timeout: time.Second}).Upgrade(t.Context(), raw)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("Upgrade: %v", err)
	}
	return tunnel.NewClientWebSocketConn(raw, reader)
}

func authenticate(t *testing.T, conn net.Conn, token config.Token) (*protocol.Encoder, *protocol.Decoder) {
	t.Helper()
	encoder := protocol.NewEncoder(conn, config.DefaultLimits().MaxControlMessageBytes)
	decoder := protocol.NewDecoder(conn, config.DefaultLimits().MaxControlMessageBytes)
	if err := encoder.Encode(protocol.Hello{Version: protocol.Version1, Token: token}); err != nil {
		t.Fatalf("encode HELLO: %v", err)
	}
	message, err := decoder.Decode()
	if err != nil {
		t.Fatalf("decode HELLO_OK: %v", err)
	}
	if _, ok := message.(protocol.HelloOK); !ok {
		t.Fatalf("HELLO response = %T, want protocol.HelloOK", message)
	}
	return encoder, decoder
}

func mustDestination(t *testing.T, host string) policy.Destination {
	t.Helper()
	destination, err := policy.NewDestination(host, policy.AllowedPort)
	if err != nil {
		t.Fatalf("NewDestination: %v", err)
	}
	return destination
}

func TestServerAuthenticatesOpensAndRelays(t *testing.T) {
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	dialer := newTestDialer()
	running := startTestServer(t, resolver, dialer)
	inner := running.dialInner(t)
	defer func() { _ = inner.Close() }()
	encoder, decoder := authenticate(t, inner, running.token)

	if err := encoder.Encode(protocol.Open{Destination: mustDestination(t, "api.openai.com")}); err != nil {
		t.Fatalf("encode OPEN: %v", err)
	}
	message, err := decoder.Decode()
	if err != nil {
		t.Fatalf("decode OPEN_OK: %v", err)
	}
	if _, ok := message.(protocol.OpenOK); !ok {
		t.Fatalf("OPEN response = %T, want protocol.OpenOK", message)
	}
	target := <-dialer.peers
	defer func() { _ = target.Close() }()

	assertRelayed(t, inner, target, "request bytes")
	assertRelayed(t, target, inner, "response bytes")
	if resolver.callCount() != 1 || dialer.callCount() != 1 {
		t.Fatalf("resolver calls = %d, dialer calls = %d; want one each", resolver.callCount(), dialer.callCount())
	}
}

func TestServerLogsOpenedRelayAtInfo(t *testing.T) {
	var output bytes.Buffer
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	dialer := newTestDialer()
	running := startTestServerWithConfigAndLogger(
		t,
		resolver,
		dialer,
		nil,
		logging.New(&output, config.DefaultLogOptions()),
	)
	inner := running.dialInner(t)
	encoder, decoder := authenticate(t, inner, running.token)
	if err := encoder.Encode(protocol.Open{Destination: mustDestination(t, "api.openai.com")}); err != nil {
		t.Fatalf("encode OPEN: %v", err)
	}
	message, err := decoder.Decode()
	if err != nil {
		t.Fatalf("decode OPEN_OK: %v", err)
	}
	if _, ok := message.(protocol.OpenOK); !ok {
		t.Fatalf("OPEN response = %T, want protocol.OpenOK", message)
	}
	target := <-dialer.peers
	_ = inner.Close()
	_ = target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := running.server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	logOutput := output.String()
	if !strings.Contains(logOutput, `level=INFO msg="relay opened" target=[redacted]`) {
		t.Fatalf("opened relay INFO log missing: %s", logOutput)
	}
	if strings.Contains(logOutput, "api.openai.com") {
		t.Fatalf("opened relay INFO log leaked target: %s", logOutput)
	}
}

func TestServerRejectsWrongTokenBeforePolicyOrDial(t *testing.T) {
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	dialer := newTestDialer()
	running := startTestServer(t, resolver, dialer)
	inner := running.dialInner(t)
	defer func() { _ = inner.Close() }()
	wrong, err := config.NewToken([]byte("fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	encoder := protocol.NewEncoder(inner, config.DefaultLimits().MaxControlMessageBytes)
	if err := encoder.Encode(protocol.Hello{Version: protocol.Version1, Token: wrong}); err != nil {
		t.Fatalf("encode HELLO: %v", err)
	}
	_ = inner.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes).Decode(); err == nil {
		t.Fatal("wrong token received a protocol response")
	}
	if resolver.callCount() != 0 || dialer.callCount() != 0 {
		t.Fatalf("wrong token reached resolver or dialer: %d, %d", resolver.callCount(), dialer.callCount())
	}
}

func TestServerEnforcesRemoteDestinationPolicy(t *testing.T) {
	t.Run("not allowlisted", func(t *testing.T) {
		resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
		dialer := newTestDialer()
		running := startTestServer(t, resolver, dialer)
		inner := running.dialInner(t)
		defer func() { _ = inner.Close() }()
		encoder, decoder := authenticate(t, inner, running.token)
		if err := encoder.Encode(protocol.Open{Destination: mustDestination(t, "example.org")}); err != nil {
			t.Fatalf("encode OPEN: %v", err)
		}
		assertOpenError(t, decoder, protocol.ErrorForbiddenDestination)
		if resolver.callCount() != 0 || dialer.callCount() != 0 {
			t.Fatalf("refused name reached resolver or dialer: %d, %d", resolver.callCount(), dialer.callCount())
		}
	})

	t.Run("private resolution", func(t *testing.T) {
		resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
		dialer := newTestDialer()
		running := startTestServer(t, resolver, dialer)
		inner := running.dialInner(t)
		defer func() { _ = inner.Close() }()
		encoder, decoder := authenticate(t, inner, running.token)
		if err := encoder.Encode(protocol.Open{Destination: mustDestination(t, "api.openai.com")}); err != nil {
			t.Fatalf("encode OPEN: %v", err)
		}
		assertOpenError(t, decoder, protocol.ErrorAddressRejected)
		if dialer.callCount() != 0 {
			t.Fatalf("private resolution reached dialer %d times", dialer.callCount())
		}
	})
}

func TestServerRejectsOutOfOrderControlMessage(t *testing.T) {
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	dialer := newTestDialer()
	running := startTestServer(t, resolver, dialer)
	inner := running.dialInner(t)
	defer func() { _ = inner.Close() }()
	encoder, decoder := authenticate(t, inner, running.token)
	if err := encoder.Encode(protocol.Hello{Version: protocol.Version1, Token: running.token}); err != nil {
		t.Fatalf("encode second HELLO: %v", err)
	}
	assertOpenError(t, decoder, protocol.ErrorMalformed)
	if resolver.callCount() != 0 || dialer.callCount() != 0 {
		t.Fatal("out-of-order message reached destination handling")
	}
}

func TestServerEnforcesConcurrentSessionLimit(t *testing.T) {
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	running := startTestServerWithConfig(t, resolver, newTestDialer(), func(settings *config.ServerConfig) {
		settings.Limits.MaxSessions = 1
	})
	first := running.dialWebSocket(t)
	defer func() { _ = first.Close() }()

	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	response, err := client.Get("http://" + running.address + TunnelPath)
	if err != nil {
		t.Fatalf("second session request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second session status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestServerExposesOnlyTunnelAndPrivateHealthPaths(t *testing.T) {
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	running := startTestServer(t, resolver, newTestDialer())

	health := httptest.NewRecorder()
	running.server.ServeHTTP(health, httptest.NewRequest(http.MethodHead, HealthPath, nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", health.Code, http.StatusOK)
	}

	unrelated := httptest.NewRecorder()
	running.server.ServeHTTP(unrelated, httptest.NewRequest(http.MethodGet, "/", nil))
	if unrelated.Code != http.StatusNotFound {
		t.Fatalf("unrelated path status = %d, want %d", unrelated.Code, http.StatusNotFound)
	}

	query := httptest.NewRecorder()
	running.server.ServeHTTP(query, httptest.NewRequest(http.MethodGet, TunnelPath+"?token=forbidden", nil))
	if query.Code != http.StatusNotFound {
		t.Fatalf("tunnel query status = %d, want %d", query.Code, http.StatusNotFound)
	}
}

func TestServerShutdownWaitsForActiveRelay(t *testing.T) {
	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	dialer := newTestDialer()
	running := startTestServer(t, resolver, dialer)
	inner := running.dialInner(t)
	encoder, decoder := authenticate(t, inner, running.token)
	if err := encoder.Encode(protocol.Open{Destination: mustDestination(t, "api.openai.com")}); err != nil {
		t.Fatalf("encode OPEN: %v", err)
	}
	message, err := decoder.Decode()
	if err != nil {
		t.Fatalf("decode OPEN_OK: %v", err)
	}
	if _, ok := message.(protocol.OpenOK); !ok {
		t.Fatalf("OPEN response = %T, want protocol.OpenOK", message)
	}
	target := <-dialer.peers

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		shutdownDone <- running.server.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned while relay was active: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	_ = inner.Close()
	_ = target.Close()
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestRelayEndReason(t *testing.T) {
	if got := relayEndReason(ErrIdleTimeout); got != "idle-timeout" {
		t.Errorf("idle timeout reason = %q", got)
	}
	if got := relayEndReason(errors.New("broken pipe")); got != "io-error" {
		t.Errorf("I/O failure reason = %q", got)
	}
}

func TestNewServerLoadsDefaultsAndRejectsBadOptions(t *testing.T) {
	if _, err := NewServer(ServerOptions{}); err == nil {
		t.Fatal("NewServer accepted no configuration")
	}

	resolver := &testResolver{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	dialer := newTestDialer()
	running := startTestServer(t, resolver, dialer)
	invalid := running.server.config
	invalid.Listen = "not-an-address"
	if _, err := NewServer(ServerOptions{Config: &invalid}); err == nil {
		t.Fatal("NewServer accepted invalid configuration")
	}

	settings := running.server.config
	settings.IdentityFile = filepath.Join(t.TempDir(), "state", "identity.pem")
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	settings.TokenFile = config.TokenFile(tokenPath)
	server, err := NewServer(ServerOptions{Config: &settings, Resolver: resolver})
	if err != nil {
		t.Fatalf("NewServer with production defaults: %v", err)
	}
	if server.identity == nil || server.tokens.Len() != 1 {
		t.Fatal("NewServer did not load identity and token defaults")
	}
	if _, ok := server.dialer.(TCPDialer); !ok {
		t.Fatalf("default dialer = %T", server.dialer)
	}
}

func TestServerServeAndHTTPGuardBranches(t *testing.T) {
	running := startTestServer(t, &testResolver{}, newTestDialer())
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = second.Close() }()
	if err := running.server.Serve(second); err == nil {
		t.Fatal("Server.Serve allowed a second listener")
	}

	method := httptest.NewRecorder()
	running.server.ServeHTTP(method, httptest.NewRequest(http.MethodPost, HealthPath, nil))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("health POST = %d, Allow %q", method.Code, method.Header().Get("Allow"))
	}

	running.server.draining.Store(true)
	for _, path := range []string{HealthPath, TunnelPath} {
		response := httptest.NewRecorder()
		running.server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Errorf("draining %s status = %d", path, response.Code)
		}
	}
	running.server.draining.Store(false)
	running.server.failures.overflow = time.Now().Add(time.Minute)
	blocked := httptest.NewRecorder()
	running.server.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, TunnelPath, nil))
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked session status = %d", blocked.Code)
	}
}

func TestServerListenAndServeReportsBindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	running := startTestServer(t, &testResolver{}, newTestDialer())
	running.server.config.Listen = occupied.Addr().String()
	if err := running.server.ListenAndServe(); err == nil {
		t.Fatal("ListenAndServe succeeded on an occupied address")
	}
}

func TestServerSessionContextAndForcedShutdown(t *testing.T) {
	running := startTestServer(t, &testResolver{}, newTestDialer())
	running.server.config.Timeouts.MaxLifetime = time.Second
	ctx, cancel := running.server.sessionContext()
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Fatal("session context has no maximum-lifetime deadline")
	}

	settings := running.server.config
	server, err := NewServer(ServerOptions{
		Config: &settings, Identity: running.server.identity, Tokens: running.server.tokens,
		Resolver: &testResolver{}, Dialer: newTestDialer(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverSide, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	activeCtx, activeCancel := context.WithCancel(context.Background())
	server.track(serverSide, activeCancel)
	server.activeWait.Add(1)
	go func() {
		<-activeCtx.Done()
		server.untrack(serverSide)
		server.activeWait.Done()
	}()

	shutdownCtx, stop := context.WithCancel(context.Background())
	stop()
	if err := server.Shutdown(shutdownCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("forced Shutdown = %v, want context cancellation", err)
	}
	if !server.draining.Load() {
		t.Fatal("forced shutdown did not mark the server draining")
	}
}

func assertOpenError(t *testing.T, decoder *protocol.Decoder, code protocol.ErrorCode) {
	t.Helper()
	message, err := decoder.Decode()
	if err != nil {
		t.Fatalf("decode OPEN_ERROR: %v", err)
	}
	openError, ok := message.(protocol.OpenError)
	if !ok || openError.Code != code {
		t.Fatalf("OPEN response = %#v, want protocol.OpenError{%s}", message, code)
	}
}

var (
	_ policy.Resolver = (*testResolver)(nil)
	_ TargetDialer    = (*testDialer)(nil)
)
