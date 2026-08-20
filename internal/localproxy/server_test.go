// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package localproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/logging"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/protocol"
	"github.com/wojciechpolak/dproxy/internal/relay"
	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

type openerFunc func(context.Context, policy.Destination) (net.Conn, error)

func (f openerFunc) Open(ctx context.Context, destination policy.Destination) (net.Conn, error) {
	return f(ctx, destination)
}

type timeoutFailure struct{}

func (timeoutFailure) Error() string { return "control read timed out" }

func (timeoutFailure) Timeout() bool { return true }

func (timeoutFailure) Temporary() bool { return true }

func localTestConfig(t *testing.T) *config.ClientConfig {
	t.Helper()
	relayURL, err := url.Parse("wss://dproxy.example.com/v1/tunnel")
	if err != nil {
		t.Fatalf("parse relay URL: %v", err)
	}
	dohURL, err := url.Parse(config.DefaultDoHURL)
	if err != nil {
		t.Fatalf("parse DoH URL: %v", err)
	}
	allowlist, err := policy.ParseAllowlist([]string{"api.openai.com"})
	if err != nil {
		t.Fatalf("parse test allowlist: %v", err)
	}
	return &config.ClientConfig{
		Listen:       config.DefaultClientListen,
		RelayURL:     relayURL,
		ServerPin:    config.PinFromSPKI([]byte("test key")),
		TokenFile:    "unused-token-file",
		DoHURL:       dohURL,
		DoHBootstrap: config.DefaultDoHBootstrap(dohURL),
		ECH:          config.ECHRequired,
		Allowlist:    allowlist,
		Timeouts:     config.DefaultTimeouts(),
		Log:          config.DefaultLogOptions(),
	}
}

func connectRequest(authority string) *http.Request {
	return &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: authority},
		RequestURI: authority,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
}

func TestServerRejectsUnsupportedAndMalformedRequestsBeforeOpeningTunnel(t *testing.T) {
	openCalls := 0
	server, err := NewServer(ServerOptions{
		Config: localTestConfig(t),
		Opener: openerFunc(func(context.Context, policy.Destination) (net.Conn, error) {
			openCalls++
			return nil, errors.New("should not open")
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	tests := []struct {
		name    string
		request *http.Request
		status  int
	}{
		{"ordinary HTTP", httptest.NewRequest(http.MethodGet, "http://api.openai.com/", nil), http.StatusMethodNotAllowed},
		{"malformed authority", connectRequest("api.openai.com"), http.StatusBadRequest},
		{"wrong port", connectRequest("api.openai.com:80"), http.StatusForbidden},
		{"IPv4 literal", connectRequest("127.0.0.1:443"), http.StatusForbidden},
		{"IPv6 literal", connectRequest("[::1]:443"), http.StatusForbidden},
		{"not allowlisted", connectRequest("example.org:443"), http.StatusForbidden},
	}
	version := connectRequest("api.openai.com:443")
	version.Proto = "HTTP/1.0"
	version.ProtoMinor = 0
	tests = append(tests, struct {
		name    string
		request *http.Request
		status  int
	}{"HTTP/1.0", version, http.StatusHTTPVersionNotSupported})
	body := connectRequest("api.openai.com:443")
	body.ContentLength = 1
	tests = append(tests, struct {
		name    string
		request *http.Request
		status  int
	}{"request body", body, http.StatusBadRequest})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, test.request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d; body: %s", recorder.Code, test.status, recorder.Body.String())
			}
		})
	}
	if openCalls != 0 {
		t.Fatalf("opener called %d times, want 0", openCalls)
	}
}

type pipeListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
}

func newPipeListener(conn net.Conn) *pipeListener {
	return &pipeListener{conn: conn, closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = l.conn })
	if conn != nil {
		return conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *pipeListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddress("pipe") }

type pipeAddress string

func (a pipeAddress) Network() string { return "pipe" }

func (a pipeAddress) String() string { return string(a) }

func TestHTTPServerRejectsMalformedRequestSyntax(t *testing.T) {
	server, err := NewServer(ServerOptions{
		Config: localTestConfig(t),
		Opener: openerFunc(func(context.Context, policy.Destination) (net.Conn, error) {
			return nil, errors.New("should not open")
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverSide, client := net.Pipe()
	listener := newPipeListener(serverSide)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	if _, err := io.WriteString(client, "CONNECT api.openai.com:443 HTTP/1.1\r\nBad Header\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	clientReader := bufio.NewReader(client)
	response, err := http.ReadResponse(clientReader, connectRequest("api.openai.com:443"))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.StatusCode)
	}
	_ = client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func TestHTTPServerPreservesBytesBufferedAfterCONNECT(t *testing.T) {
	remote, origin := net.Pipe()
	defer func() { _ = origin.Close() }()
	server, err := NewServer(ServerOptions{
		Config: localTestConfig(t),
		Opener: openerFunc(func(context.Context, policy.Destination) (net.Conn, error) {
			return remote, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverSide, client := net.Pipe()
	listener := newPipeListener(serverSide)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	prefix := []byte{0x16, 0x03, 0x01, 0x00, 0x02, 0xaa, 0xbb}
	request := append([]byte("CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n"), prefix...)
	go func() { _, _ = client.Write(request) }()
	clientReader := bufio.NewReader(client)
	response, err := http.ReadResponse(clientReader, connectRequest("api.openai.com:443"))
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	got := make([]byte, len(prefix))
	if _, err := io.ReadFull(origin, got); err != nil {
		t.Fatalf("origin read: %v", err)
	}
	if string(got) != string(prefix) {
		t.Fatalf("origin bytes = %v, want %v", got, prefix)
	}
	_ = client.Close()
	_ = origin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func TestServerMapsTunnelFailuresToProxyResponses(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"policy", &tunnel.RemoteOpenError{Code: protocol.ErrorForbiddenDestination}, http.StatusForbidden},
		{"private address", &tunnel.RemoteOpenError{Code: protocol.ErrorAddressRejected}, http.StatusForbidden},
		{"authentication", tunnel.ErrAuthenticationFailed, http.StatusBadGateway},
		{"remote unauthenticated", &tunnel.RemoteOpenError{Code: protocol.ErrorUnauthenticated}, http.StatusBadGateway},
		{"remote resolution", &tunnel.RemoteOpenError{Code: protocol.ErrorResolutionFailed}, http.StatusBadGateway},
		{"remote dial", &tunnel.RemoteOpenError{Code: protocol.ErrorDialFailed}, http.StatusBadGateway},
		{"remote limit", &tunnel.RemoteOpenError{Code: protocol.ErrorLimitExceeded}, http.StatusServiceUnavailable},
		{"remote malformed", &tunnel.RemoteOpenError{Code: protocol.ErrorMalformed}, http.StatusBadGateway},
		{"remote version", &tunnel.RemoteOpenError{Code: protocol.ErrorUnsupportedVersion}, http.StatusBadGateway},
		{"remote internal", &tunnel.RemoteOpenError{Code: protocol.ErrorInternal}, http.StatusBadGateway},
		{"context timeout", context.DeadlineExceeded, http.StatusGatewayTimeout},
		{"network timeout", timeoutFailure{}, http.StatusGatewayTimeout},
		{"tunnel", errors.New("outer TLS failed"), http.StatusBadGateway},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := NewServer(ServerOptions{
				Config: localTestConfig(t),
				Opener: openerFunc(func(context.Context, policy.Destination) (net.Conn, error) {
					return nil, test.err
				}),
			})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, connectRequest("api.openai.com:443"))
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

type hijackWriter struct {
	header http.Header
	conn   net.Conn
	rw     *bufio.ReadWriter
	mu     sync.Mutex
	status int
}

func (w *hijackWriter) Header() http.Header { return w.header }

func (w *hijackWriter) WriteHeader(status int) {
	w.mu.Lock()
	w.status = status
	w.mu.Unlock()
}

func (w *hijackWriter) Write(data []byte) (int, error) { return len(data), nil }

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.rw, nil
}

func TestServerRelaysApplicationBytesWithoutInspectingThem(t *testing.T) {
	remote, origin := net.Pipe()
	defer func() { _ = origin.Close() }()
	server, err := NewServer(ServerOptions{
		Config: localTestConfig(t),
		Opener: openerFunc(func(context.Context, policy.Destination) (net.Conn, error) {
			return remote, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	proxySide, client := net.Pipe()
	defer func() { _ = client.Close() }()
	writer := &hijackWriter{
		header: make(http.Header),
		conn:   proxySide,
		rw:     bufio.NewReadWriter(bufio.NewReader(proxySide), bufio.NewWriter(proxySide)),
	}
	done := make(chan struct{})
	go func() {
		server.ServeHTTP(writer, connectRequest("api.openai.com:443"))
		close(done)
	}()
	clientReader := bufio.NewReader(client)
	response, err := http.ReadResponse(clientReader, connectRequest("api.openai.com:443"))
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	requestBytes := []byte{0x16, 0x03, 0x01, 0x00, 0xff, 0x00, 0x7f}
	go func() { _, _ = client.Write(requestBytes) }()
	got := make([]byte, len(requestBytes))
	if _, err := io.ReadFull(origin, got); err != nil {
		t.Fatalf("origin read: %v", err)
	}
	if string(got) != string(requestBytes) {
		t.Fatalf("origin bytes = %v, want %v", got, requestBytes)
	}
	responseBytes := []byte{0x17, 0x03, 0x03, 0x01, 0x02}
	go func() { _, _ = origin.Write(responseBytes) }()
	got = make([]byte, len(responseBytes))
	if _, err := io.ReadFull(clientReader, got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != string(responseBytes) {
		t.Fatalf("client bytes = %v, want %v", got, responseBytes)
	}
	_ = client.Close()
	_ = origin.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CONNECT handler did not stop")
	}
}

func TestServerLogsOpenedTunnelAtInfo(t *testing.T) {
	var output bytes.Buffer
	remote, origin := net.Pipe()
	server, err := NewServer(ServerOptions{
		Config: localTestConfig(t),
		Logger: logging.New(&output, config.DefaultLogOptions()),
		Opener: openerFunc(func(context.Context, policy.Destination) (net.Conn, error) {
			return remote, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	proxySide, client := net.Pipe()
	writer := &hijackWriter{
		header: make(http.Header),
		conn:   proxySide,
		rw:     bufio.NewReadWriter(bufio.NewReader(proxySide), bufio.NewWriter(proxySide)),
	}
	done := make(chan struct{})
	go func() {
		server.ServeHTTP(writer, connectRequest("api.openai.com:443"))
		close(done)
	}()
	response, err := http.ReadResponse(bufio.NewReader(client), connectRequest("api.openai.com:443"))
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	_ = client.Close()
	_ = origin.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CONNECT handler did not stop")
	}
	logOutput := output.String()
	if !strings.Contains(logOutput, `level=INFO msg="tunnel opened" target=[redacted]`) {
		t.Fatalf("opened tunnel INFO log missing: %s", logOutput)
	}
	if strings.Contains(logOutput, "api.openai.com") {
		t.Fatalf("opened tunnel INFO log leaked target: %s", logOutput)
	}
}

func TestShutdownCancelsAStuckTunnelAfterItsDeadline(t *testing.T) {
	started := make(chan struct{})
	server, err := NewServer(ServerOptions{
		Config: localTestConfig(t),
		Opener: openerFunc(func(ctx context.Context, _ policy.Destination) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	handlerDone := make(chan struct{})
	go func() {
		server.ServeHTTP(httptest.NewRecorder(), connectRequest("api.openai.com:443"))
		close(handlerDone)
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(ctx); err == nil {
		t.Fatal("Shutdown succeeded despite an expired graceful deadline")
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("forced shutdown did not cancel tunnel establishment")
	}
}

func TestProxyErrorsDoNotNameTheDestination(t *testing.T) {
	server, err := NewServer(ServerOptions{
		Config: localTestConfig(t),
		Opener: openerFunc(func(context.Context, policy.Destination) (net.Conn, error) {
			return nil, errors.New("failed")
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, connectRequest("api.openai.com:443"))
	if strings.Contains(recorder.Body.String(), "api.openai.com") {
		t.Fatalf("proxy response leaked destination: %q", recorder.Body.String())
	}
}

func TestRelayEndClassification(t *testing.T) {
	for name, err := range map[string]error{
		"success":      nil,
		"canceled":     context.Canceled,
		"deadline":     context.DeadlineExceeded,
		"closed":       net.ErrClosed,
		"idle timeout": relay.ErrIdleTimeout,
	} {
		t.Run(name, func(t *testing.T) {
			if !expectedRelayEnd(err) {
				t.Fatalf("expectedRelayEnd(%v) = false", err)
			}
		})
	}
	if expectedRelayEnd(errors.New("broken pipe")) {
		t.Fatal("unexpected I/O failure was classified as an expected relay end")
	}
	if got := localRelayEndReason(relay.ErrIdleTimeout); got != "idle-timeout" {
		t.Errorf("idle timeout reason = %q", got)
	}
	if got := localRelayEndReason(errors.New("broken pipe")); got != "io-error" {
		t.Errorf("I/O failure reason = %q", got)
	}
}

func TestNewServerAndServeLifecycleErrors(t *testing.T) {
	if _, err := NewServer(ServerOptions{}); err == nil {
		t.Fatal("NewServer accepted no configuration")
	}
	invalid := localTestConfig(t)
	invalid.Listen = "0.0.0.0:18080"
	if _, err := NewServer(ServerOptions{Config: invalid}); err == nil {
		t.Fatal("NewServer accepted a non-loopback listener")
	}
	missing := localTestConfig(t)
	missing.TokenFile = config.TokenFile(filepath.Join(t.TempDir(), "missing"))
	if _, err := NewServer(ServerOptions{Config: missing}); err == nil {
		t.Fatal("NewServer built the production opener with a missing token")
	}

	server, err := NewServer(ServerOptions{Config: localTestConfig(t), Opener: openerFunc(func(context.Context, policy.Destination) (net.Conn, error) {
		return nil, errors.New("unused")
	})})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()
	server.config.Listen = occupied.Addr().String()
	if err := server.ListenAndServe(); err == nil {
		t.Fatal("ListenAndServe succeeded on an occupied address")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	server.serveMu.Lock()
	server.serving = true
	server.serveMu.Unlock()
	if err := server.Serve(listener); err == nil {
		t.Fatal("Serve accepted a second invocation")
	}
}

func TestServeHTTPDrainingAndMissingHijacker(t *testing.T) {
	server, err := NewServer(ServerOptions{
		Config: localTestConfig(t),
		Opener: openerFunc(func(context.Context, policy.Destination) (net.Conn, error) {
			local, peer := net.Pipe()
			_ = peer.Close()
			return local, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	server.draining.Store(true)
	draining := httptest.NewRecorder()
	server.ServeHTTP(draining, connectRequest("api.openai.com:443"))
	if draining.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining status = %d", draining.Code)
	}
	server.draining.Store(false)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, connectRequest("api.openai.com:443"))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("missing hijacker status = %d", response.Code)
	}
}
