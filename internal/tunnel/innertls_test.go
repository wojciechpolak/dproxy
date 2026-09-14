// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/protocol"
)

type innerTLSResult struct {
	conn net.Conn
	info *InnerTLSInfo
	err  error
}

func TestInnerTLSRequiresTLS13ALPNAndPin(t *testing.T) {
	identity := testIdentity(t)
	clientRaw, serverRaw := net.Pipe()
	serverResult := make(chan innerTLSResult, 1)
	go func() {
		conn, info, err := AcceptInnerTLS(context.Background(), serverRaw, identity, config.PinSet{}, time.Second)
		serverResult <- innerTLSResult{conn: conn, info: info, err: err}
	}()
	client, clientInfo, err := DialInnerTLS(context.Background(), clientRaw, identity.Pin, nil, time.Second)
	if err != nil {
		t.Fatalf("DialInnerTLS: %v", err)
	}
	defer func() { _ = clientRaw.Close() }()
	server := <-serverResult
	if server.err != nil {
		t.Fatalf("AcceptInnerTLS: %v", server.err)
	}
	defer func() { _ = serverRaw.Close() }()
	for side, info := range map[string]*InnerTLSInfo{"client": clientInfo, "server": server.info} {
		if info.Version != tls.VersionTLS13 || info.NegotiatedProtocol != protocol.ALPN || info.ServerPin != identity.Pin {
			t.Errorf("%s info = %+v", side, info)
		}
	}

	written := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("inner stream"))
		written <- err
	}()
	buffer := make([]byte, len("inner stream"))
	if _, err := io.ReadFull(server.conn, buffer); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if err := <-written; err != nil || string(buffer) != "inner stream" {
		t.Fatalf("stream = %q, write error %v", buffer, err)
	}
}

func TestInnerTLSRejectsTheWrongPin(t *testing.T) {
	identity := testIdentity(t)
	other := testIdentity(t)
	clientRaw, serverRaw := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		_, _, err := AcceptInnerTLS(context.Background(), serverRaw, identity, config.PinSet{}, time.Second)
		serverErr <- err
	}()
	if _, _, err := DialInnerTLS(context.Background(), clientRaw, other.Pin, nil, time.Second); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("DialInnerTLS = %v, want ErrPinMismatch", err)
	}
	select {
	case <-serverErr:
	case <-time.After(2 * time.Second):
		t.Fatal("server handshake stayed blocked after pin rejection")
	}
}

func TestInnerTLSRejectsMissingALPN(t *testing.T) {
	identity := testIdentity(t)
	clientRaw, serverRaw := net.Pipe()
	serverErr := make(chan error, 1)
	go func() {
		server := tls.Server(serverRaw, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{identity.Certificate},
		})
		serverErr <- server.Handshake()
	}()
	if _, _, err := DialInnerTLS(context.Background(), clientRaw, identity.Pin, nil, time.Second); !errors.Is(err, ErrALPNMismatch) {
		t.Fatalf("DialInnerTLS = %v, want ErrALPNMismatch", err)
	}
	select {
	case <-serverErr:
	case <-time.After(2 * time.Second):
		t.Fatal("server handshake stayed blocked after ALPN rejection")
	}
}

func TestFrontEndVisibleBytesDoNotRevealInnerData(t *testing.T) {
	identity := testIdentity(t)
	// A pinned client identity runs here too: its certificate is sent after the
	// remote's Finished and must stay inside the handshake encryption.
	clientIdentity := testClientIdentity(t)
	clients, err := config.NewPinSet(clientIdentity.Pin)
	if err != nil {
		t.Fatalf("NewPinSet: %v", err)
	}
	rawClient, rawServer := net.Pipe()
	recorded := &recordingConn{Conn: rawClient}
	clientWebSocket := NewClientWebSocketConn(recorded, nil)
	serverWebSocket := NewServerWebSocketConn(rawServer, nil)
	serverReady := make(chan innerTLSResult, 1)
	go func() {
		conn, info, err := AcceptInnerTLS(context.Background(), serverWebSocket, identity, clients, 2*time.Second)
		serverReady <- innerTLSResult{conn: conn, info: info, err: err}
	}()
	clientTLS, _, err := DialInnerTLS(context.Background(), clientWebSocket, identity.Pin, clientIdentity, 2*time.Second)
	if err != nil {
		t.Fatalf("DialInnerTLS: %v", err)
	}
	defer func() { _ = rawClient.Close() }()
	server := <-serverReady
	if server.err != nil {
		t.Fatalf("AcceptInnerTLS: %v", server.err)
	}
	defer func() { _ = rawServer.Close() }()

	if server.info.ClientPin != clientIdentity.Pin {
		t.Fatalf("server client pin = %s, want %s", server.info.ClientPin, clientIdentity.Pin)
	}

	secret := []byte("0123456789abcdef0123456789abcdef")
	token, err := config.NewToken(secret)
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	destination, err := policy.NewDestination("api.openai.com", policy.AllowedPort)
	if err != nil {
		t.Fatalf("NewDestination: %v", err)
	}
	clientEncoder := protocol.NewEncoder(clientTLS, 4096)
	serverDecoder := protocol.NewDecoder(server.conn, 4096)
	for _, message := range []protocol.Message{
		protocol.Hello{Version: protocol.Version1, Token: token},
		protocol.Open{Destination: destination},
	} {
		encoded := make(chan error, 1)
		go func() { encoded <- clientEncoder.Encode(message) }()
		if _, err := serverDecoder.Decode(); err != nil {
			t.Fatalf("Decode(%s): %v", message.Type(), err)
		}
		if err := <-encoded; err != nil {
			t.Fatalf("Encode(%s): %v", message.Type(), err)
		}
	}
	application := []byte("opaque application bytes")
	written := make(chan error, 1)
	go func() {
		_, err := clientTLS.Write(application)
		written <- err
	}()
	got := make([]byte, len(application))
	if _, err := io.ReadFull(server.conn, got); err != nil {
		t.Fatalf("application ReadFull: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("application Write: %v", err)
	}

	visible := recorded.Bytes()
	for description, plaintext := range map[string][]byte{
		"token":              secret,
		"target hostname":    []byte(destination.Host()),
		"application bytes":  application,
		"client certificate": clientIdentity.Certificate.Certificate[0],
		"client pin digest":  clientIdentity.Pin.Digest(),
	} {
		if bytes.Contains(visible, plaintext) {
			t.Errorf("front-end-visible WebSocket bytes contain %s", description)
		}
	}
}

func testIdentity(t *testing.T) *Identity {
	t.Helper()
	identity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	return identity
}

func testClientIdentity(t *testing.T) *Identity {
	t.Helper()
	identity, err := LoadOrCreateClientIdentity(filepath.Join(t.TempDir(), "client-identity.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateClientIdentity: %v", err)
	}
	return identity
}

type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes bytes.Buffer
}

func (c *recordingConn) Write(payload []byte) (int, error) {
	c.mu.Lock()
	_, _ = c.writes.Write(payload)
	c.mu.Unlock()
	return c.Conn.Write(payload)
}

func (c *recordingConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.writes.Bytes()...)
}

// loopbackPair returns a buffered connection pair. A refused client certificate
// deadlocks net.Pipe: the remote writes its alert while the client is still
// writing the rest of its handshake flight and neither side is reading.
func loopbackPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func clientPinPair(t *testing.T, clients config.PinSet, offered *Identity) (net.Conn, *InnerTLSInfo, innerTLSResult, error) {
	t.Helper()
	identity := testIdentity(t)
	clientRaw, serverRaw := loopbackPair(t)
	accepted := make(chan innerTLSResult, 1)
	go func() {
		conn, info, err := AcceptInnerTLS(context.Background(), serverRaw, identity, clients, 2*time.Second)
		accepted <- innerTLSResult{conn: conn, info: info, err: err}
	}()
	client, clientInfo, err := DialInnerTLS(context.Background(), clientRaw, identity.Pin, offered, 2*time.Second)
	select {
	case server := <-accepted:
		return client, clientInfo, server, err
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake stayed blocked")
		return nil, nil, innerTLSResult{}, nil
	}
}

func TestInnerTLSAcceptsAPinnedClient(t *testing.T) {
	clientIdentity := testClientIdentity(t)
	clients, err := config.NewPinSet(clientIdentity.Pin)
	if err != nil {
		t.Fatal(err)
	}
	client, clientInfo, server, dialErr := clientPinPair(t, clients, clientIdentity)
	if dialErr != nil {
		t.Fatalf("DialInnerTLS: %v", dialErr)
	}
	if server.err != nil {
		t.Fatalf("AcceptInnerTLS: %v", server.err)
	}
	if server.info.ClientPin != clientIdentity.Pin {
		t.Errorf("server client pin = %s, want %s", server.info.ClientPin, clientIdentity.Pin)
	}
	if clientInfo.ClientPin != clientIdentity.Pin {
		t.Errorf("client client pin = %s, want %s", clientInfo.ClientPin, clientIdentity.Pin)
	}
	_ = client.Close()
}

func TestInnerTLSRejectsAnUnpinnedClient(t *testing.T) {
	clients, err := config.NewPinSet(testClientIdentity(t).Pin)
	if err != nil {
		t.Fatal(err)
	}
	// TLS 1.3 finishes the client handshake before the remote validates the
	// certificate, so the dial succeeds and the refusal arrives on the first
	// read. The remote must still hold no usable connection.
	client, _, server, dialErr := clientPinPair(t, clients, nil)
	if dialErr != nil {
		t.Fatalf("DialInnerTLS = %v, want the refusal to arrive on the first read", dialErr)
	}
	if server.err == nil {
		t.Fatal("AcceptInnerTLS accepted a client that presented no certificate")
	}
	if server.info != nil {
		t.Error("AcceptInnerTLS produced authenticated state for a rejected client")
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("client read succeeded after the remote refused its identity")
	} else if !ClientCertificateRejected(err) {
		t.Errorf("client read error = %v, want a certificate refusal", err)
	}
}

func TestInnerTLSRejectsTheWrongClientPin(t *testing.T) {
	clients, err := config.NewPinSet(testClientIdentity(t).Pin)
	if err != nil {
		t.Fatal(err)
	}
	_, _, server, _ := clientPinPair(t, clients, testClientIdentity(t))
	if !errors.Is(server.err, ErrClientPinMismatch) {
		t.Fatalf("AcceptInnerTLS = %v, want ErrClientPinMismatch", server.err)
	}
	if server.info != nil {
		t.Error("AcceptInnerTLS produced authenticated state for an unpinned key")
	}
}

func TestInnerTLSIgnoresAClientIdentityWhenNoPinsAreConfigured(t *testing.T) {
	clientIdentity := testClientIdentity(t)
	client, _, server, dialErr := clientPinPair(t, config.PinSet{}, clientIdentity)
	if dialErr != nil {
		t.Fatalf("DialInnerTLS: %v", dialErr)
	}
	if server.err != nil {
		t.Fatalf("AcceptInnerTLS: %v", server.err)
	}
	// No CertificateRequest was sent, so nothing was transmitted.
	if !server.info.ClientPin.IsZero() {
		t.Errorf("server client pin = %s, want none", server.info.ClientPin)
	}
	_ = client.Close()
}

// TestConnectionResetMatchesARealSocketReset checks connectionResetErrors
// against an error the operating system produced. A remote that refuses the
// certificate closes with the client's HELLO still unread, and Windows reports
// that as a reset rather than delivering the alert. Windows names that error
// WSAECONNRESET, which its own syscall.ECONNRESET never matches, so compiling
// the constant is no evidence that it matches.
func TestConnectionResetMatchesARealSocketReset(t *testing.T) {
	clientRaw, serverRaw := loopbackPair(t)
	tcp, ok := serverRaw.(*net.TCPConn)
	if !ok {
		t.Fatalf("loopbackPair server = %T, want *net.TCPConn", serverRaw)
	}
	// SO_LINGER 0 makes the close send RST instead of FIN.
	if err := tcp.SetLinger(0); err != nil {
		t.Fatalf("SetLinger: %v", err)
	}
	if err := tcp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var err error
	for range 10 {
		if _, err = clientRaw.Read(make([]byte, 1)); err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("read succeeded after the peer reset the connection")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("read = %v, want a reset; the peer closed in an orderly way", err)
	}
	if !connectionReset(err) {
		t.Fatalf("connectionReset(%v) = false, want true", err)
	}
	if !ClientCertificateRejected(err) {
		t.Errorf("ClientCertificateRejected(%v) = false, want true", err)
	}
}

func TestClientCertificateRejectedIgnoresUnrelatedErrors(t *testing.T) {
	if ClientCertificateRejected(nil) {
		t.Error("nil classified as a certificate refusal")
	}
	if ClientCertificateRejected(io.EOF) {
		t.Error("EOF classified as a certificate refusal")
	}
	if !ClientCertificateRejected(ErrClientPinMismatch) {
		t.Error("ErrClientPinMismatch not classified as a certificate refusal")
	}
	reset := fmt.Errorf("receive HELLO response: %w", &net.OpError{Op: "read", Err: connectionResetErrors[0]})
	if !ClientCertificateRejected(reset) {
		t.Error("a wrapped connection reset not classified as a certificate refusal")
	}
}
