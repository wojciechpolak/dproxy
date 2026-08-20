// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
		conn, info, err := AcceptInnerTLS(context.Background(), serverRaw, identity, time.Second)
		serverResult <- innerTLSResult{conn: conn, info: info, err: err}
	}()
	client, clientInfo, err := DialInnerTLS(context.Background(), clientRaw, identity.Pin, time.Second)
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
		_, _, err := AcceptInnerTLS(context.Background(), serverRaw, identity, time.Second)
		serverErr <- err
	}()
	if _, _, err := DialInnerTLS(context.Background(), clientRaw, other.Pin, time.Second); !errors.Is(err, ErrPinMismatch) {
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
	if _, _, err := DialInnerTLS(context.Background(), clientRaw, identity.Pin, time.Second); !errors.Is(err, ErrALPNMismatch) {
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
	rawClient, rawServer := net.Pipe()
	recorded := &recordingConn{Conn: rawClient}
	clientWebSocket := NewClientWebSocketConn(recorded, nil)
	serverWebSocket := NewServerWebSocketConn(rawServer, nil)
	serverReady := make(chan innerTLSResult, 1)
	go func() {
		conn, info, err := AcceptInnerTLS(context.Background(), serverWebSocket, identity, 2*time.Second)
		serverReady <- innerTLSResult{conn: conn, info: info, err: err}
	}()
	clientTLS, _, err := DialInnerTLS(context.Background(), clientWebSocket, identity.Pin, 2*time.Second)
	if err != nil {
		t.Fatalf("DialInnerTLS: %v", err)
	}
	defer func() { _ = rawClient.Close() }()
	server := <-serverReady
	if server.err != nil {
		t.Fatalf("AcceptInnerTLS: %v", server.err)
	}
	defer func() { _ = rawServer.Close() }()

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
		"token":             secret,
		"target hostname":   []byte(destination.Host()),
		"application bytes": application,
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
