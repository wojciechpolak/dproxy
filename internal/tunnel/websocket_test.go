// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/securetransport"
)

const relayEndpoint = "wss://relay.example.com/v1/tunnel"

// upgraderFor builds an upgrader for the test endpoint.
func upgraderFor(t *testing.T) *Upgrader {
	t.Helper()
	endpoint, err := url.Parse(relayEndpoint)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &Upgrader{URL: endpoint, Timeout: 5 * time.Second}
}

// serve runs one handshake exchange on the server end of a pipe. reply is
// given the parsed request and returns the raw bytes to answer with.
func serve(t *testing.T, reply func(*http.Request) string, trailing string) (net.Conn, chan *http.Request) {
	t.Helper()
	client, server := net.Pipe()
	requests := make(chan *http.Request, 1)
	go func() {
		defer func() { _ = server.Close() }()
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			requests <- nil
			return
		}
		requests <- request
		if _, err := io.WriteString(server, reply(request)); err != nil {
			return
		}
		if trailing != "" {
			_, _ = io.WriteString(server, trailing)
		}
		// Hold the pipe open so the client can read what was written.
		time.Sleep(50 * time.Millisecond)
	}()
	t.Cleanup(func() { _ = client.Close() })
	return client, requests
}

// accepted builds a correct 101 response for a request.
func accepted(request *http.Request) string {
	return "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptToken(request.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
}

func TestUpgradeSucceedsAndKeepsBufferedBytes(t *testing.T) {
	conn, requests := serve(t, accepted, "the first inner TLS bytes")
	reader, err := upgraderFor(t).Upgrade(context.Background(), conn)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	buffer := make([]byte, len("the first inner TLS bytes"))
	if _, err := io.ReadFull(reader, buffer); err != nil {
		t.Fatalf("read after upgrade: %v", err)
	}
	if string(buffer) != "the first inner TLS bytes" {
		t.Errorf("read %q; bytes that arrived with the response were lost", buffer)
	}

	request := <-requests
	if request.Method != http.MethodGet || request.URL.Path != "/v1/tunnel" {
		t.Errorf("request line = %s %s", request.Method, request.URL)
	}
	if request.Host != "relay.example.com" {
		t.Errorf("Host = %q", request.Host)
	}
	if !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
		t.Errorf("Upgrade = %q", request.Header.Get("Upgrade"))
	}
	if request.Header.Get("Sec-WebSocket-Version") != websocketVersion {
		t.Errorf("Sec-WebSocket-Version = %q", request.Header.Get("Sec-WebSocket-Version"))
	}
	key, err := base64.StdEncoding.DecodeString(request.Header.Get("Sec-WebSocket-Key"))
	if err != nil || len(key) != 16 {
		t.Errorf("Sec-WebSocket-Key = %q, %v", request.Header.Get("Sec-WebSocket-Key"), err)
	}
}

// Nothing in the request may name this software or this protocol: the outer
// handshake is what the WSS front end sees, and dproxy/1 belongs in the inner
// ALPN.
func TestUpgradeRequestCarriesNoFingerprint(t *testing.T) {
	conn, requests := serve(t, accepted, "")
	if _, err := upgraderFor(t).Upgrade(context.Background(), conn); err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	request := <-requests
	for _, header := range []string{"Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions", "User-Agent", "Origin"} {
		if value := request.Header.Get(header); value != "" {
			t.Errorf("%s = %q, want it absent", header, value)
		}
	}
}

// A redirect during establishment would let whatever answered choose the
// endpoint, so it is refused by name rather than folded into "handshake failed".
func TestUpgradeRejectsARedirect(t *testing.T) {
	for _, status := range []string{"301 Moved Permanently", "302 Found", "307 Temporary Redirect"} {
		conn, _ := serve(t, func(*http.Request) string {
			return "HTTP/1.1 " + status + "\r\nLocation: https://elsewhere.example/\r\nContent-Length: 0\r\n\r\n"
		}, "")
		_, err := upgraderFor(t).Upgrade(context.Background(), conn)
		if reason := securetransport.ReasonOf(err); reason != securetransport.FailureRedirect {
			t.Errorf("%s: reason = %s, want redirect", status, reason)
		}
	}
}

func TestUpgradeRejectsBadResponses(t *testing.T) {
	cases := map[string]func(*http.Request) string{
		"not an upgrade at all": func(*http.Request) string {
			return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
		},
		"forbidden": func(*http.Request) string {
			return "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
		},
		"accept token does not match": func(*http.Request) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: " + acceptToken("some other key") + "\r\n\r\n"
		},
		"accept token missing": func(*http.Request) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		},
		"upgraded to something else": func(request *http.Request) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: " + acceptToken(request.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
		},
		"connection header without the token": func(request *http.Request) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive\r\n" +
				"Sec-WebSocket-Accept: " + acceptToken(request.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
		},
		"unoffered extension selected": func(request *http.Request) string {
			return strings.TrimSuffix(accepted(request), "\r\n") +
				"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
		},
		"unoffered subprotocol selected": func(request *http.Request) string {
			return strings.TrimSuffix(accepted(request), "\r\n") +
				"Sec-WebSocket-Protocol: dproxy/1\r\n\r\n"
		},
		"not HTTP at all": func(*http.Request) string {
			return "this is not a response\r\n\r\n"
		},
	}
	for description, reply := range cases {
		t.Run(description, func(t *testing.T) {
			conn, _ := serve(t, reply, "")
			reader, err := upgraderFor(t).Upgrade(context.Background(), conn)
			if err == nil {
				t.Fatalf("a bad upgrade response was accepted (reader %v)", reader != nil)
			}
			if reason := securetransport.ReasonOf(err); reason == securetransport.FailureNone {
				t.Errorf("err = %v, want a classified transport failure", err)
			}
		})
	}
}

// A relay that accepts the connection and then says nothing must not hold the
// tunnel open: cancelling the context has to reach a blocked read.
func TestUpgradeHonoursCancellation(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go func() {
		defer func() { _ = server.Close() }()
		_, _ = http.ReadRequest(bufio.NewReader(server))
		<-time.After(2 * time.Second)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	upgrader := upgraderFor(t)
	upgrader.Timeout = time.Minute
	start := time.Now()
	if _, err := upgrader.Upgrade(ctx, client); err == nil {
		t.Fatal("a cancelled upgrade succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the upgrade took %s; cancellation did not reach the read", elapsed)
	}
}

func TestUpgradeHonoursItsTimeout(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go func() {
		defer func() { _ = server.Close() }()
		_, _ = http.ReadRequest(bufio.NewReader(server))
		<-time.After(2 * time.Second)
	}()

	upgrader := upgraderFor(t)
	upgrader.Timeout = 100 * time.Millisecond
	if _, err := upgrader.Upgrade(context.Background(), client); err == nil {
		t.Fatal("an upgrade with no response succeeded")
	}
}

func TestUpgradeRequiresARelayURL(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	if _, err := (&Upgrader{}).Upgrade(context.Background(), client); err == nil {
		t.Fatal("an upgrade without a relay URL was attempted")
	}
}

func TestHeaderHasToken(t *testing.T) {
	cases := map[string]bool{
		"Upgrade":             true,
		"upgrade":             true,
		"keep-alive, Upgrade": true,
		" Upgrade ":           true,
		"keep-alive":          false,
		"":                    false,
		"Upgraded":            false,
	}
	for value, want := range cases {
		if got := headerHasToken(value, "upgrade"); got != want {
			t.Errorf("headerHasToken(%q) = %v, want %v", value, got, want)
		}
	}
}

// A fixed vector over the sample key from RFC 6455 and the GUID that RFC
// fixes, so a change to the derivation is caught rather than agreed with by
// both sides of a test that computes it twice.
func TestAcceptTokenIsStable(t *testing.T) {
	if got := acceptToken("dGhlIHNhbXBsZSBub25jZQ=="); got != "tF+4yo8PvjWV9zMFht911yVrKKY=" {
		t.Errorf("acceptToken = %q", got)
	}
}

func TestAcceptWebSocketCompletesTheServerHandshake(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := AcceptWebSocket(writer, request)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(conn, buffer); err == nil {
			_, _ = conn.Write(bytes.ToUpper(buffer))
		}
	}))
	defer server.Close()

	endpoint, err := url.Parse("wss" + strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	raw, err := net.Dial("tcp", endpoint.Host)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	reader, err := (&Upgrader{URL: endpoint, Timeout: time.Second}).Upgrade(t.Context(), raw)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	client := NewClientWebSocketConn(raw, reader)
	defer func() { _ = client.Close() }()
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("ping"))
		writeErr <- err
	}()
	response := make([]byte, 4)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("Write: %v", err)
	}
	if string(response) != "PING" {
		t.Errorf("response = %q", response)
	}
}

func TestAcceptWebSocketRejectsBadRequests(t *testing.T) {
	cases := []struct {
		name   string
		method string
		header http.Header
		status int
	}{
		{"wrong method", http.MethodPost, http.Header{}, http.StatusMethodNotAllowed},
		{"not an upgrade", http.MethodGet, http.Header{}, http.StatusUpgradeRequired},
		{"wrong version", http.MethodGet, http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Version": {"12"}}, http.StatusBadRequest},
		{"bad key", http.MethodGet, http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"bad"}}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, "http://relay.test/v1/tunnel", nil)
			request.Header = tc.header
			response := httptest.NewRecorder()
			if conn, err := AcceptWebSocket(response, request); err == nil || conn != nil {
				t.Fatal("AcceptWebSocket accepted a bad request")
			}
			if response.Code != tc.status {
				t.Errorf("status = %d, want %d", response.Code, tc.status)
			}
		})
	}
}

func TestAcceptWebSocketRejectsOffersAndMissingHijacker(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	request := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://relay.test/v1/tunnel", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", websocketVersion)
		req.Header.Set("Sec-WebSocket-Key", key)
		return req
	}

	offered := request()
	offered.Header.Set("Sec-WebSocket-Protocol", "dproxy/1")
	response := httptest.NewRecorder()
	if _, err := AcceptWebSocket(response, offered); err == nil || response.Code != http.StatusBadRequest {
		t.Fatalf("offered protocol = status %d, err %v", response.Code, err)
	}

	response = httptest.NewRecorder()
	if _, err := AcceptWebSocket(response, request()); err == nil || response.Code != http.StatusInternalServerError {
		t.Fatalf("missing hijacker = status %d, err %v", response.Code, err)
	}
}

type deadlineErrorConn struct {
	net.Conn
	err error
}

func (c deadlineErrorConn) SetDeadline(time.Time) error { return c.err }

type websocketErrorReader struct{ err error }

func (r websocketErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestUpgraderReportsNonceAndDeadlineFailures(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	upgrader := upgraderFor(t)
	upgrader.entropy = websocketErrorReader{err: errors.New("entropy failed")}
	if _, err := upgrader.Upgrade(t.Context(), client); err == nil {
		t.Fatal("Upgrade ignored entropy failure")
	}

	upgrader = upgraderFor(t)
	if _, err := upgrader.Upgrade(t.Context(), deadlineErrorConn{Conn: client, err: errors.New("deadline failed")}); err == nil {
		t.Fatal("Upgrade ignored deadline failure")
	}

	root := &Upgrader{URL: &url.URL{Scheme: "wss", Host: "relay.example"}}
	if request := string(root.request("key")); !strings.HasPrefix(request, "GET / HTTP/1.1") {
		t.Errorf("root request = %q", request)
	}
}

func TestPrefixReaderDrainsPrefixThenRest(t *testing.T) {
	buffered := bufio.NewReader(strings.NewReader("prefix"))
	if _, err := buffered.Peek(1); err != nil {
		t.Fatalf("Peek: %v", err)
	}
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	reader := newPrefixReader(buffered, client)
	go func() { _, _ = server.Write([]byte("rest")) }()
	got := make([]byte, len("prefixrest"))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "prefixrest" {
		t.Errorf("joined stream = %q", got)
	}

	cause := errors.New("prefix failed")
	failing := &prefixReader{prefix: websocketErrorReader{err: cause}, rest: strings.NewReader("rest")}
	if _, err := failing.Read(make([]byte, 1)); !errors.Is(err, cause) {
		t.Fatalf("prefix error = %v", err)
	}
}
