// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/wojciechpolak/dproxy/internal/securetransport"
)

// The client half of the WebSocket opening handshake (RFC 6455 §4.1), written
// out rather than taken from a library: it is one request, one response, and
// four checks, and the product module has no dependencies.
//
// The handshake carries nothing dproxy-specific. No subprotocol is offered and
// no header names this software, because everything that distinguishes this
// connection from any other WebSocket is a fingerprint for no functional gain.
// What identifies the protocol is the ALPN value inside the inner TLS session,
// which the WSS front end cannot read.

// websocketGUID is the constant RFC 6455 mixes into the accept token.
const websocketGUID = "258EAFA5-E914-47DA-95CA-5AB0DC85B11F"

// websocketVersion is the only version RFC 6455 defines.
const websocketVersion = "13"

// responseHeaderLimit bounds the upgrade response. A relay that answers with
// something larger is not answering with a handshake.
const responseHeaderLimit = 64 << 10

// Upgrader performs the opening handshake over an established connection.
//
// The connection must already be the TLS 1.3 session that
// securetransport.SecureDialer produced: this type adds no transport security
// and checks none, it only turns a byte stream into an accepted WebSocket.
type Upgrader struct {
	// URL is the wss:// endpoint. Its host becomes the Host header and its
	// path the request target.
	URL *url.URL
	// Timeout bounds the whole exchange.
	Timeout time.Duration
	// entropy generates the nonce. Tests set it; production leaves it nil
	// and gets crypto/rand.
	entropy io.Reader
}

// AcceptWebSocket validates and accepts the server side of the opening
// handshake. The caller must reject unrelated paths before calling it.
func AcceptWebSocket(writer http.ResponseWriter, request *http.Request) (*WebSocketConn, error) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return nil, errors.New("WebSocket upgrade method is not GET")
	}
	if !headerHasToken(request.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
		http.Error(writer, "WebSocket upgrade required", http.StatusUpgradeRequired)
		return nil, errors.New("request is not a WebSocket upgrade")
	}
	if request.Header.Get("Sec-WebSocket-Version") != websocketVersion {
		writer.Header().Set("Sec-WebSocket-Version", websocketVersion)
		http.Error(writer, "unsupported WebSocket version", http.StatusBadRequest)
		return nil, errors.New("request does not use WebSocket version 13")
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decodedKey) != 16 || base64.StdEncoding.EncodeToString(decodedKey) != key {
		http.Error(writer, "invalid WebSocket key", http.StatusBadRequest)
		return nil, errors.New("request carries an invalid WebSocket key")
	}
	if request.Header.Get("Sec-WebSocket-Protocol") != "" || request.Header.Get("Sec-WebSocket-Extensions") != "" {
		http.Error(writer, "WebSocket extensions are not supported", http.StatusBadRequest)
		return nil, errors.New("request offered a WebSocket subprotocol or extension")
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "WebSocket upgrade unavailable", http.StatusInternalServerError)
		return nil, errors.New("HTTP server does not support connection hijacking")
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack WebSocket connection: %w", err)
	}
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptToken(key) + "\r\n\r\n"
	if _, err := io.WriteString(buffered, response); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write WebSocket upgrade response: %w", err)
	}
	if err := buffered.Flush(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("flush WebSocket upgrade response: %w", err)
	}
	return NewServerWebSocketConn(conn, buffered.Reader), nil
}

// Upgrade sends the request, validates the response, and returns a reader
// positioned at the first WebSocket byte.
//
// The reader is returned rather than the connection because the response may
// arrive in the same read as the bytes after it: discarding the buffer would
// discard the beginning of the inner TLS handshake.
func (u *Upgrader) Upgrade(ctx context.Context, conn net.Conn) (*bufio.Reader, error) {
	if u.URL == nil {
		return nil, securetransport.Fail(securetransport.FailureHandshake, errors.New("no relay URL"))
	}
	key, err := u.nonce()
	if err != nil {
		return nil, securetransport.Fail(securetransport.FailureHandshake, err)
	}

	if u.Timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(u.Timeout)); err != nil {
			return nil, securetransport.Fail(securetransport.FailureHandshake, err)
		}
	}
	// A cancelled context has to reach a connection that is already blocked
	// in a read, and a deadline in the past is the only thing that does.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Unix(1, 0))
	})
	defer func() {
		stop()
		_ = conn.SetDeadline(time.Time{})
	}()

	if _, err := conn.Write(u.request(key)); err != nil {
		return nil, securetransport.Fail(securetransport.FailureHandshake, fmt.Errorf("send the upgrade request: %w", err))
	}

	reader := bufio.NewReader(io.LimitReader(conn, responseHeaderLimit))
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, securetransport.Fail(securetransport.FailureHandshake, fmt.Errorf("read the upgrade response: %w", err))
	}
	// The body of a non-101 response is never read: nothing in it is
	// trusted, and reading it would only give a hostile endpoint somewhere
	// to put bytes.
	defer func() { _ = response.Body.Close() }()
	if err := validateUpgrade(response, key); err != nil {
		return nil, err
	}
	// Reading resumes on the connection itself; the limit existed only to
	// bound the header exchange.
	return bufio.NewReaderSize(newPrefixReader(reader, conn), responseHeaderLimit), nil
}

// nonce generates the Sec-WebSocket-Key value.
func (u *Upgrader) nonce() (string, error) {
	source := u.entropy
	if source == nil {
		source = rand.Reader
	}
	var value [16]byte
	if _, err := io.ReadFull(source, value[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(value[:]), nil
}

// request builds the opening handshake request.
func (u *Upgrader) request(key string) []byte {
	target := u.URL.RequestURI()
	if target == "" {
		target = "/"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "GET %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&builder, "Host: %s\r\n", u.URL.Host)
	builder.WriteString("Upgrade: websocket\r\n")
	builder.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&builder, "Sec-WebSocket-Key: %s\r\n", key)
	fmt.Fprintf(&builder, "Sec-WebSocket-Version: %s\r\n", websocketVersion)
	builder.WriteString("\r\n")
	return []byte(builder.String())
}

// validateUpgrade checks the response against the request that was sent.
//
// A redirect is called out separately: following one during establishment
// would let whatever answered choose the endpoint, which is the one decision
// the pinned configuration is supposed to own.
func validateUpgrade(response *http.Response, key string) error {
	if response.StatusCode != http.StatusSwitchingProtocols {
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return securetransport.Fail(securetransport.FailureRedirect,
				fmt.Errorf("the relay answered the upgrade with HTTP status %d", response.StatusCode))
		}
		return securetransport.Fail(securetransport.FailureHandshake,
			fmt.Errorf("the relay answered the upgrade with HTTP status %d", response.StatusCode))
	}
	if !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
		return securetransport.Fail(securetransport.FailureHandshake,
			fmt.Errorf("the relay upgraded to %q", response.Header.Get("Upgrade")))
	}
	if !headerHasToken(response.Header.Get("Connection"), "upgrade") {
		return securetransport.Fail(securetransport.FailureHandshake,
			fmt.Errorf("the relay answered with Connection: %q", response.Header.Get("Connection")))
	}
	if got := response.Header.Get("Sec-WebSocket-Accept"); got != acceptToken(key) {
		return securetransport.Fail(securetransport.FailureHandshake,
			errors.New("the relay did not prove it read the handshake key"))
	}
	// Nothing was offered, so nothing may be selected: an extension or a
	// subprotocol here would change the framing this build implements.
	if value := response.Header.Get("Sec-WebSocket-Extensions"); value != "" {
		return securetransport.Fail(securetransport.FailureHandshake,
			fmt.Errorf("the relay selected the unoffered extension %q", value))
	}
	if value := response.Header.Get("Sec-WebSocket-Protocol"); value != "" {
		return securetransport.Fail(securetransport.FailureHandshake,
			fmt.Errorf("the relay selected the unoffered subprotocol %q", value))
	}
	return nil
}

// acceptToken computes the Sec-WebSocket-Accept value for a key.
//
// SHA-1 is not a security choice here: RFC 6455 fixes it, and the token proves
// only that the peer parsed the handshake rather than replaying a cached
// response.
func acceptToken(key string) string {
	sum := sha1.Sum([]byte(key + websocketGUID)) // #nosec G401 -- fixed by RFC 6455
	return base64.StdEncoding.EncodeToString(sum[:])
}

// headerHasToken reports whether a comma-separated header lists a token.
func headerHasToken(value, token string) bool {
	for _, candidate := range strings.Split(value, ",") {
		if strings.EqualFold(textproto.TrimString(candidate), token) {
			return true
		}
	}
	return false
}

// prefixReader reads what a bufio.Reader already buffered before continuing on
// the connection, so the bytes that arrived with the response are not lost.
type prefixReader struct {
	prefix io.Reader
	rest   io.Reader
}

// newPrefixReader joins a buffered prefix to the stream it came from.
func newPrefixReader(buffered *bufio.Reader, conn net.Conn) io.Reader {
	if buffered.Buffered() == 0 {
		return conn
	}
	return &prefixReader{prefix: io.LimitReader(buffered, int64(buffered.Buffered())), rest: conn}
}

// Read drains the prefix first.
func (r *prefixReader) Read(buffer []byte) (int, error) {
	if r.prefix != nil {
		count, err := r.prefix.Read(buffer)
		if err == nil || errors.Is(err, io.EOF) {
			if count > 0 {
				return count, nil
			}
			r.prefix = nil
		} else {
			return count, err
		}
	}
	return r.rest.Read(buffer)
}
