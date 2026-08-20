// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/protocol"
)

type streamDialerFunc func(context.Context) (net.Conn, error)

func (f streamDialerFunc) DialStream(ctx context.Context) (net.Conn, error) {
	return f(ctx)
}

func testClientConfig(t *testing.T, pin config.Pin) *config.ClientConfig {
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
	timeouts := config.DefaultTimeouts()
	timeouts.TLSHandshake = time.Second
	timeouts.Control = time.Second
	return &config.ClientConfig{
		Listen:       config.DefaultClientListen,
		RelayURL:     relayURL,
		ServerPin:    pin,
		TokenFile:    "unused-token-file",
		DoHURL:       dohURL,
		DoHBootstrap: config.DefaultDoHBootstrap(dohURL),
		ECH:          config.ECHRequired,
		Allowlist:    allowlist,
		Timeouts:     timeouts,
		Log:          config.DefaultLogOptions(),
	}
}

func testToken(t *testing.T) config.Token {
	t.Helper()
	token, err := config.NewToken([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	return token
}

func testDestination(t *testing.T) policy.Destination {
	t.Helper()
	destination, err := policy.ParseAuthority("api.openai.com:443")
	if err != nil {
		t.Fatalf("ParseAuthority: %v", err)
	}
	return destination
}

func TestClientAuthenticatesOpensAndReturnsRawStream(t *testing.T) {
	identity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	token := testToken(t)
	serverDone := make(chan error, 1)
	dialer := streamDialerFunc(func(context.Context) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		go func() {
			inner, _, err := AcceptInnerTLS(t.Context(), serverSide, identity, time.Second)
			if err != nil {
				serverDone <- err
				return
			}
			defer func() { _ = serverSide.Close() }()
			encoder := protocol.NewEncoder(inner, config.DefaultLimits().MaxControlMessageBytes)
			decoder := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes)
			message, err := decoder.Decode()
			if err != nil {
				serverDone <- err
				return
			}
			hello, ok := message.(protocol.Hello)
			if !ok || !hello.Token.Equal(token) {
				serverDone <- errors.New("unexpected HELLO")
				return
			}
			if err := encoder.Encode(protocol.HelloOK{Version: protocol.Version1}); err != nil {
				serverDone <- err
				return
			}
			message, err = decoder.Decode()
			if err != nil {
				serverDone <- err
				return
			}
			if _, ok := message.(protocol.Open); !ok {
				serverDone <- errors.New("unexpected OPEN")
				return
			}
			if err := encoder.Encode(protocol.OpenOK{}); err != nil {
				serverDone <- err
				return
			}
			buffer := make([]byte, 4)
			if _, err := io.ReadFull(inner, buffer); err != nil {
				serverDone <- err
				return
			}
			_, err = inner.Write(buffer)
			serverDone <- err
		}()
		return clientSide, nil
	})
	client, err := NewClient(ClientOptions{
		Config: testClientConfig(t, identity.Pin), Token: token, StreamDialer: dialer,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	stream, err := client.Open(t.Context(), testDestination(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = stream.Close() }()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(stream, response); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(response) != "ping" {
		t.Fatalf("response = %q, want ping", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestClientClassifiesAuthenticationFailure(t *testing.T) {
	identity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	dialer := streamDialerFunc(func(context.Context) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		go func() {
			inner, _, err := AcceptInnerTLS(t.Context(), serverSide, identity, time.Second)
			if err == nil {
				_, _ = protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes).Decode()
				_ = inner.Close()
			}
		}()
		return clientSide, nil
	})
	client, err := NewClient(ClientOptions{
		Config: testClientConfig(t, identity.Pin), Token: testToken(t), StreamDialer: dialer,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Open(t.Context(), testDestination(t)); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("Open error = %v, want ErrAuthenticationFailed", err)
	}
}

func TestClientReturnsRemoteOpenError(t *testing.T) {
	identity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	dialer := streamDialerFunc(func(context.Context) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		go func() {
			inner, _, err := AcceptInnerTLS(t.Context(), serverSide, identity, time.Second)
			if err != nil {
				return
			}
			defer func() { _ = serverSide.Close() }()
			encoder := protocol.NewEncoder(inner, config.DefaultLimits().MaxControlMessageBytes)
			decoder := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes)
			_, _ = decoder.Decode()
			_ = encoder.Encode(protocol.HelloOK{Version: protocol.Version1})
			_, _ = decoder.Decode()
			_ = encoder.Encode(protocol.OpenError{Code: protocol.ErrorDialFailed})
		}()
		return clientSide, nil
	})
	client, err := NewClient(ClientOptions{
		Config: testClientConfig(t, identity.Pin), Token: testToken(t), StreamDialer: dialer,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Open(t.Context(), testDestination(t))
	var remote *RemoteOpenError
	if !errors.As(err, &remote) || remote.Code != protocol.ErrorDialFailed {
		t.Fatalf("Open error = %v, want remote dial failure", err)
	}
}

func TestClientDoesNotSendHelloAfterPinMismatch(t *testing.T) {
	serverIdentity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "server.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity(server): %v", err)
	}
	wrongIdentity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "wrong.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity(wrong): %v", err)
	}
	observed := make(chan protocol.Message, 1)
	dialer := streamDialerFunc(func(context.Context) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		go func() {
			defer func() { _ = serverSide.Close() }()
			inner, _, err := AcceptInnerTLS(t.Context(), serverSide, serverIdentity, time.Second)
			if err != nil {
				observed <- nil
				return
			}
			_ = inner.SetReadDeadline(time.Now().Add(time.Second))
			message, _ := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes).Decode()
			observed <- message
		}()
		return clientSide, nil
	})
	client, err := NewClient(ClientOptions{
		Config: testClientConfig(t, wrongIdentity.Pin), Token: testToken(t), StreamDialer: dialer,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Open(t.Context(), testDestination(t)); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("Open error = %v, want ErrPinMismatch", err)
	}
	select {
	case message := <-observed:
		if message != nil {
			t.Fatalf("server received %s after pin mismatch", message.Type())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after pin mismatch")
	}
}

func TestClientControlExchangeHonoursTimeout(t *testing.T) {
	client, controlRead, serverDone := clientWithStalledControlServer(t, 100*time.Millisecond, false)
	_, err := client.Open(t.Context(), testDestination(t))
	if controlErr := <-controlRead; controlErr != nil {
		t.Fatalf("server did not read HELLO: %v", controlErr)
	}
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		t.Fatalf("Open error = %v, want a network timeout", err)
	}
	if errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("control timeout was classified as authentication failure: %v", err)
	}
	waitForControlServer(t, serverDone)
}

func TestClientControlExchangeHonoursCancellation(t *testing.T) {
	client, controlRead, serverDone := clientWithStalledControlServer(t, 2*time.Second, true)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := client.Open(ctx, testDestination(t))
		result <- err
	}()
	if controlErr := <-controlRead; controlErr != nil {
		t.Fatalf("server did not read OPEN: %v", controlErr)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Open error = %v, want context.Canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancellation waited for the two-second control timeout")
	}
	waitForControlServer(t, serverDone)
}

func clientWithStalledControlServer(
	t *testing.T,
	controlTimeout time.Duration,
	stallAfterOpen bool,
) (*Client, <-chan error, <-chan error) {
	t.Helper()
	identity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	controlRead := make(chan error, 1)
	serverDone := make(chan error, 1)
	dialer := streamDialerFunc(func(context.Context) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		go func() {
			defer func() { _ = serverSide.Close() }()
			inner, _, err := AcceptInnerTLS(t.Context(), serverSide, identity, time.Second)
			if err != nil {
				controlRead <- err
				serverDone <- err
				return
			}
			decoder := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes)
			message, err := decoder.Decode()
			if err == nil {
				if _, ok := message.(protocol.Hello); !ok {
					err = errors.New("first control message is not HELLO")
				}
			}
			if err == nil && stallAfterOpen {
				encoder := protocol.NewEncoder(inner, config.DefaultLimits().MaxControlMessageBytes)
				err = encoder.Encode(protocol.HelloOK{Version: protocol.Version1})
				if err == nil {
					message, err = decoder.Decode()
				}
				if err == nil {
					if _, ok := message.(protocol.Open); !ok {
						err = errors.New("second control message is not OPEN")
					}
				}
			}
			controlRead <- err
			if err != nil {
				serverDone <- err
				return
			}
			var buffer [1]byte
			_, err = inner.Read(buffer[:])
			serverDone <- err
		}()
		return clientSide, nil
	})
	settings := testClientConfig(t, identity.Pin)
	settings.Timeouts.Control = controlTimeout
	client, err := NewClient(ClientOptions{Config: settings, Token: testToken(t), StreamDialer: dialer})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client, controlRead, serverDone
}

func waitForControlServer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control server did not stop after the client closed")
	}
}

func TestNewClientAndOpenRejectInvalidSetupBeforeNetwork(t *testing.T) {
	if _, err := NewClient(ClientOptions{}); err == nil {
		t.Fatal("NewClient accepted no configuration")
	}
	invalid := testClientConfig(t, config.Pin{})
	if _, err := NewClient(ClientOptions{Config: invalid, Token: testToken(t)}); err == nil {
		t.Fatal("NewClient accepted invalid configuration")
	}
	settings := testClientConfig(t, config.PinFromSPKI([]byte("server")))
	settings.TokenFile = config.TokenFile(filepath.Join(t.TempDir(), "missing"))
	if _, err := NewClient(ClientOptions{Config: settings}); err == nil {
		t.Fatal("NewClient accepted a missing token file")
	}
	production, err := NewClient(ClientOptions{Config: settings, Token: testToken(t)})
	if err != nil {
		t.Fatalf("NewClient production transport: %v", err)
	}
	if _, ok := production.stream.(*webSocketStreamDialer); !ok {
		t.Fatalf("production stream dialer = %T", production.stream)
	}

	var nilClient *Client
	if _, err := nilClient.Open(t.Context(), testDestination(t)); err == nil {
		t.Fatal("nil client opened a tunnel")
	}
	if _, err := (&Client{}).Open(t.Context(), testDestination(t)); err == nil {
		t.Fatal("unconfigured client opened a tunnel")
	}

	dialed := false
	client, err := NewClient(ClientOptions{
		Config: settings, Token: testToken(t),
		StreamDialer: streamDialerFunc(func(context.Context) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		}),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	denied, err := policy.ParseAuthority("example.org:443")
	if err != nil {
		t.Fatalf("ParseAuthority: %v", err)
	}
	if _, err := client.Open(t.Context(), denied); err == nil {
		t.Fatal("client opened a non-allowlisted destination")
	}
	if dialed {
		t.Fatal("policy refusal reached the stream dialer")
	}
	dialFailure := errors.New("outer transport failed")
	client.stream = streamDialerFunc(func(context.Context) (net.Conn, error) { return nil, dialFailure })
	if _, err := client.Open(t.Context(), testDestination(t)); !errors.Is(err, dialFailure) {
		t.Fatalf("stream dial error = %v", err)
	}
	if got := (&RemoteOpenError{Code: protocol.ErrorInternal}).Error(); got == "" {
		t.Fatal("RemoteOpenError has no message")
	}
}

func TestWebSocketStreamDialerRejectsInvalidPort(t *testing.T) {
	endpoint := &url.URL{Scheme: "wss", Host: "relay.example:70000", Path: "/v1/tunnel"}
	dialer := &webSocketStreamDialer{endpoint: endpoint}
	if _, err := dialer.DialStream(t.Context()); err == nil {
		t.Fatal("DialStream accepted an out-of-range relay port")
	}
}

func TestClientRejectsOutOfOrderControlResponses(t *testing.T) {
	tests := []struct {
		name     string
		response protocol.Message
		raw      []byte
	}{
		{name: "OPEN before HELLO_OK", response: protocol.OpenOK{}},
		{name: "wrong HELLO version", raw: []byte{0, 0, 0, 2, byte(protocol.MessageHelloOK), 9}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
			if err != nil {
				t.Fatalf("LoadOrCreateIdentity: %v", err)
			}
			dialer := streamDialerFunc(func(context.Context) (net.Conn, error) {
				clientSide, serverSide := net.Pipe()
				go func() {
					inner, _, err := AcceptInnerTLS(t.Context(), serverSide, identity, time.Second)
					if err == nil {
						_, _ = protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes).Decode()
						if test.response != nil {
							_ = protocol.NewEncoder(inner, config.DefaultLimits().MaxControlMessageBytes).Encode(test.response)
						} else {
							_, _ = inner.Write(test.raw)
						}
						_ = inner.Close()
					}
				}()
				return clientSide, nil
			})
			client, err := NewClient(ClientOptions{
				Config: testClientConfig(t, identity.Pin), Token: testToken(t), StreamDialer: dialer,
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if _, err := client.Open(t.Context(), testDestination(t)); err == nil {
				t.Fatal("Open accepted an out-of-order control response")
			}
		})
	}
}
