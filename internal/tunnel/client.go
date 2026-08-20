// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/protocol"
	"github.com/wojciechpolak/dproxy/internal/securetransport"
)

// ErrAuthenticationFailed reports that the remote closed or rejected the
// session while answering HELLO. The local proxy never asks its HTTP client
// for credentials because this token belongs only to dproxy.
var ErrAuthenticationFailed = errors.New("remote dproxy authentication failed")

// RemoteOpenError reports a typed OPEN_ERROR from the remote. The code is safe
// to log and maps to an HTTP proxy response without using peer-supplied prose.
type RemoteOpenError struct {
	Code protocol.ErrorCode
}

func (e *RemoteOpenError) Error() string {
	return "remote dproxy refused OPEN: " + e.Code.String()
}

// StreamDialer establishes the front-end-visible WebSocket byte stream. It is
// a test seam; production uses the DoH, TLS 1.3, ECH, and WSS implementation
// built by NewClient.
type StreamDialer interface {
	DialStream(ctx context.Context) (net.Conn, error)
}

// ClientOptions supplies validated client configuration and optional test
// seams. Production leaves Token and StreamDialer at their zero values.
type ClientOptions struct {
	Config       *config.ClientConfig
	Token        config.Token
	StreamDialer StreamDialer
}

// Client opens one authenticated inner tunnel per destination.
type Client struct {
	config config.ClientConfig
	token  config.Token
	stream StreamDialer
}

// NewClient loads the client token and constructs the mandatory outer
// transport. It performs no network I/O until Open is called.
func NewClient(options ClientOptions) (*Client, error) {
	if options.Config == nil {
		return nil, errors.New("client configuration is required")
	}
	settings := *options.Config
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	token := options.Token
	if token.IsZero() {
		var err error
		token, err = settings.TokenFile.Read()
		if err != nil {
			return nil, err
		}
	}
	stream := options.StreamDialer
	if stream == nil {
		resolver, err := securetransport.NewResolver(securetransport.ResolverOptions{
			URL:       settings.DoHURL,
			Bootstrap: settings.DoHBootstrap,
			Timeouts:  settings.Timeouts,
		})
		if err != nil {
			return nil, err
		}
		stream = &webSocketStreamDialer{
			endpoint: settings.RelayURL,
			secure: &securetransport.SecureDialer{
				Resolver: resolver,
				ECH:      settings.ECH,
				Timeouts: settings.Timeouts,
			},
			timeout: settings.Timeouts.Control,
		}
	}
	return &Client{config: settings, token: token, stream: stream}, nil
}

// Open establishes WSS, pinned inner TLS, HELLO, and OPEN in that order. The
// returned connection is positioned at the first raw application byte.
func (c *Client) Open(ctx context.Context, destination policy.Destination) (net.Conn, error) {
	if c == nil || c.stream == nil {
		return nil, errors.New("tunnel client is not configured")
	}
	if decision := c.config.Checker().CheckDestination(destination); !decision.Allowed() {
		return nil, &RemoteOpenError{Code: protocol.ErrorCodeFor(decision.Reason())}
	}
	stream, err := c.stream.DialStream(ctx)
	if err != nil {
		return nil, err
	}
	inner, _, err := DialInnerTLS(ctx, stream, c.config.ServerPin, c.config.Timeouts.TLSHandshake)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = stream.Close()
			_ = inner.Close()
		}
	}()
	if err := inner.SetDeadline(time.Now().Add(c.config.Timeouts.Control)); err != nil {
		return nil, fmt.Errorf("set tunnel control deadline: %w", err)
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = inner.SetDeadline(time.Unix(1, 0))
	})
	defer stopCancellation()
	encoder := protocol.NewEncoder(inner, config.DefaultLimits().MaxControlMessageBytes)
	decoder := protocol.NewDecoder(inner, config.DefaultLimits().MaxControlMessageBytes)
	if err := encoder.Encode(protocol.Hello{Version: protocol.Version1, Token: c.token}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("send HELLO: %w", err)
	}
	message, err := decoder.Decode()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err == io.EOF {
			return nil, fmt.Errorf("%w: %w", ErrAuthenticationFailed, err)
		}
		return nil, fmt.Errorf("receive HELLO response: %w", err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	helloOK, accepted := message.(protocol.HelloOK)
	if !accepted || helloOK.Version != protocol.Version1 {
		return nil, fmt.Errorf("unexpected %s while awaiting HELLO response", message.Type())
	}
	if err := encoder.Encode(protocol.Open{Destination: destination}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("send OPEN: %w", err)
	}
	message, err = decoder.Decode()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("receive OPEN response: %w", err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	switch response := message.(type) {
	case protocol.OpenOK:
		stopCancellation()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err := inner.SetDeadline(time.Time{}); err != nil {
			return nil, fmt.Errorf("clear tunnel control deadline: %w", err)
		}
		ok = true
		return inner, nil
	case protocol.OpenError:
		return nil, &RemoteOpenError{Code: response.Code}
	default:
		return nil, fmt.Errorf("unexpected %s while awaiting OPEN response", message.Type())
	}
}

type webSocketStreamDialer struct {
	endpoint *url.URL
	secure   *securetransport.SecureDialer
	timeout  time.Duration
}

func (d *webSocketStreamDialer) DialStream(ctx context.Context) (net.Conn, error) {
	port := policy.AllowedPort
	if text := d.endpoint.Port(); text != "" {
		value, err := strconv.ParseUint(text, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("relay port: %w", err)
		}
		port = uint16(value)
	}
	raw, _, err := d.secure.DialPort(ctx, d.endpoint.Hostname(), port)
	if err != nil {
		return nil, err
	}
	reader, err := (&Upgrader{URL: d.endpoint, Timeout: d.timeout}).Upgrade(ctx, raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return NewClientWebSocketConn(raw, reader), nil
}
