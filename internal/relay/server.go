// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/logging"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/protocol"
	"github.com/wojciechpolak/dproxy/internal/securetransport"
	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

const (
	TunnelPath = "/v1/tunnel"
	HealthPath = "/healthz"
)

// ServerOptions supplies the validated configuration and optional test seams.
// Production leaves Identity, Tokens, Resolver, and Dialer at their zero values.
type ServerOptions struct {
	Config   *config.ServerConfig
	Logger   *logging.Logger
	Identity *tunnel.Identity
	Tokens   config.TokenSet
	Resolver policy.Resolver
	Dialer   TargetDialer
}

// Server accepts authenticated dproxy sessions behind a private WSS ingress.
type Server struct {
	config     config.ServerConfig
	logger     *logging.Logger
	identity   *tunnel.Identity
	tokens     config.TokenSet
	checker    policy.Checker
	dialer     TargetDialer
	http       *http.Server
	sessions   chan struct{}
	failures   *authFailureLimiter
	draining   atomic.Bool
	serveMu    sync.Mutex
	serving    bool
	activeMu   sync.Mutex
	active     map[net.Conn]context.CancelFunc
	activeWait sync.WaitGroup
}

// NewServer loads the persistent identity, token set, and DoH resolver unless
// tests supply them explicitly.
func NewServer(options ServerOptions) (*Server, error) {
	if options.Config == nil {
		return nil, errors.New("server configuration is required")
	}
	settings := *options.Config
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	identity := options.Identity
	if identity == nil {
		var err error
		identity, err = tunnel.LoadOrCreateIdentity(settings.IdentityFile)
		if err != nil {
			return nil, err
		}
	}
	tokens := options.Tokens
	if tokens.Len() == 0 {
		var err error
		tokens, err = settings.TokenFile.ReadSet()
		if err != nil {
			return nil, err
		}
	}
	resolver := options.Resolver
	if resolver == nil {
		var err error
		resolver, err = securetransport.NewResolver(securetransport.ResolverOptions{
			URL: settings.DoHURL, Bootstrap: settings.DoHBootstrap, Timeouts: settings.Timeouts,
		})
		if err != nil {
			return nil, err
		}
	}
	dialer := options.Dialer
	if dialer == nil {
		dialer = TCPDialer{}
	}
	logger := options.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	server := &Server{
		config:   settings,
		logger:   logger,
		identity: identity,
		tokens:   tokens,
		checker:  settings.Checker(resolver),
		dialer:   dialer,
		sessions: make(chan struct{}, settings.Limits.MaxSessions),
		failures: newAuthFailureLimiter(),
		active:   make(map[net.Conn]context.CancelFunc),
	}
	server.http = &http.Server{
		Handler:           server,
		ReadHeaderTimeout: settings.Timeouts.Control,
		IdleTimeout:       settings.Timeouts.Control,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return server, nil
}

// IdentityPin is the value operators configure on clients.
func (s *Server) IdentityPin() config.Pin { return s.identity.Pin }

// ListenAndServe binds the configured listener and serves until shutdown.
func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return err
	}
	return s.Serve(listener)
}

// Serve accepts HTTP requests on listener. One Server may be served once.
func (s *Server) Serve(listener net.Listener) error {
	s.serveMu.Lock()
	if s.serving {
		s.serveMu.Unlock()
		return errors.New("remote server is already serving")
	}
	s.serving = true
	s.serveMu.Unlock()
	err := s.http.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeHTTP exposes a private health check and the single tunnel endpoint.
func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == HealthPath && request.URL.RawQuery == "" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.draining.Load() {
			http.Error(writer, "draining", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
		return
	}
	if request.URL.Path != TunnelPath || request.URL.RawQuery != "" {
		http.NotFound(writer, request)
		return
	}
	if s.draining.Load() {
		http.Error(writer, "server is draining", http.StatusServiceUnavailable)
		return
	}
	source := authenticationSource(request)
	if s.failures.blocked(source) {
		http.Error(writer, "too many failed sessions", http.StatusTooManyRequests)
		return
	}
	select {
	case s.sessions <- struct{}{}:
		defer func() { <-s.sessions }()
	default:
		http.Error(writer, "session limit reached", http.StatusServiceUnavailable)
		return
	}
	s.activeWait.Add(1)
	defer s.activeWait.Done()
	websocket, err := tunnel.AcceptWebSocket(writer, request)
	if err != nil {
		return
	}
	ctx, cancel := s.sessionContext()
	s.track(websocket, cancel)
	defer func() {
		s.untrack(websocket)
		cancel()
		_ = websocket.Close()
	}()
	s.handleSession(ctx, websocket, source)
}

func (s *Server) sessionContext() (context.Context, context.CancelFunc) {
	if s.config.Timeouts.MaxLifetime > 0 {
		return context.WithTimeout(context.Background(), s.config.Timeouts.MaxLifetime)
	}
	return context.WithCancel(context.Background())
}

func (s *Server) handleSession(ctx context.Context, websocket net.Conn, source string) {
	inner, _, err := tunnel.AcceptInnerTLS(ctx, websocket, s.identity, s.config.Timeouts.TLSHandshake)
	if err != nil {
		s.logger.Debug("inner TLS rejected", logging.KeyReason, "inner-tls")
		return
	}
	defer func() {
		_ = inner.SetWriteDeadline(time.Now().Add(time.Second))
		_ = inner.Close()
	}()
	if err := inner.SetDeadline(time.Now().Add(s.config.Timeouts.Control)); err != nil {
		return
	}
	encoder := protocol.NewEncoder(inner, s.config.Limits.MaxControlMessageBytes)
	decoder := protocol.NewDecoder(inner, s.config.Limits.MaxControlMessageBytes)

	message, err := decoder.Decode()
	if err != nil {
		s.authenticationFailed(source, "malformed-hello")
		return
	}
	hello, ok := message.(protocol.Hello)
	if !ok || !s.tokens.Contains(hello.Token) {
		s.authenticationFailed(source, "invalid-token")
		return
	}
	s.failures.reset(source)
	if err := encoder.Encode(protocol.HelloOK{Version: protocol.Version1}); err != nil {
		return
	}

	message, err = decoder.Decode()
	if err != nil {
		_ = encoder.Encode(protocol.OpenError{Code: protocol.ErrorMalformed})
		return
	}
	open, ok := message.(protocol.Open)
	if !ok {
		_ = encoder.Encode(protocol.OpenError{Code: protocol.ErrorMalformed})
		return
	}
	addresses, decision := s.checker.Resolve(ctx, open.Destination)
	if !decision.Allowed() {
		_ = encoder.Encode(protocol.OpenError{Code: protocol.ErrorCodeFor(decision.Reason())})
		s.logger.Info("destination refused", logging.KeyReason, decision.Reason(), s.logger.Target(open.Destination.Authority()))
		return
	}
	target, err := s.dialer.Dial(ctx, addresses, open.Destination.Port(), s.config.Timeouts.Dial)
	if err != nil {
		_ = encoder.Encode(protocol.OpenError{Code: protocol.ErrorDialFailed})
		s.logger.Info("target dial failed", logging.KeyReason, "dial-failed", s.logger.Target(open.Destination.Authority()))
		return
	}
	defer func() { _ = target.Close() }()
	if err := encoder.Encode(protocol.OpenOK{}); err != nil {
		return
	}
	if err := inner.SetDeadline(time.Time{}); err != nil {
		return
	}
	s.logger.Info("relay opened", s.logger.Target(open.Destination.Authority()))
	err = Copy(ctx, inner, target, Options{IdleTimeout: s.config.Timeouts.Idle})
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, net.ErrClosed) {
		s.logger.Debug("relay ended", logging.KeyReason, relayEndReason(err))
	}
}

func (s *Server) authenticationFailed(source, reason string) {
	s.failures.record(source)
	s.logger.Warn("authentication failed", logging.KeyReason, reason)
}

func relayEndReason(err error) string {
	if errors.Is(err, ErrIdleTimeout) {
		return "idle-timeout"
	}
	return "io-error"
}

func (s *Server) track(conn net.Conn, cancel context.CancelFunc) {
	s.activeMu.Lock()
	s.active[conn] = cancel
	s.activeMu.Unlock()
}

func (s *Server) untrack(conn net.Conn) {
	s.activeMu.Lock()
	delete(s.active, conn)
	s.activeMu.Unlock()
}

// Shutdown stops accepting sessions, waits for active relays, and forcefully
// cancels only those still running when ctx expires.
func (s *Server) Shutdown(ctx context.Context) error {
	s.draining.Store(true)
	httpErr := s.http.Shutdown(ctx)
	done := make(chan struct{})
	go func() {
		s.activeWait.Wait()
		close(done)
	}()
	select {
	case <-done:
		return httpErr
	case <-ctx.Done():
		s.closeActive()
		<-done
		return fmt.Errorf("remote server shutdown: %w", ctx.Err())
	}
}

func (s *Server) closeActive() {
	s.activeMu.Lock()
	connections := make([]net.Conn, 0, len(s.active))
	cancellations := make([]context.CancelFunc, 0, len(s.active))
	for conn, cancel := range s.active {
		connections = append(connections, conn)
		cancellations = append(cancellations, cancel)
	}
	s.activeMu.Unlock()
	for _, cancel := range cancellations {
		cancel()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
}
