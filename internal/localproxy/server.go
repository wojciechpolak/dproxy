// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package localproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/logging"
	"github.com/wojciechpolak/dproxy/internal/policy"
	"github.com/wojciechpolak/dproxy/internal/protocol"
	"github.com/wojciechpolak/dproxy/internal/relay"
	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

// TunnelOpener establishes one complete remote tunnel for a checked
// destination.
type TunnelOpener interface {
	Open(ctx context.Context, destination policy.Destination) (net.Conn, error)
}

// ServerOptions supplies client configuration and optional test seams.
// Production leaves Opener nil.
type ServerOptions struct {
	Config *config.ClientConfig
	Logger *logging.Logger
	Opener TunnelOpener
}

// Server accepts loopback HTTP/1.1 CONNECT requests.
type Server struct {
	config     config.ClientConfig
	logger     *logging.Logger
	checker    policy.Checker
	opener     TunnelOpener
	http       *http.Server
	draining   atomic.Bool
	serveMu    sync.Mutex
	serving    bool
	activeMu   sync.Mutex
	active     map[*activeSession]struct{}
	activeZero chan struct{}
}

type activeSession struct {
	cancel context.CancelFunc
	conn   net.Conn
}

// NewServer validates the configuration and constructs the remote tunnel
// client unless a test opener was supplied.
func NewServer(options ServerOptions) (*Server, error) {
	if options.Config == nil {
		return nil, errors.New("client configuration is required")
	}
	settings := *options.Config
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	opener := options.Opener
	if opener == nil {
		client, err := tunnel.NewClient(tunnel.ClientOptions{Config: &settings})
		if err != nil {
			return nil, err
		}
		opener = client
	}
	logger := options.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	server := &Server{
		config:     settings,
		logger:     logger,
		checker:    settings.Checker(),
		opener:     opener,
		active:     make(map[*activeSession]struct{}),
		activeZero: closedChannel(),
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

// ListenAndServe binds the configured loopback listener and serves until
// shutdown.
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
		return errors.New("local proxy is already serving")
	}
	s.serving = true
	s.serveMu.Unlock()
	err := s.http.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeHTTP validates one CONNECT request, opens one tunnel, and then relays
// raw bytes. It sends no success response until the remote has accepted OPEN.
func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if s.draining.Load() {
		writeProxyError(writer, http.StatusServiceUnavailable, "proxy is shutting down")
		return
	}
	if request.Method != http.MethodConnect {
		writer.Header().Set("Allow", http.MethodConnect)
		writeProxyError(writer, http.StatusMethodNotAllowed, "CONNECT required")
		return
	}
	if request.ProtoMajor != 1 || request.ProtoMinor != 1 {
		writeProxyError(writer, http.StatusHTTPVersionNotSupported, "HTTP/1.1 required")
		return
	}
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		writeProxyError(writer, http.StatusBadRequest, "CONNECT request body is not permitted")
		return
	}
	destination, decision := s.checker.CheckAuthority(request.RequestURI)
	if !decision.Allowed() {
		status := http.StatusForbidden
		if decision.Reason() == policy.DenyMalformedAuthority {
			status = http.StatusBadRequest
		}
		s.logger.Info("CONNECT refused", logging.KeyReason, decision.Reason())
		writeProxyError(writer, status, "destination refused")
		return
	}

	ctx, cancel := context.WithCancel(request.Context())
	session := &activeSession{cancel: cancel}
	s.track(session)
	defer func() {
		s.untrack(session)
		cancel()
	}()

	remote, err := s.opener.Open(ctx, destination)
	if err != nil {
		status, reason := proxyStatus(err)
		s.logger.Info("tunnel establishment failed", logging.KeyReason, reason, s.logger.Target(destination.Authority()))
		writeProxyError(writer, status, http.StatusText(status))
		return
	}
	defer func() { _ = remote.Close() }()

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		writeProxyError(writer, http.StatusInternalServerError, "connection takeover unavailable")
		return
	}
	local, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	s.setConnection(session, local)
	defer func() { _ = local.Close() }()
	if _, err := io.WriteString(buffered, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	s.logger.Info("tunnel opened", s.logger.Target(destination.Authority()))
	stream := newBufferedConn(local, buffered.Reader)
	err = relay.Copy(ctx, stream, remote, relay.Options{
		IdleTimeout: s.config.Timeouts.Idle,
		MaxLifetime: s.config.Timeouts.MaxLifetime,
	})
	if err != nil && !expectedRelayEnd(err) {
		s.logger.Debug("local relay ended", logging.KeyReason, localRelayEndReason(err), s.logger.Target(destination.Authority()))
	}
}

func writeProxyError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Connection", "close")
	http.Error(writer, message, status)
}

func proxyStatus(err error) (int, string) {
	if errors.Is(err, context.DeadlineExceeded) || timeoutError(err) {
		return http.StatusGatewayTimeout, "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return http.StatusServiceUnavailable, "canceled"
	}
	if errors.Is(err, tunnel.ErrAuthenticationFailed) {
		return http.StatusBadGateway, "authentication-failed"
	}
	var remote *tunnel.RemoteOpenError
	if errors.As(err, &remote) {
		switch remote.Code {
		case protocol.ErrorForbiddenDestination, protocol.ErrorAddressRejected:
			return http.StatusForbidden, remote.Code.String()
		case protocol.ErrorLimitExceeded:
			return http.StatusServiceUnavailable, remote.Code.String()
		default:
			return http.StatusBadGateway, remote.Code.String()
		}
	}
	return http.StatusBadGateway, "tunnel-failed"
}

func timeoutError(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func expectedRelayEnd(err error) bool {
	return err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, relay.ErrIdleTimeout)
}

func localRelayEndReason(err error) string {
	if errors.Is(err, relay.ErrIdleTimeout) {
		return "idle-timeout"
	}
	return "io-error"
}

func (s *Server) track(session *activeSession) {
	s.activeMu.Lock()
	if len(s.active) == 0 {
		s.activeZero = make(chan struct{})
	}
	s.active[session] = struct{}{}
	s.activeMu.Unlock()
}

func (s *Server) setConnection(session *activeSession, conn net.Conn) {
	s.activeMu.Lock()
	if _, exists := s.active[session]; exists {
		session.conn = conn
	}
	s.activeMu.Unlock()
}

func (s *Server) untrack(session *activeSession) {
	s.activeMu.Lock()
	delete(s.active, session)
	if len(s.active) == 0 {
		close(s.activeZero)
	}
	s.activeMu.Unlock()
}

// Shutdown stops accepting CONNECT requests, waits for active tunnels, and
// cancels the remaining sessions if ctx expires.
func (s *Server) Shutdown(ctx context.Context) error {
	s.draining.Store(true)
	httpErr := s.http.Shutdown(ctx)
	done := s.activeDone()
	select {
	case <-done:
		return httpErr
	case <-ctx.Done():
		s.closeActive()
		<-done
		return fmt.Errorf("local proxy shutdown: %w", ctx.Err())
	}
}

func (s *Server) activeDone() <-chan struct{} {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	return s.activeZero
}

func closedChannel() chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func (s *Server) closeActive() {
	s.activeMu.Lock()
	type closingSession struct {
		cancel context.CancelFunc
		conn   net.Conn
	}
	sessions := make([]closingSession, 0, len(s.active))
	for session := range s.active {
		sessions = append(sessions, closingSession{cancel: session.cancel, conn: session.conn})
	}
	s.activeMu.Unlock()
	for _, session := range sessions {
		session.cancel()
		if session.conn != nil {
			_ = session.conn.Close()
		}
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func newBufferedConn(conn net.Conn, reader *bufio.Reader) net.Conn {
	if reader == nil || reader.Buffered() == 0 {
		return conn
	}
	return &bufferedConn{Conn: conn, reader: reader}
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

func (c *bufferedConn) CloseRead() error {
	if closer, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return nil
}

func (c *bufferedConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

var _ net.Conn = (*bufferedConn)(nil)
