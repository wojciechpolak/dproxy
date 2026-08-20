// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestCopyRelaysBothDirections(t *testing.T) {
	leftClient, leftRelay := tcpPair(t)
	rightRelay, rightServer := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- Copy(t.Context(), leftRelay, rightRelay, Options{IdleTimeout: time.Second}) }()

	assertRelayed(t, leftClient, rightServer, "left to right")
	assertRelayed(t, rightServer, leftClient, "right to left")
	if err := leftClient.Close(); err != nil {
		t.Fatalf("close left: %v", err)
	}
	if err := rightServer.Close(); err != nil {
		t.Fatalf("close right: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Copy: %v", err)
	}
}

func TestCopyPropagatesHalfClose(t *testing.T) {
	leftClient, leftRelay := tcpPair(t)
	rightRelay, rightServer := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- Copy(t.Context(), leftRelay, rightRelay, Options{IdleTimeout: time.Second}) }()

	if _, err := leftClient.Write([]byte("request")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := leftClient.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	request, err := io.ReadAll(rightServer)
	if err != nil || string(request) != "request" {
		t.Fatalf("request = %q, %v", request, err)
	}
	if _, err := rightServer.Write([]byte("response")); err != nil {
		t.Fatalf("write response: %v", err)
	}
	if err := rightServer.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	response, err := io.ReadAll(leftClient)
	if err != nil || string(response) != "response" {
		t.Fatalf("response = %q, %v", response, err)
	}
	_ = leftClient.Close()
	_ = rightServer.Close()
	if err := <-done; err != nil {
		t.Fatalf("Copy: %v", err)
	}
}

func TestCopyStopsOnCancellationAndTimeouts(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		leftClient, leftRelay := net.Pipe()
		rightRelay, rightServer := net.Pipe()
		defer func() { _ = leftClient.Close() }()
		defer func() { _ = rightServer.Close() }()
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- Copy(ctx, leftRelay, rightRelay, Options{}) }()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("Copy = %v, want context.Canceled", err)
		}
	})
	t.Run("idle", func(t *testing.T) {
		leftClient, leftRelay := net.Pipe()
		rightRelay, rightServer := net.Pipe()
		defer func() { _ = leftClient.Close() }()
		defer func() { _ = rightServer.Close() }()
		err := Copy(t.Context(), leftRelay, rightRelay, Options{IdleTimeout: 30 * time.Millisecond})
		if !errors.Is(err, ErrIdleTimeout) {
			t.Fatalf("Copy = %v, want ErrIdleTimeout", err)
		}
	})
	t.Run("lifetime", func(t *testing.T) {
		leftClient, leftRelay := net.Pipe()
		rightRelay, rightServer := net.Pipe()
		defer func() { _ = leftClient.Close() }()
		defer func() { _ = rightServer.Close() }()
		err := Copy(t.Context(), leftRelay, rightRelay, Options{MaxLifetime: 30 * time.Millisecond})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Copy = %v, want context deadline", err)
		}
	})
}

func assertRelayed(t *testing.T, writer, reader net.Conn, text string) {
	t.Helper()
	written := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, text)
		written <- err
	}()
	buffer := make([]byte, len(text))
	if _, err := io.ReadFull(reader, buffer); err != nil {
		t.Fatalf("read %q: %v", text, err)
	}
	if err := <-written; err != nil {
		t.Fatalf("write %q: %v", text, err)
	}
	if string(buffer) != text {
		t.Errorf("relayed = %q, want %q", buffer, text)
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := listener.AcceptTCP()
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	server := <-accepted
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}
