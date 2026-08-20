// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestWebSocketConnIsABidirectionalByteStream(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	client := NewClientWebSocketConn(clientRaw, nil)
	server := NewServerWebSocketConn(serverRaw, nil)
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })

	clientPayload := bytes.Repeat([]byte("client"), 100)
	serverPayload := bytes.Repeat([]byte("server"), 100)
	clientErr := make(chan error, 1)
	serverErr := make(chan error, 1)
	go func() {
		_, err := client.Write(clientPayload)
		clientErr <- err
	}()
	go func() {
		_, err := server.Write(serverPayload)
		serverErr <- err
	}()

	fromClient := make([]byte, len(clientPayload))
	fromServer := make([]byte, len(serverPayload))
	if _, err := io.ReadFull(server, fromClient); err != nil {
		t.Fatalf("server ReadFull: %v", err)
	}
	if _, err := io.ReadFull(client, fromServer); err != nil {
		t.Fatalf("client ReadFull: %v", err)
	}
	if err := <-clientErr; err != nil {
		t.Fatalf("client Write: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server Write: %v", err)
	}
	if !bytes.Equal(fromClient, clientPayload) || !bytes.Equal(fromServer, serverPayload) {
		t.Fatal("adapter changed stream bytes")
	}
}

func TestWebSocketConnJoinsFragmentsAndAnswersPing(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	server := NewServerWebSocketConn(serverRaw, nil)
	t.Cleanup(func() { _ = clientRaw.Close() })
	t.Cleanup(func() { _ = server.Close() })

	done := make(chan error, 1)
	go func() {
		frames := append(maskedTestFrame(false, opcodeBinary, []byte("ab")), maskedTestFrame(true, opcodePing, []byte("?"))...)
		if _, err := clientRaw.Write(frames); err != nil {
			done <- err
			return
		}
		var pong [3]byte
		_, err := io.ReadFull(clientRaw, pong[:])
		if err == nil && !bytes.Equal(pong[:], []byte{0x80 | opcodePong, 1, '?'}) {
			err = errors.New("server returned an invalid pong")
		}
		if err == nil {
			_, err = clientRaw.Write(maskedTestFrame(true, opcodeContinuation, []byte("cd")))
		}
		done <- err
	}()

	got := make([]byte, 4)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "abcd" {
		t.Errorf("stream = %q, want abcd", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("peer: %v", err)
	}
}

func TestWebSocketConnRejectsMalformedFrames(t *testing.T) {
	cases := map[string][]byte{
		"unmasked client frame":     {0x80 | opcodeBinary, 1, 'x'},
		"reserved bit":              {0xc0 | opcodeBinary, 0x80},
		"continuation without data": maskedTestFrame(true, opcodeContinuation, []byte("x")),
		"text data":                 maskedTestFrame(true, 0x1, []byte("x")),
		"fragmented control":        maskedTestFrame(false, opcodePing, []byte("x")),
		"non-canonical length":      {0x80 | opcodeBinary, 0x80 | 126, 0, 1, 1, 2, 3, 4, 'x'},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			clientRaw, serverRaw := net.Pipe()
			server := NewServerWebSocketConn(serverRaw, nil)
			t.Cleanup(func() { _ = clientRaw.Close() })
			t.Cleanup(func() { _ = server.Close() })
			go func() { _, _ = clientRaw.Write(wire) }()
			var one [1]byte
			if _, err := server.Read(one[:]); !errors.Is(err, ErrMalformedWebSocketFrame) {
				t.Errorf("Read = %v, want ErrMalformedWebSocketFrame", err)
			}
		})
	}
}

func TestWebSocketConnDelegatesDeadlinesAndAddresses(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	client := NewClientWebSocketConn(clientRaw, nil)
	defer func() { _ = client.Close() }()
	defer func() { _ = serverRaw.Close() }()
	if client.LocalAddr() != clientRaw.LocalAddr() || client.RemoteAddr() != clientRaw.RemoteAddr() {
		t.Fatal("adapter changed connection addresses")
	}
	deadline := time.Now().Add(time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := client.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := client.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
}

func maskedTestFrame(fin bool, opcode byte, payload []byte) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	mask := [4]byte{1, 2, 3, 4}
	wire := []byte{first, 0x80 | byte(len(payload))}
	wire = append(wire, mask[:]...)
	masked := append([]byte(nil), payload...)
	applyMask(masked, mask, 0)
	return append(wire, masked...)
}

func TestWebSocketConnRejectsAFrameAboveTheLimit(t *testing.T) {
	var wire [10]byte
	wire[0] = 0x80 | opcodeBinary
	wire[1] = 0x80 | 127
	binary.BigEndian.PutUint64(wire[2:], maxWebSocketFramePayload+1)
	clientRaw, serverRaw := net.Pipe()
	server := NewServerWebSocketConn(serverRaw, nil)
	defer func() { _ = clientRaw.Close() }()
	defer func() { _ = server.Close() }()
	go func() { _, _ = clientRaw.Write(wire[:]) }()
	var one [1]byte
	if _, err := server.Read(one[:]); !errors.Is(err, ErrMalformedWebSocketFrame) {
		t.Errorf("Read = %v, want ErrMalformedWebSocketFrame", err)
	}
}

func TestWebSocketConnHandlesEmptyIOAndMaskFailure(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	client := NewClientWebSocketConn(clientRaw, nil)
	defer func() { _ = client.Close() }()
	defer func() { _ = serverRaw.Close() }()
	if count, err := client.Read(nil); count != 0 || err != nil {
		t.Fatalf("empty Read = %d, %v", count, err)
	}
	if count, err := client.Write(nil); count != 0 || err != nil {
		t.Fatalf("empty Write = %d, %v", count, err)
	}
	client.entropy = websocketErrorReader{err: errors.New("entropy failed")}
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("client Write ignored mask entropy failure")
	}
}

func TestWebSocketConnControlAndTruncationErrors(t *testing.T) {
	cases := map[string][]byte{
		"truncated header":        {0x80},
		"truncated 16-bit length": {0x80 | opcodeBinary, 126, 0},
		"truncated 64-bit length": {0x80 | opcodeBinary, 127, 0, 0},
		"noncanonical 64-bit":     {0x80 | opcodeBinary, 127, 0, 0, 0, 0, 0, 0, 0, 126},
		"truncated mask":          {0x80 | opcodeBinary, 0x80 | 1, 1, 2},
		"oversized control":       {0x80 | opcodePing, 126, 0, 126},
		"unknown control":         {0x80 | 0x0b, 0},
		"truncated payload":       {0x80 | opcodeBinary, 2, 'x'},
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			conn := NewClientWebSocketConn(&stubConn{Reader: bytes.NewReader(wire)}, nil)
			_, err := conn.Read(make([]byte, 2))
			if !errors.Is(err, ErrMalformedWebSocketFrame) {
				t.Fatalf("Read = %v, want malformed frame", err)
			}
		})
	}

	closeConn := NewClientWebSocketConn(&stubConn{Reader: bytes.NewReader([]byte{0x80 | opcodeClose, 0})}, nil)
	if _, err := closeConn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("close frame = %v, want EOF", err)
	}
}

type stubConn struct {
	io.Reader
	io.Writer
}

func (c *stubConn) Read(buffer []byte) (int, error) {
	if c.Reader == nil {
		return 0, io.EOF
	}
	return c.Reader.Read(buffer)
}

func (c *stubConn) Write(buffer []byte) (int, error) {
	if c.Writer == nil {
		return len(buffer), nil
	}
	return c.Writer.Write(buffer)
}

func (*stubConn) Close() error                     { return nil }
func (*stubConn) LocalAddr() net.Addr              { return nil }
func (*stubConn) RemoteAddr() net.Addr             { return nil }
func (*stubConn) SetDeadline(time.Time) error      { return nil }
func (*stubConn) SetReadDeadline(time.Time) error  { return nil }
func (*stubConn) SetWriteDeadline(time.Time) error { return nil }
