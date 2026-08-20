// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// maxWebSocketFramePayload bounds allocation and discard work before inner
// TLS authenticates the peer. TLS records are much smaller than this limit.
const maxWebSocketFramePayload = 16 << 20

const (
	opcodeContinuation byte = 0x0
	opcodeBinary       byte = 0x2
	opcodeClose        byte = 0x8
	opcodePing         byte = 0x9
	opcodePong         byte = 0xa
)

// ErrMalformedWebSocketFrame reports framing that cannot represent the byte
// stream dproxy negotiated. The outer handshake offers no extensions.
var ErrMalformedWebSocketFrame = errors.New("malformed WebSocket frame")

// WebSocketConn adapts RFC 6455 binary messages to net.Conn. Each Write is one
// final binary message. Read joins data and continuation frames, handles
// control frames between them, and hides message boundaries from inner TLS.
type WebSocketConn struct {
	conn          net.Conn
	reader        io.Reader
	client        bool
	entropy       io.Reader
	readMu        sync.Mutex
	writeMu       sync.Mutex
	readRemaining uint64
	readMask      [4]byte
	readMaskAt    uint64
	fragmented    bool
}

// NewClientWebSocketConn wraps the client side after a successful upgrade.
// reader must be the buffered reader returned by Upgrader. Passing nil reads
// directly from conn.
func NewClientWebSocketConn(conn net.Conn, reader io.Reader) *WebSocketConn {
	return newWebSocketConn(conn, reader, true)
}

// NewServerWebSocketConn wraps the server side after it accepts an upgrade.
// reader may hold bytes buffered while parsing the HTTP request.
func NewServerWebSocketConn(conn net.Conn, reader io.Reader) *WebSocketConn {
	return newWebSocketConn(conn, reader, false)
}

func newWebSocketConn(conn net.Conn, reader io.Reader, client bool) *WebSocketConn {
	if reader == nil {
		reader = conn
	}
	return &WebSocketConn{conn: conn, reader: reader, client: client, entropy: rand.Reader}
}

// Read implements net.Conn. WebSocket data-message boundaries are not
// observable to the caller.
func (c *WebSocketConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.readRemaining == 0 {
		if err := c.nextDataFrame(); err != nil {
			return 0, err
		}
	}
	want := uint64(len(buffer))
	if want > c.readRemaining {
		want = c.readRemaining
	}
	count, err := io.ReadFull(c.reader, buffer[:int(want)])
	if count > 0 && c.peerFramesAreMasked() {
		for index := 0; index < count; index++ {
			buffer[index] ^= c.readMask[(c.readMaskAt+uint64(index))%4]
		}
		c.readMaskAt += uint64(count)
	}
	c.readRemaining -= uint64(count)
	if err != nil {
		return count, fmt.Errorf("%w: truncated payload: %v", ErrMalformedWebSocketFrame, err)
	}
	return count, nil
}

// Write implements net.Conn. Client frames are masked with fresh entropy as
// RFC 6455 requires; server frames are not masked.
func (c *WebSocketConn) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	if len(payload) > maxWebSocketFramePayload {
		return 0, fmt.Errorf("WebSocket payload is %d bytes, limit is %d", len(payload), maxWebSocketFramePayload)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.writeFrame(opcodeBinary, payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *WebSocketConn) nextDataFrame() error {
	for {
		fin, opcode, masked, length, mask, err := c.readHeader()
		if err != nil {
			return err
		}
		if masked != c.peerFramesAreMasked() {
			return fmt.Errorf("%w: peer used invalid masking", ErrMalformedWebSocketFrame)
		}
		if opcode >= opcodeClose {
			if !fin || length > 125 {
				return fmt.Errorf("%w: invalid control frame", ErrMalformedWebSocketFrame)
			}
			control := make([]byte, length)
			if _, err := io.ReadFull(c.reader, control); err != nil {
				return fmt.Errorf("%w: truncated control frame: %v", ErrMalformedWebSocketFrame, err)
			}
			if masked {
				applyMask(control, mask, 0)
			}
			switch opcode {
			case opcodePing:
				c.writeMu.Lock()
				err := c.writeFrame(opcodePong, control)
				c.writeMu.Unlock()
				if err != nil {
					return err
				}
				continue
			case opcodePong:
				continue
			case opcodeClose:
				return io.EOF
			default:
				return fmt.Errorf("%w: unknown control opcode %#x", ErrMalformedWebSocketFrame, opcode)
			}
		}

		switch opcode {
		case opcodeBinary:
			if c.fragmented {
				return fmt.Errorf("%w: new data message before final continuation", ErrMalformedWebSocketFrame)
			}
		case opcodeContinuation:
			if !c.fragmented {
				return fmt.Errorf("%w: continuation without a data message", ErrMalformedWebSocketFrame)
			}
		default:
			return fmt.Errorf("%w: unsupported data opcode %#x", ErrMalformedWebSocketFrame, opcode)
		}
		c.fragmented = !fin
		if length == 0 {
			continue
		}
		c.readRemaining = length
		c.readMask = mask
		c.readMaskAt = 0
		return nil
	}
}

func (c *WebSocketConn) readHeader() (fin bool, opcode byte, masked bool, length uint64, mask [4]byte, err error) {
	var header [2]byte
	if _, err = io.ReadFull(c.reader, header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return false, 0, false, 0, mask, io.EOF
		}
		return false, 0, false, 0, mask, fmt.Errorf("%w: truncated header: %v", ErrMalformedWebSocketFrame, err)
	}
	if header[0]&0x70 != 0 {
		return false, 0, false, 0, mask, fmt.Errorf("%w: reserved bits are set", ErrMalformedWebSocketFrame)
	}
	fin = header[0]&0x80 != 0
	opcode = header[0] & 0x0f
	masked = header[1]&0x80 != 0
	length = uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err = io.ReadFull(c.reader, extended[:]); err != nil {
			return false, 0, false, 0, mask, fmt.Errorf("%w: truncated length: %v", ErrMalformedWebSocketFrame, err)
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
		if length < 126 {
			return false, 0, false, 0, mask, fmt.Errorf("%w: non-canonical length", ErrMalformedWebSocketFrame)
		}
	case 127:
		var extended [8]byte
		if _, err = io.ReadFull(c.reader, extended[:]); err != nil {
			return false, 0, false, 0, mask, fmt.Errorf("%w: truncated length: %v", ErrMalformedWebSocketFrame, err)
		}
		length = binary.BigEndian.Uint64(extended[:])
		if length < 65536 || length>>63 != 0 {
			return false, 0, false, 0, mask, fmt.Errorf("%w: non-canonical length", ErrMalformedWebSocketFrame)
		}
	}
	if length > maxWebSocketFramePayload {
		return false, 0, false, 0, mask, fmt.Errorf("%w: payload is %d bytes, limit is %d", ErrMalformedWebSocketFrame, length, maxWebSocketFramePayload)
	}
	if masked {
		if _, err = io.ReadFull(c.reader, mask[:]); err != nil {
			return false, 0, false, 0, mask, fmt.Errorf("%w: truncated mask: %v", ErrMalformedWebSocketFrame, err)
		}
	}
	return fin, opcode, masked, length, mask, nil
}

func (c *WebSocketConn) writeFrame(opcode byte, payload []byte) error {
	masked := c.client
	header := make([]byte, 0, 14)
	header = append(header, 0x80|opcode)
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch length := len(payload); {
	case length <= 125:
		header = append(header, maskBit|byte(length))
	case length <= 65535:
		header = append(header, maskBit|126, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(length))
	default:
		header = append(header, maskBit|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(length))
	}
	if !masked {
		if err := writeFull(c.conn, header); err != nil {
			return err
		}
		return writeFull(c.conn, payload)
	}
	var mask [4]byte
	if _, err := io.ReadFull(c.entropy, mask[:]); err != nil {
		return fmt.Errorf("generate WebSocket mask: %w", err)
	}
	header = append(header, mask[:]...)
	maskedPayload := append([]byte(nil), payload...)
	applyMask(maskedPayload, mask, 0)
	if err := writeFull(c.conn, header); err != nil {
		return err
	}
	return writeFull(c.conn, maskedPayload)
}

func applyMask(payload []byte, mask [4]byte, offset uint64) {
	for index := range payload {
		payload[index] ^= mask[(offset+uint64(index))%4]
	}
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		count, err := writer.Write(data)
		if count > 0 {
			data = data[count:]
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (c *WebSocketConn) peerFramesAreMasked() bool { return !c.client }

// Close implements net.Conn by closing the transport. Sending a close frame
// could block when the peer has stopped reading, while net.Conn.Close must
// unblock pending I/O.
func (c *WebSocketConn) Close() error { return c.conn.Close() }

// LocalAddr implements net.Conn.
func (c *WebSocketConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr implements net.Conn.
func (c *WebSocketConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline implements net.Conn.
func (c *WebSocketConn) SetDeadline(deadline time.Time) error { return c.conn.SetDeadline(deadline) }

// SetReadDeadline implements net.Conn.
func (c *WebSocketConn) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

// SetWriteDeadline implements net.Conn.
func (c *WebSocketConn) SetWriteDeadline(deadline time.Time) error {
	return c.conn.SetWriteDeadline(deadline)
}

var _ net.Conn = (*WebSocketConn)(nil)
