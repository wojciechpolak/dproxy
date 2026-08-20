// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/policy"
)

const framePrefixBytes = 4

// Encoder writes canonical dproxy/1 control frames. It is not safe for
// concurrent use; one session has one ordered control exchange.
type Encoder struct {
	writer          io.Writer
	maxMessageBytes int
}

// NewEncoder returns an encoder bounded to maxMessageBytes, excluding the
// four-byte length prefix.
func NewEncoder(writer io.Writer, maxMessageBytes int) *Encoder {
	return &Encoder{writer: writer, maxMessageBytes: maxMessageBytes}
}

// Encode validates and writes one message.
func (e *Encoder) Encode(message Message) error {
	if e == nil || e.writer == nil {
		return errors.New("protocol encoder has no writer")
	}
	if message == nil {
		return fmt.Errorf("%w: nil message", ErrMalformedMessage)
	}
	if nilMessagePointer(message) {
		return fmt.Errorf("%w: nil %T", ErrMalformedMessage, message)
	}
	if err := message.Validate(); err != nil {
		return err
	}
	body, err := marshalMessage(message)
	if err != nil {
		return err
	}
	if e.maxMessageBytes <= 0 || len(body) > e.maxMessageBytes {
		return fmt.Errorf("%w: %d bytes exceeds limit %d", ErrMessageTooLarge, len(body), e.maxMessageBytes)
	}
	var prefix [framePrefixBytes]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	if err := writeAll(e.writer, prefix[:]); err != nil {
		return fmt.Errorf("write control-message length: %w", err)
	}
	if err := writeAll(e.writer, body); err != nil {
		return fmt.Errorf("write control message: %w", err)
	}
	return nil
}

func nilMessagePointer(message Message) bool {
	switch value := message.(type) {
	case *Hello:
		return value == nil
	case *HelloOK:
		return value == nil
	case *Open:
		return value == nil
	case *OpenOK:
		return value == nil
	case *OpenError:
		return value == nil
	default:
		return false
	}
}

// Decoder reads bounded dproxy/1 control frames. It is not safe for concurrent
// use, and must not be used after OPEN_OK changes the session to raw bytes.
type Decoder struct {
	reader          io.Reader
	maxMessageBytes int
}

// NewDecoder returns a decoder bounded to maxMessageBytes, excluding the
// four-byte length prefix.
func NewDecoder(reader io.Reader, maxMessageBytes int) *Decoder {
	return &Decoder{reader: reader, maxMessageBytes: maxMessageBytes}
}

// Decode reads, validates, and returns one message. EOF before any prefix byte
// is a clean stream end. Every partial or malformed frame is explicit.
func (d *Decoder) Decode() (Message, error) {
	if d == nil || d.reader == nil {
		return nil, errors.New("protocol decoder has no reader")
	}
	var prefix [framePrefixBytes]byte
	count, err := io.ReadFull(d.reader, prefix[:])
	if err != nil {
		if count == 0 && errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("%w: truncated length prefix: %w", ErrMalformedMessage, err)
	}
	length := uint64(binary.BigEndian.Uint32(prefix[:]))
	if length == 0 {
		return nil, fmt.Errorf("%w: empty control message", ErrMalformedMessage)
	}
	if d.maxMessageBytes <= 0 || length > uint64(d.maxMessageBytes) {
		return nil, fmt.Errorf("%w: %d bytes exceeds limit %d", ErrMessageTooLarge, length, d.maxMessageBytes)
	}
	body := make([]byte, int(length))
	if _, err := io.ReadFull(d.reader, body); err != nil {
		return nil, fmt.Errorf("%w: truncated body: %w", ErrMalformedMessage, err)
	}
	return unmarshalMessage(body)
}

func marshalMessage(message Message) ([]byte, error) {
	switch value := message.(type) {
	case Hello:
		return append([]byte{byte(MessageHello), byte(value.Version)}, value.Token.Bytes()...), nil
	case *Hello:
		return marshalMessage(*value)
	case HelloOK:
		return []byte{byte(MessageHelloOK), byte(value.Version)}, nil
	case *HelloOK:
		return marshalMessage(*value)
	case Open:
		host := value.Destination.Host()
		if len(host) > 65535 {
			return nil, fmt.Errorf("%w: OPEN hostname is too long", ErrMalformedMessage)
		}
		body := make([]byte, 1+2+len(host)+2)
		body[0] = byte(MessageOpen)
		binary.BigEndian.PutUint16(body[1:3], uint16(len(host)))
		copy(body[3:], host)
		binary.BigEndian.PutUint16(body[len(body)-2:], value.Destination.Port())
		return body, nil
	case *Open:
		return marshalMessage(*value)
	case OpenOK, *OpenOK:
		return []byte{byte(MessageOpenOK)}, nil
	case OpenError:
		body := []byte{byte(MessageOpenError), 0, 0}
		binary.BigEndian.PutUint16(body[1:], uint16(value.Code))
		return body, nil
	case *OpenError:
		return marshalMessage(*value)
	default:
		return nil, fmt.Errorf("%w: unsupported Go message type %T", ErrMalformedMessage, message)
	}
}

func unmarshalMessage(body []byte) (Message, error) {
	typeByte := MessageType(body[0])
	if !typeByte.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownMessageType, uint8(typeByte))
	}
	var message Message
	switch typeByte {
	case MessageHello:
		if len(body) < 2 {
			return nil, malformed(typeByte, "missing version and token")
		}
		version := Version(body[1])
		if !version.Supported() {
			return nil, &UnsupportedVersionError{Offered: version}
		}
		token, err := config.NewToken(body[2:])
		if err != nil {
			return nil, malformed(typeByte, "invalid token length")
		}
		message = Hello{Version: version, Token: token}
	case MessageHelloOK:
		if len(body) != 2 {
			return nil, malformed(typeByte, "want exactly one version byte")
		}
		message = HelloOK{Version: Version(body[1])}
	case MessageOpen:
		if len(body) < 5 {
			return nil, malformed(typeByte, "missing destination fields")
		}
		hostLength := int(binary.BigEndian.Uint16(body[1:3]))
		if hostLength == 0 || len(body) != 1+2+hostLength+2 {
			return nil, malformed(typeByte, "hostname length does not match frame")
		}
		port := binary.BigEndian.Uint16(body[len(body)-2:])
		destination, err := policy.NewDestination(string(body[3:3+hostLength]), port)
		if err != nil {
			return nil, malformed(typeByte, "invalid destination")
		}
		message = Open{Destination: destination}
	case MessageOpenOK:
		if len(body) != 1 {
			return nil, malformed(typeByte, "unexpected payload")
		}
		message = OpenOK{}
	case MessageOpenError:
		if len(body) != 3 {
			return nil, malformed(typeByte, "want exactly one error code")
		}
		message = OpenError{Code: ErrorCode(binary.BigEndian.Uint16(body[1:]))}
	}
	if err := message.Validate(); err != nil {
		return nil, err
	}
	return message, nil
}

func malformed(messageType MessageType, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrMalformedMessage, messageType, reason)
}

func writeAll(writer io.Writer, data []byte) error {
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
