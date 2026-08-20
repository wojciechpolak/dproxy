// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"
)

const testControlLimit = 4096

func TestCodecRoundTripsEveryMessage(t *testing.T) {
	messages := []Message{
		Hello{Version: Version1, Token: testToken(t)},
		HelloOK{Version: Version1},
		Open{Destination: testDestination(t)},
		OpenOK{},
		OpenError{Code: ErrorAddressRejected},
	}
	var stream bytes.Buffer
	encoder := NewEncoder(&stream, testControlLimit)
	for _, message := range messages {
		if err := encoder.Encode(message); err != nil {
			t.Fatalf("Encode(%s): %v", message.Type(), err)
		}
	}

	decoder := NewDecoder(&stream, testControlLimit)
	for index, want := range messages {
		got, err := decoder.Decode()
		if err != nil {
			t.Fatalf("Decode(%d): %v", index, err)
		}
		if got.Type() != want.Type() {
			t.Fatalf("Decode(%d) type = %s, want %s", index, got.Type(), want.Type())
		}
		switch expected := want.(type) {
		case Hello:
			actual := got.(Hello)
			if actual.Version != expected.Version || !actual.Token.Equal(expected.Token) {
				t.Error("decoded HELLO does not match")
			}
		case Open:
			if got.(Open).Destination != expected.Destination {
				t.Errorf("decoded OPEN = %s, want %s", got.(Open).Destination, expected.Destination)
			}
		default:
			if !reflect.DeepEqual(got, want) {
				t.Errorf("decoded %s does not match", want.Type())
			}
		}
	}
	if _, err := decoder.Decode(); !errors.Is(err, io.EOF) {
		t.Errorf("Decode at stream end = %v, want EOF", err)
	}
}

func TestCodecHasStableCanonicalWireEncoding(t *testing.T) {
	var stream bytes.Buffer
	if err := NewEncoder(&stream, testControlLimit).Encode(HelloOK{Version: Version1}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{0, 0, 0, 2, byte(MessageHelloOK), byte(Version1)}
	if !bytes.Equal(stream.Bytes(), want) {
		t.Errorf("wire bytes = %x, want %x", stream.Bytes(), want)
	}
}

func TestDecoderRejectsUnknownAndMalformedMessages(t *testing.T) {
	cases := []struct {
		name            string
		body            []byte
		is              error
		wantUnsupported bool
	}{
		{"unknown type", []byte{99}, ErrUnknownMessageType, false},
		{"empty hello", []byte{byte(MessageHello)}, ErrMalformedMessage, false},
		{"short hello token", []byte{byte(MessageHello), byte(Version1), 1, 2, 3}, ErrMalformedMessage, false},
		{"hello_ok trailing data", []byte{byte(MessageHelloOK), byte(Version1), 0}, ErrMalformedMessage, false},
		{"open length mismatch", []byte{byte(MessageOpen), 0, 9, 'a', 1, 187}, ErrMalformedMessage, false},
		{"open malformed host", append([]byte{byte(MessageOpen), 0, 3}, append([]byte("a b"), 1, 187)...), ErrMalformedMessage, false},
		{"open_ok trailing data", []byte{byte(MessageOpenOK), 0}, ErrMalformedMessage, false},
		{"open_error unknown code", []byte{byte(MessageOpenError), 0xff, 0xff}, ErrMalformedMessage, false},
		{"unsupported hello version", append([]byte{byte(MessageHello), 9}, bytes.Repeat([]byte{'x'}, 32)...), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDecoder(bytes.NewReader(frame(tc.body)), testControlLimit).Decode()
			if err == nil {
				t.Fatal("Decode succeeded")
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("Decode = %v, want errors.Is(%v)", err, tc.is)
			}
			var unsupported *UnsupportedVersionError
			if tc.wantUnsupported && !errors.As(err, &unsupported) {
				t.Errorf("Decode = %v, want UnsupportedVersionError", err)
			}
		})
	}
}

func TestDecoderRejectsBadFramingAndOversizeBeforeReadingBody(t *testing.T) {
	if _, err := NewDecoder(bytes.NewReader([]byte{0, 0}), testControlLimit).Decode(); !errors.Is(err, ErrMalformedMessage) {
		t.Errorf("partial prefix = %v", err)
	}
	if _, err := NewDecoder(bytes.NewReader([]byte{0, 0, 0, 0}), testControlLimit).Decode(); !errors.Is(err, ErrMalformedMessage) {
		t.Errorf("zero length = %v", err)
	}
	if _, err := NewDecoder(bytes.NewReader(frame([]byte{byte(MessageOpen), 0})), testControlLimit).Decode(); !errors.Is(err, ErrMalformedMessage) {
		t.Errorf("partial body = %v", err)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], testControlLimit+1)
	if _, err := NewDecoder(bytes.NewReader(prefix[:]), testControlLimit).Decode(); !errors.Is(err, ErrMessageTooLarge) {
		t.Errorf("oversize = %v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestDecoderPreservesUnderlyingReadErrors(t *testing.T) {
	cause := errors.New("read timed out")
	_, err := NewDecoder(errorReader{err: cause}, testControlLimit).Decode()
	if !errors.Is(err, ErrMalformedMessage) || !errors.Is(err, cause) {
		t.Fatalf("prefix error = %v, want malformed message wrapping the read error", err)
	}
	prefix := []byte{0, 0, 0, 2}
	_, err = NewDecoder(io.MultiReader(bytes.NewReader(prefix), errorReader{err: cause}), testControlLimit).Decode()
	if !errors.Is(err, ErrMalformedMessage) || !errors.Is(err, cause) {
		t.Fatalf("body error = %v, want malformed message wrapping the read error", err)
	}
}

func TestEncoderRejectsInvalidMessagesAndLimit(t *testing.T) {
	if err := NewEncoder(io.Discard, testControlLimit).Encode(HelloOK{Version: 9}); err == nil {
		t.Fatal("Encode accepted an unsupported version")
	}
	if err := NewEncoder(io.Discard, 1).Encode(HelloOK{Version: Version1}); !errors.Is(err, ErrMessageTooLarge) {
		t.Errorf("Encode over limit = %v", err)
	}
	var nilHello *Hello
	if err := NewEncoder(io.Discard, testControlLimit).Encode(nilHello); !errors.Is(err, ErrMalformedMessage) {
		t.Errorf("Encode typed nil = %v", err)
	}
}

func frame(body []byte) []byte {
	framed := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(body)))
	copy(framed[4:], body)
	return framed
}
