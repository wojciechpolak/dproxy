// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package protocol

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type unsupportedMessage struct{}

func (unsupportedMessage) Type() MessageType { return MessageType(99) }
func (unsupportedMessage) Validate() error   { return nil }

type failingWriter struct {
	calls  int
	failAt int
	zeroAt int
}

func (w *failingWriter) Write(data []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		return 0, errors.New("write failed")
	}
	if w.calls == w.zeroAt {
		return 0, nil
	}
	return len(data), nil
}

func TestCodecRejectsMissingEndpointsAndMessages(t *testing.T) {
	var encoder *Encoder
	if err := encoder.Encode(OpenOK{}); err == nil {
		t.Fatal("nil encoder accepted a message")
	}
	if err := NewEncoder(nil, testControlLimit).Encode(OpenOK{}); err == nil {
		t.Fatal("encoder without a writer accepted a message")
	}
	if err := NewEncoder(io.Discard, testControlLimit).Encode(nil); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("nil message error = %v", err)
	}

	var decoder *Decoder
	if _, err := decoder.Decode(); err == nil {
		t.Fatal("nil decoder read a message")
	}
	if _, err := NewDecoder(nil, testControlLimit).Decode(); err == nil {
		t.Fatal("decoder without a reader read a message")
	}
	if _, err := NewDecoder(bytes.NewReader(frame([]byte{byte(MessageOpenError), 0})), testControlLimit).Decode(); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("short OPEN_ERROR error = %v", err)
	}
}

func TestCodecSupportsMessagePointers(t *testing.T) {
	messages := []Message{
		&Hello{Version: Version1, Token: testToken(t)},
		&HelloOK{Version: Version1},
		&Open{Destination: testDestination(t)},
		&OpenOK{},
		&OpenError{Code: ErrorInternal},
	}
	for _, message := range messages {
		var stream bytes.Buffer
		if err := NewEncoder(&stream, testControlLimit).Encode(message); err != nil {
			t.Errorf("Encode(%T) = %v", message, err)
		}
	}

	typedNils := []Message{
		(*Hello)(nil),
		(*HelloOK)(nil),
		(*Open)(nil),
		(*OpenOK)(nil),
		(*OpenError)(nil),
	}
	for _, message := range typedNils {
		if err := NewEncoder(io.Discard, testControlLimit).Encode(message); !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("Encode(%T(nil)) = %v", message, err)
		}
	}
	if err := NewEncoder(io.Discard, testControlLimit).Encode(unsupportedMessage{}); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("unsupported Go message error = %v", err)
	}
}

func TestEncoderReportsPrefixAndBodyWriteFailures(t *testing.T) {
	for name, writer := range map[string]*failingWriter{
		"prefix error": {failAt: 1},
		"body error":   {failAt: 2},
		"short write":  {zeroAt: 1},
	} {
		t.Run(name, func(t *testing.T) {
			err := NewEncoder(writer, testControlLimit).Encode(OpenOK{})
			if err == nil {
				t.Fatal("Encode succeeded")
			}
			if name == "short write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("Encode error = %v, want io.ErrShortWrite", err)
			}
		})
	}
}

func TestErrorCodeRendersEveryDefinedCase(t *testing.T) {
	codes := []ErrorCode{
		ErrorUnauthenticated,
		ErrorForbiddenDestination,
		ErrorResolutionFailed,
		ErrorAddressRejected,
		ErrorDialFailed,
		ErrorLimitExceeded,
		ErrorMalformed,
		ErrorUnsupportedVersion,
		ErrorInternal,
	}
	for _, code := range codes {
		if got := code.String(); strings.HasPrefix(got, "ErrorCode(") {
			t.Errorf("error code %d has no name", code)
		}
	}
	if got := ErrorCode(99).String(); got != "ErrorCode(99)" {
		t.Errorf("unknown error code = %q", got)
	}

	unsupported := (&UnsupportedVersionError{Offered: 9}).Error()
	if !strings.Contains(unsupported, "9") || !strings.Contains(unsupported, Version1.String()) {
		t.Errorf("unsupported-version error = %q", unsupported)
	}
}
