// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package protocol

import (
	"strings"
	"testing"
)

func TestMessageTypeValidity(t *testing.T) {
	for _, valid := range []MessageType{MessageHello, MessageHelloOK, MessageOpen, MessageOpenOK, MessageOpenError} {
		if !valid.Valid() {
			t.Errorf("%s reports Valid() = false", valid)
		}
		if strings.HasPrefix(valid.String(), "MessageType(") {
			t.Errorf("%d has no wire name", uint8(valid))
		}
	}
	for _, invalid := range []MessageType{0, 6, 42, 255} {
		if invalid.Valid() {
			t.Errorf("MessageType(%d) reports Valid() = true", uint8(invalid))
		}
	}
	if got := MessageType(99).String(); got != "MessageType(99)" {
		t.Errorf("unknown message type = %q", got)
	}
}

func TestVersionSupport(t *testing.T) {
	if !Version1.Supported() {
		t.Error("Version1.Supported() = false")
	}
	for _, version := range []Version{0, 2, 255} {
		if version.Supported() {
			t.Errorf("Version(%d).Supported() = true", uint8(version))
		}
	}
	if Name != "dproxy/1" || ALPN != Name {
		t.Errorf("protocol name = %q, ALPN = %q", Name, ALPN)
	}
}
