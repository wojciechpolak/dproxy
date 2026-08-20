// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package protocol

import (
	"errors"
	"strings"
	"testing"
)

func TestHappyPathTransitions(t *testing.T) {
	state := StateNew
	sequence := []struct {
		message MessageType
		want    State
	}{
		{MessageHello, StateHelloSent},
		{MessageHelloOK, StateAuthenticated},
		{MessageOpen, StateOpenRequested},
		{MessageOpenOK, StateRelaying},
	}
	for _, step := range sequence {
		next, err := state.Transition(step.message)
		if err != nil {
			t.Fatalf("%s in %s: %v", step.message, state, err)
		}
		if next != step.want {
			t.Fatalf("%s in %s = %s, want %s", step.message, state, next, step.want)
		}
		state = next
	}
	if state.Framed() {
		t.Error("a relaying session still reports itself as framed")
	}
	if state.Terminal() {
		t.Error("a relaying session reports itself as terminal")
	}
}

func TestOpenErrorClosesTheSession(t *testing.T) {
	state := StateOpenRequested
	next, err := state.Transition(MessageOpenError)
	if err != nil {
		t.Fatalf("Transition = %v", err)
	}
	if next != StateClosed || !next.Terminal() {
		t.Fatalf("Transition = %s, want a terminal closed state", next)
	}
}

// TestOpenBeforeAuthenticationIsRejected: no destination may be requested
// before the token has been accepted.
func TestOpenBeforeAuthenticationIsRejected(t *testing.T) {
	for _, state := range []State{StateNew, StateHelloSent} {
		if _, err := state.Transition(MessageOpen); err == nil {
			t.Errorf("OPEN accepted in state %s", state)
		}
	}
}

func TestOutOfOrderMessagesAreRejected(t *testing.T) {
	cases := []struct {
		state   State
		message MessageType
	}{
		{StateNew, MessageHelloOK},
		{StateNew, MessageOpenOK},
		{StateHelloSent, MessageHello},
		{StateAuthenticated, MessageHello},
		{StateAuthenticated, MessageOpenOK},
		{StateOpenRequested, MessageOpen},
		{StateRelaying, MessageOpen},
		{StateClosed, MessageHello},
		{StateNew, MessageType(200)},
	}
	for _, tc := range cases {
		next, err := tc.state.Transition(tc.message)
		if err == nil {
			t.Errorf("%s in %s was accepted (-> %s)", tc.message, tc.state, next)
			continue
		}
		var unexpected *UnexpectedMessageError
		if !errors.As(err, &unexpected) {
			t.Errorf("%s in %s: error type %T, want *UnexpectedMessageError", tc.message, tc.state, err)
			continue
		}
		if unexpected.State != tc.state || unexpected.Message != tc.message {
			t.Errorf("error = %v, want it to name the state and message", unexpected)
		}
		if next != tc.state {
			t.Errorf("a rejected message advanced the state to %s", next)
		}
	}
}

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
