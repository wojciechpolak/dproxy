// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package protocol

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/policy"
)

const secret = "0123456789abcdef0123456789abcdef"

func testToken(t *testing.T) config.Token {
	t.Helper()
	token, err := config.NewToken([]byte(secret))
	if err != nil {
		t.Fatalf("NewToken = %v", err)
	}
	return token
}

func testDestination(t *testing.T) policy.Destination {
	t.Helper()
	destination, err := policy.NewDestination("api.openai.com", policy.AllowedPort)
	if err != nil {
		t.Fatalf("NewDestination = %v", err)
	}
	return destination
}

func TestMessagesValidate(t *testing.T) {
	valid := []Message{
		Hello{Version: Version1, Token: testToken(t)},
		HelloOK{Version: Version1},
		Open{Destination: testDestination(t)},
		OpenOK{},
		OpenError{Code: ErrorForbiddenDestination},
	}
	for _, message := range valid {
		if err := message.Validate(); err != nil {
			t.Errorf("%s.Validate() = %v", message.Type(), err)
		}
	}
}

func TestMessagesRejectMalformedFields(t *testing.T) {
	cases := []struct {
		name    string
		message Message
	}{
		{"hello without a token", Hello{Version: Version1}},
		{"hello with an unsupported version", Hello{Version: 2, Token: testToken(t)}},
		{"hello_ok with an unsupported version", HelloOK{Version: 7}},
		{"open without a destination", Open{}},
		{"open_error with an unknown code", OpenError{Code: 4242}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.message.Validate(); err == nil {
				t.Fatalf("%s.Validate() = nil, want error", tc.message.Type())
			}
		})
	}
}

func TestUnsupportedVersionIsExplicit(t *testing.T) {
	err := Hello{Version: 9, Token: testToken(t)}.Validate()
	var unsupported *UnsupportedVersionError
	if !errors.As(err, &unsupported) {
		t.Fatalf("Validate() = %v (%T), want *UnsupportedVersionError", err, err)
	}
	if unsupported.Offered != 9 {
		t.Errorf("Offered = %d", uint8(unsupported.Offered))
	}
}

func TestShortTokenIsMalformed(t *testing.T) {
	// A short token cannot be built at all, so this check is for a peer's
	// decoded HELLO, not for a local mistake.
	if _, err := config.NewToken([]byte("short")); err == nil {
		t.Fatal("config.NewToken accepted a short secret")
	}
	err := Hello{Version: Version1}.Validate()
	if !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("Validate() = %v, want ErrMalformedMessage", err)
	}
}

// TestHelloNeverPrintsItsToken: a HELLO reaching a log or a debug print must
// not carry the secret.
func TestHelloNeverPrintsItsToken(t *testing.T) {
	message := Hello{Version: Version1, Token: testToken(t)}
	rendered := []string{
		message.String(),
		fmt.Sprint(message),
		fmt.Sprintf("%v", message),
		fmt.Sprintf("%+v", message),
		fmt.Sprintf("%#v", message),
		fmt.Sprintf("%v", []Message{message}),
	}
	for _, text := range rendered {
		if strings.Contains(text, secret) {
			t.Errorf("HELLO leaked its token: %s", text)
		}
	}
}

func TestErrorCodeMapping(t *testing.T) {
	cases := map[policy.DenyReason]ErrorCode{
		policy.DenyNotAllowlisted:     ErrorForbiddenDestination,
		policy.DenyIPLiteral:          ErrorForbiddenDestination,
		policy.DenyPortNotAllowed:     ErrorForbiddenDestination,
		policy.DenyMalformedAuthority: ErrorForbiddenDestination,
		policy.DenyResolutionFailed:   ErrorResolutionFailed,
		policy.DenyNonPublicAddress:   ErrorAddressRejected,
		policy.DenyNone:               ErrorInternal,
	}
	for reason, want := range cases {
		if got := ErrorCodeFor(reason); got != want {
			t.Errorf("ErrorCodeFor(%s) = %s, want %s", reason, got, want)
		}
		if !want.Valid() {
			t.Errorf("%s is not a valid code", want)
		}
	}
}

// TestForbiddenDestinationIsIndistinguishable: a client cannot tell an unlisted
// host from a malformed one, so OPEN_ERROR is no allowlist oracle.
func TestForbiddenDestinationIsIndistinguishable(t *testing.T) {
	if ErrorCodeFor(policy.DenyNotAllowlisted) != ErrorCodeFor(policy.DenyMalformedAuthority) {
		t.Error("the refusal codes differ, which turns OPEN_ERROR into an allowlist oracle")
	}
}
