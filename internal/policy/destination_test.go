// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestNewDestinationCanonicalizes(t *testing.T) {
	destination, err := NewDestination("API.OpenAI.com.", AllowedPort)
	if err != nil {
		t.Fatalf("NewDestination = %v", err)
	}
	if destination.Host() != "api.openai.com" {
		t.Errorf("Host() = %q", destination.Host())
	}
	if destination.Port() != AllowedPort {
		t.Errorf("Port() = %d", destination.Port())
	}
	if got, want := destination.Authority(), "api.openai.com:443"; got != want {
		t.Errorf("Authority() = %q, want %q", got, want)
	}
	if destination.IsZero() {
		t.Error("a built Destination reports IsZero() = true")
	}
}

func TestNewDestinationRejects(t *testing.T) {
	cases := []struct {
		name string
		host string
		port uint16
	}{
		{"http port", "api.openai.com", 80},
		{"alternate TLS port", "api.openai.com", 8443},
		{"zero port", "api.openai.com", 0},
		{"IPv4 literal", "203.0.113.10", AllowedPort},
		{"IPv6 literal", "::1", AllowedPort},
		{"bracketed IPv6 literal", "[2001:db8::1]", AllowedPort},
		{"empty host", "", AllowedPort},
		{"trailing dot only", ".", AllowedPort},
		{"embedded port", "api.openai.com:443", AllowedPort},
		{"URL", "https://api.openai.com", AllowedPort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			destination, err := NewDestination(tc.host, tc.port)
			if err == nil {
				t.Fatalf("NewDestination(%q, %d) = %s, want error", tc.host, tc.port, destination)
			}
			var invalid *InvalidDestinationError
			if !asInvalidDestination(err, &invalid) {
				t.Fatalf("error type %T, want *InvalidDestinationError", err)
			}
			if invalid.Reason == "" {
				t.Error("error carries no reason")
			}
		})
	}
}

func TestZeroDestinationHasNoAuthority(t *testing.T) {
	var destination Destination
	if !destination.IsZero() {
		t.Fatal("the zero Destination reports IsZero() = false")
	}
	if destination.Authority() != "" || destination.String() != "" {
		t.Errorf("Authority() = %q", destination.Authority())
	}
}

func TestInvalidDestinationErrorNamesTheAuthority(t *testing.T) {
	_, err := NewDestination("api.openai.com", 80)
	if err == nil || !strings.Contains(err.Error(), "api.openai.com:80") {
		t.Fatalf("error = %v, want it to name the rejected authority", err)
	}
}

// asInvalidDestination keeps errors.As out of every case above.
func asInvalidDestination(err error, target **InvalidDestinationError) bool {
	return errors.As(err, target)
}
