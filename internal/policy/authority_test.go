// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseAuthorityAccepts(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"plain", "api.openai.com:443", "api.openai.com:443"},
		{"uppercase is folded", "API.OpenAI.COM:443", "api.openai.com:443"},
		{"root dot is removed", "api.anthropic.com.:443", "api.anthropic.com:443"},
		{"single label", "localhostname:443", "localhostname:443"},
		{"underscore label", "_service.example.com:443", "_service.example.com:443"},
		{"A-label", "xn--bcher-kva.example.com:443", "xn--bcher-kva.example.com:443"},
		{"long but legal", strings.Repeat("a", 63) + ".example.com:443", strings.Repeat("a", 63) + ".example.com:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			destination, err := ParseAuthority(tc.raw)
			if err != nil {
				t.Fatalf("ParseAuthority(%q) = error %v", tc.raw, err)
			}
			if got := destination.Authority(); got != tc.want {
				t.Errorf("Authority() = %q, want %q", got, tc.want)
			}
			if destination.Port() != AllowedPort {
				t.Errorf("Port() = %d, want %d", destination.Port(), AllowedPort)
			}
		})
	}
}

// TestParseAuthorityClassifiesRefusals pins the deny reason too: it becomes the
// OPEN_ERROR code and the HTTP proxy status.
func TestParseAuthorityClassifiesRefusals(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want DenyReason
	}{
		{"empty", "", DenyMalformedAuthority},
		{"no port", "api.openai.com", DenyMalformedAuthority},
		{"empty port", "api.openai.com:", DenyMalformedAuthority},
		{"no host", ":443", DenyMalformedAuthority},
		{"port only colon", ":", DenyMalformedAuthority},
		{"two ports", "api.openai.com:443:443", DenyMalformedAuthority},
		{"service name", "api.openai.com:https", DenyMalformedAuthority},
		{"leading zero port", "api.openai.com:0443", DenyMalformedAuthority},
		{"signed port", "api.openai.com:+443", DenyMalformedAuthority},
		{"negative port", "api.openai.com:-443", DenyMalformedAuthority},
		{"port zero", "api.openai.com:0", DenyMalformedAuthority},
		{"port out of range", "api.openai.com:65536", DenyMalformedAuthority},
		{"absurd port", "api.openai.com:999999", DenyMalformedAuthority},
		{"userinfo", "user:pass@api.openai.com:443", DenyMalformedAuthority},
		{"userinfo without password", "user@api.openai.com:443", DenyMalformedAuthority},
		{"path", "api.openai.com:443/v1", DenyMalformedAuthority},
		{"scheme", "https://api.openai.com:443", DenyMalformedAuthority},
		{"leading space", " api.openai.com:443", DenyMalformedAuthority},
		{"trailing space", "api.openai.com:443 ", DenyMalformedAuthority},
		{"tab", "api.openai.com:443\t", DenyMalformedAuthority},
		{"embedded space", "api openai.com:443", DenyMalformedAuthority},
		{"newline", "api.openai.com:443\n", DenyMalformedAuthority},
		{"nul byte", "api.openai.com\x00:443", DenyMalformedAuthority},
		{"empty label", "api..openai.com:443", DenyMalformedAuthority},
		{"leading dot", ".openai.com:443", DenyMalformedAuthority},
		{"leading hyphen", "-openai.com:443", DenyMalformedAuthority},
		{"trailing hyphen", "openai-.com:443", DenyMalformedAuthority},
		{"non-ASCII", "bücher.example.com:443", DenyMalformedAuthority},
		{"wildcard", "*.openai.com:443", DenyMalformedAuthority},
		{"label too long", strings.Repeat("a", 64) + ".example.com:443", DenyMalformedAuthority},
		{"name too long", strings.Repeat("a.", 130) + "com:443", DenyMalformedAuthority},
		{"bracketed name", "[api.openai.com]:443", DenyMalformedAuthority},
		{"unmatched bracket", "[api.openai.com:443", DenyMalformedAuthority},

		{"IPv4 literal", "203.0.113.10:443", DenyIPLiteral},
		{"IPv4 literal without port", "203.0.113.10", DenyIPLiteral},
		{"loopback literal", "127.0.0.1:443", DenyIPLiteral},
		{"private literal", "192.168.1.1:443", DenyIPLiteral},
		{"bracketed IPv6", "[2001:db8::1]:443", DenyIPLiteral},
		{"bracketed IPv6 loopback", "[::1]:443", DenyIPLiteral},
		{"bare IPv6", "::1", DenyIPLiteral},
		{"bare IPv6 in brackets", "[::1]", DenyIPLiteral},
		{"IPv6 with zone", "[fe80::1%eth0]:443", DenyIPLiteral},
		{"IPv4-mapped IPv6", "[::ffff:127.0.0.1]:443", DenyIPLiteral},

		{"http port", "api.openai.com:80", DenyPortNotAllowed},
		{"alternate TLS port", "api.openai.com:8443", DenyPortNotAllowed},
		{"high port", "api.openai.com:65535", DenyPortNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			destination, err := ParseAuthority(tc.raw)
			if err == nil {
				t.Fatalf("ParseAuthority(%q) = %s, want a refusal", tc.raw, destination)
			}
			if !destination.IsZero() {
				t.Errorf("a refused authority still produced %s", destination)
			}
			if got := DenyReasonOf(err); got != tc.want {
				t.Errorf("DenyReasonOf = %s, want %s", got, tc.want)
			}
			var invalid *InvalidDestinationError
			if !errors.As(err, &invalid) {
				t.Fatalf("error type %T, want *InvalidDestinationError", err)
			}
			if invalid.Reason == "" {
				t.Error("error carries no prose reason")
			}
			if got := invalid.Decision(); got.Allowed() || got.Reason() != tc.want {
				t.Errorf("Decision() = %s, want deny:%s", got, tc.want)
			}
		})
	}
}

// TestDenyReasonOfUnknownErrorDenies: an error from elsewhere must not
// classify as "not denied".
func TestDenyReasonOfUnknownErrorDenies(t *testing.T) {
	if got := DenyReasonOf(errors.New("something else")); got != DenyMalformedAuthority {
		t.Errorf("DenyReasonOf(other) = %s, want %s", got, DenyMalformedAuthority)
	}
	if got := DenyReasonOf(nil); got != DenyNone {
		t.Errorf("DenyReasonOf(nil) = %s, want %s", got, DenyNone)
	}
}

func TestParseAuthorityWrappedErrorIsFound(t *testing.T) {
	_, err := ParseAuthority("127.0.0.1:443")
	wrapped := fmt.Errorf("connect: %w", err)
	if got := DenyReasonOf(wrapped); got != DenyIPLiteral {
		t.Errorf("DenyReasonOf(wrapped) = %s, want %s", got, DenyIPLiteral)
	}
}
