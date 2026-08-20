// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wojciechpolak/dproxy/internal/policy"
)

// Mode names the role a dproxy process runs in. Each role has its own struct
// and its own validation; no value is shared silently.
type Mode string

const (
	// ModeClient is the local process that serves CONNECT on loopback.
	ModeClient Mode = "client"
	// ModeServer is the remote process behind the public WSS front end.
	ModeServer Mode = "server"
)

// String implements fmt.Stringer.
func (m Mode) String() string { return string(m) }

// ECHMode records whether Encrypted Client Hello is mandatory. There is no
// third value: it is required, or disabled by a conspicuously named flag.
type ECHMode string

const (
	// ECHRequired aborts the tunnel unless ECH is offered and accepted.
	ECHRequired ECHMode = "required"
	// ECHInsecureDisabled skips ECH, exposing the outer SNI. For local
	// development against endpoints with no HTTPS RR; never production.
	ECHInsecureDisabled ECHMode = "insecure-disabled"
)

// String implements fmt.Stringer.
func (m ECHMode) String() string { return string(m) }

// Secure reports whether the mode preserves the outer-SNI guarantee.
func (m ECHMode) Secure() bool { return m == ECHRequired }

// ParseECHMode validates an ECH mode written by an operator.
func ParseECHMode(raw string) (ECHMode, error) {
	switch ECHMode(raw) {
	case ECHRequired:
		return ECHRequired, nil
	case ECHInsecureDisabled:
		return ECHInsecureDisabled, nil
	default:
		return "", fmt.Errorf("unknown ECH mode %q (want %q or %q)", raw, ECHRequired, ECHInsecureDisabled)
	}
}

// Timeouts bounds each phase of a tunnel separately: one deadline cannot serve
// both a prompt control exchange and a long-running provider stream.
type Timeouts struct {
	// Dial bounds the TCP connection to the WSS front end or the target.
	Dial time.Duration
	// TLSHandshake bounds each TLS handshake, outer and inner.
	TLSHandshake time.Duration
	// Control bounds the HELLO/OPEN exchange after the inner handshake.
	Control time.Duration
	// Idle ends a relayed session that has moved no bytes in either
	// direction for this long. Zero disables the idle check.
	Idle time.Duration
	// MaxLifetime ends a relayed session regardless of progress. Zero, the
	// default, is unbounded: provider streams are long-lived by design.
	MaxLifetime time.Duration
	// Shutdown is how long the server waits for active relays after it stops
	// accepting sessions. It then cancels and closes what remains.
	Shutdown time.Duration
}

// DefaultTimeouts returns the shipped defaults.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		Dial:         10 * time.Second,
		TLSHandshake: 10 * time.Second,
		Control:      10 * time.Second,
		Idle:         5 * time.Minute,
		MaxLifetime:  0,
		Shutdown:     30 * time.Second,
	}
}

// Validate rejects timeouts that would disable a bound that must exist.
func (t Timeouts) Validate() error {
	required := []struct {
		name  string
		value time.Duration
	}{
		{"dial", t.Dial},
		{"tls-handshake", t.TLSHandshake},
		{"control", t.Control},
		{"shutdown", t.Shutdown},
	}
	for _, field := range required {
		if field.value <= 0 {
			return fmt.Errorf("%s timeout must be positive, got %s", field.name, field.value)
		}
	}
	if t.Idle < 0 {
		return fmt.Errorf("idle timeout must not be negative, got %s", t.Idle)
	}
	if t.MaxLifetime < 0 {
		return fmt.Errorf("max lifetime must not be negative, got %s", t.MaxLifetime)
	}
	if t.MaxLifetime != 0 && t.Idle != 0 && t.MaxLifetime < t.Idle {
		return fmt.Errorf("max lifetime %s is shorter than the idle timeout %s", t.MaxLifetime, t.Idle)
	}
	return nil
}

// Limits bounds what one remote dproxy carries at once. Resource controls,
// not policy.
type Limits struct {
	// MaxSessions caps concurrent sessions. Zero is rejected: an unbounded
	// remote is not a configuration on offer.
	MaxSessions int
	// MaxControlMessageBytes caps one control message. A hostname is at most
	// 253 bytes, so this is generous: it exists to fail a hostile length
	// prefix immediately.
	MaxControlMessageBytes int
}

// DefaultLimits returns the shipped defaults.
func DefaultLimits() Limits {
	return Limits{MaxSessions: 64, MaxControlMessageBytes: 4096}
}

// Validate rejects limits that would remove a bound.
func (l Limits) Validate() error {
	if l.MaxSessions <= 0 {
		return fmt.Errorf("max sessions must be positive, got %d", l.MaxSessions)
	}
	if l.MaxControlMessageBytes < 256 {
		return fmt.Errorf("max control message must be at least 256 bytes, got %d", l.MaxControlMessageBytes)
	}
	if l.MaxControlMessageBytes > 1<<20 {
		return fmt.Errorf("max control message must be at most 1 MiB, got %d", l.MaxControlMessageBytes)
	}
	return nil
}

// ClientConfig is the validated configuration of the local process. Nothing
// downstream re-parses an operator string.
type ClientConfig struct {
	// Listen is the loopback address the CONNECT listener binds.
	Listen string
	// RelayURL is the public wss:// endpoint in front of the remote dproxy.
	RelayURL *url.URL
	// ServerPin is the remote identity the inner TLS session must present.
	ServerPin Pin
	// TokenFile holds the shared secret sent inside the inner session.
	TokenFile TokenFile
	// DoHURL is the in-process resolver. There is no OS-DNS fallback.
	DoHURL *url.URL
	// DoHBootstrap are the addresses the resolver itself is dialed at.
	DoHBootstrap []netip.Addr
	// ECH is required unless explicitly disabled for development.
	ECH ECHMode
	// Allowlist is checked before a tunnel is built. It permits all valid
	// hostnames by default and can be narrowed by configuration.
	Allowlist policy.Allowlist
	// Timeouts bounds each phase of a tunnel.
	Timeouts Timeouts
	// Log controls verbosity and redaction.
	Log LogOptions
}

// Mode reports the role this configuration describes.
func (c *ClientConfig) Mode() Mode { return ModeClient }

// Checker builds the destination policy the local process enforces. It has no
// resolver: the hostname goes to the remote inside the inner TLS session and
// is resolved there, so no provider name is queried from the user's network.
func (c *ClientConfig) Checker() policy.Checker {
	return policy.NewChecker(c.Allowlist, nil)
}

// Validate checks every field and reports the first problem.
func (c *ClientConfig) Validate() error {
	if err := validateLoopbackAddress(c.Listen); err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if c.RelayURL == nil {
		return errors.New("relay URL is required (--server)")
	}
	if err := validateRelayURL(c.RelayURL); err != nil {
		return fmt.Errorf("relay URL: %w", err)
	}
	if c.ServerPin.IsZero() {
		return errors.New("remote identity pin is required (--server-pin)")
	}
	if c.TokenFile == "" {
		return errors.New("token file is required (--token-file)")
	}
	if err := validateDoHURL(c.DoHURL); err != nil {
		return fmt.Errorf("DoH URL: %w", err)
	}
	if err := validateDoHBootstrap(c.DoHURL, c.DoHBootstrap); err != nil {
		return err
	}
	if _, err := ParseECHMode(string(c.ECH)); err != nil {
		return err
	}
	if c.Allowlist.IsEmpty() {
		return errors.New("destination allowlist is empty; dproxy would permit nothing")
	}
	if err := c.Timeouts.Validate(); err != nil {
		return err
	}
	return c.Log.Validate()
}

// ServerConfig is the validated configuration of the remote process.
type ServerConfig struct {
	// Listen is the address the WebSocket endpoint binds. It is reached
	// through private ingress, so it should not be published directly.
	Listen string
	// IdentityFile stores the persistent Ed25519 key and self-signed
	// certificate used by inner TLS. The client authenticates its SPKI.
	IdentityFile string
	// TokenFile holds the shared secret the client must prove it has.
	TokenFile TokenFile
	// DoHURL resolves destinations, keeping target names out of the host's
	// ordinary resolver.
	DoHURL *url.URL
	// DoHBootstrap are the addresses the resolver itself is dialed at.
	DoHBootstrap []netip.Addr
	// Allowlist is enforced again here; the client's decision is not trusted.
	// It permits all valid hostnames by default and can be narrowed.
	Allowlist policy.Allowlist
	// Timeouts bounds each phase of a session.
	Timeouts Timeouts
	// Limits bounds concurrent work and control-message size.
	Limits Limits
	// Log controls verbosity and redaction.
	Log LogOptions
}

// Mode reports the role this configuration describes.
func (c *ServerConfig) Mode() Mode { return ModeServer }

// Checker builds the destination policy the remote enforces. Same type and
// same allowlist configuration as the client's, applied to the destination
// decoded from OPEN.
func (c *ServerConfig) Checker(resolver policy.Resolver) policy.Checker {
	return policy.NewChecker(c.Allowlist, resolver)
}

// Validate checks every field and reports the first problem.
func (c *ServerConfig) Validate() error {
	if err := validateListenAddress(c.Listen); err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if c.TokenFile == "" {
		return errors.New("token file is required (--token-file)")
	}
	if c.IdentityFile == "" {
		return errors.New("inner TLS identity file is required (--identity-file)")
	}
	if err := validateDoHURL(c.DoHURL); err != nil {
		return fmt.Errorf("DoH URL: %w", err)
	}
	if err := validateDoHBootstrap(c.DoHURL, c.DoHBootstrap); err != nil {
		return err
	}
	if c.Allowlist.IsEmpty() {
		return errors.New("destination allowlist is empty; the remote would permit nothing")
	}
	if err := c.Timeouts.Validate(); err != nil {
		return err
	}
	if err := c.Limits.Validate(); err != nil {
		return err
	}
	return c.Log.Validate()
}

// validateListenAddress accepts a host:port whose host is an IP literal or
// empty. A name is rejected: what a listener binds must not depend on DNS.
func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %w", address, err)
	}
	if port == "" {
		return errors.New("port is required")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort <= 0 || parsedPort > 65535 {
		return fmt.Errorf("%q is not a usable TCP port", port)
	}
	if host == "" {
		return nil
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("host %q must be an IP literal", host)
	}
	return nil
}

// validateLoopbackAddress additionally requires loopback: the local CONNECT
// listener has no authentication, so binding it elsewhere exposes an open
// proxy.
func validateLoopbackAddress(address string) error {
	if err := validateListenAddress(address); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%q is not host:port: %w", address, err)
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || !parsed.IsLoopback() {
		return fmt.Errorf("host %q is not loopback; the local listener may bind only 127.0.0.1 or ::1", host)
	}
	return nil
}

// validateRelayURL enforces the wss:// shape, rejecting anything that could
// move the endpoint or carry a secret in the URL.
func validateRelayURL(u *url.URL) error {
	if u.Scheme != "wss" {
		return fmt.Errorf("scheme %q is not wss", u.Scheme)
	}
	if u.User != nil {
		return errors.New("must not carry userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must not carry a query or fragment; no secret belongs in the URL")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("host is required")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return errors.New("host must be a name, not an IP literal: ECH and DoH both need a name")
	}
	if port := u.Port(); port != "" && port != "443" {
		return fmt.Errorf("port %q is not 443", port)
	}
	if !strings.HasPrefix(u.EscapedPath(), "/") {
		return errors.New("path must be absolute")
	}
	return nil
}

// validateDoHURL enforces an https endpoint with a canonical path. An IP
// literal is allowed: the resolver is the one endpoint reachable without
// prior resolution.
func validateDoHURL(u *url.URL) error {
	if u == nil {
		return errors.New("DoH URL is required")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme %q is not https", u.Scheme)
	}
	if u.User != nil {
		return errors.New("must not carry userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must not carry a query or fragment")
	}
	if u.Hostname() == "" {
		return errors.New("host is required")
	}
	path := u.EscapedPath()
	if !strings.HasPrefix(path, "/") || strings.Contains(strings.ToLower(path), "%2f") {
		return fmt.Errorf("path %q is not canonical", path)
	}
	return nil
}

// knownDoHBootstrap maps a DoH hostname onto the addresses it is reached at.
//
// The resolver's own name is the one name DoH cannot resolve, and asking the
// operating system for it would emit exactly the plaintext query dproxy exists
// to avoid. So a shipped endpoint ships with its addresses, and any other
// endpoint must be configured with its own.
var knownDoHBootstrap = map[string][]string{
	"cloudflare-dns.com": {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"},
	"one.one.one.one":    {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"},
}

// DefaultDoHBootstrap returns the built-in bootstrap addresses for a DoH
// endpoint, or nil when the endpoint is not one dproxy ships knowledge of.
func DefaultDoHBootstrap(endpoint *url.URL) []netip.Addr {
	if endpoint == nil {
		return nil
	}
	entries, known := knownDoHBootstrap[strings.ToLower(endpoint.Hostname())]
	if !known {
		return nil
	}
	addresses := make([]netip.Addr, 0, len(entries))
	for _, entry := range entries {
		address, err := netip.ParseAddr(entry)
		if err != nil {
			// A compile-time constant, so this is a programming error.
			panic("config: built-in bootstrap address is invalid: " + entry)
		}
		addresses = append(addresses, address)
	}
	return addresses
}

// ParseBootstrapAddresses validates operator-supplied bootstrap addresses.
func ParseBootstrapAddresses(entries []string) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(entries))
	for _, entry := range entries {
		address, err := netip.ParseAddr(strings.TrimSpace(entry))
		if err != nil {
			return nil, fmt.Errorf("bootstrap address %q is not an IP address", entry)
		}
		if err := validateBootstrapAddress(address); err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

// validateBootstrapAddress rejects an address nothing can be dialed at.
func validateBootstrapAddress(address netip.Addr) error {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return fmt.Errorf("bootstrap address %s is not dialable", address)
	}
	return nil
}

// validateDoHBootstrap checks that the resolver can be reached without the
// operating system resolver.
func validateDoHBootstrap(endpoint *url.URL, addresses []netip.Addr) error {
	for _, address := range addresses {
		if err := validateBootstrapAddress(address); err != nil {
			return err
		}
	}
	if len(addresses) != 0 {
		return nil
	}
	if endpoint == nil {
		return errors.New("DoH URL is required")
	}
	if _, err := netip.ParseAddr(endpoint.Hostname()); err == nil {
		return nil
	}
	return fmt.Errorf(
		"DoH endpoint %s has no bootstrap addresses; dproxy will not ask the operating system resolver for one (--doh-bootstrap)",
		endpoint.Hostname())
}
