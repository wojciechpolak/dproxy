// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package policy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// maxHostnameLength is the DNS limit on a presentation-form name, excluding
// the root label.
const maxHostnameLength = 253

// PatternKind distinguishes the two shapes an allowlist entry may take.
type PatternKind int

const (
	// PatternExact matches one hostname and nothing else.
	PatternExact PatternKind = iota
	// PatternWildcard matches any name with at least one label in front of
	// the suffix. It does not match the bare suffix: "*.example.com" does
	// not allow "example.com".
	PatternWildcard
)

// String implements fmt.Stringer.
func (k PatternKind) String() string {
	switch k {
	case PatternExact:
		return "exact"
	case PatternWildcard:
		return "wildcard"
	default:
		return fmt.Sprintf("PatternKind(%d)", int(k))
	}
}

// HostPattern is one validated allowlist entry. Only ParseHostPattern builds
// one, so it is always canonical: lower-case, no trailing dot, not an IP
// literal.
type HostPattern struct {
	kind PatternKind
	// host is the whole name for PatternExact, the part after "*." for
	// PatternWildcard.
	host string
}

// Kind reports whether the pattern is exact or a wildcard.
func (p HostPattern) Kind() PatternKind { return p.kind }

// Suffix returns the canonical name the pattern is built from.
func (p HostPattern) Suffix() string { return p.host }

// String returns the pattern in the syntax ParseHostPattern accepts.
func (p HostPattern) String() string {
	if p.kind == PatternWildcard {
		return "*." + p.host
	}
	return p.host
}

// Matches reports whether the pattern permits the destination's hostname. It
// takes a Destination because only this package can build one, so an
// uncanonicalized name cannot be tested against an allowlist at all.
func (p HostPattern) Matches(d Destination) bool {
	return p.matches(d.host)
}

// matches applies the pattern to an already-canonical hostname.
//
// The wildcard case is where suffix confusion lives. A plain HasSuffix would
// let "evilexample.com" match "*.example.com", so the character in front of the
// suffix must be the label separator; the length test rejects the bare suffix
// and the empty first label.
func (p HostPattern) matches(host string) bool {
	if host == "" {
		return false
	}
	switch p.kind {
	case PatternExact:
		return host == p.host
	case PatternWildcard:
		if len(host) <= len(p.host)+1 {
			return false
		}
		if !strings.HasSuffix(host, p.host) {
			return false
		}
		return host[len(host)-len(p.host)-1] == '.'
	default:
		return false
	}
}

// ErrEmptyPattern reports an allowlist entry with no content.
var ErrEmptyPattern = errors.New("empty host pattern")

// InvalidPatternError reports an unusable allowlist entry. The text is kept
// because it comes from the operator's configuration, not from the network.
type InvalidPatternError struct {
	Pattern string
	Reason  string
}

func (e *InvalidPatternError) Error() string {
	return fmt.Sprintf("invalid host pattern %q: %s", e.Pattern, e.Reason)
}

// ParseHostPattern validates and canonicalizes one allowlist entry: case
// folding, trailing root dot removed, anything not a plain ASCII hostname
// rejected. Internationalized names must be given in A-label form — a
// non-ASCII entry is rejected rather than converted, so no name can be
// silently reinterpreted into a different one.
func ParseHostPattern(raw string) (HostPattern, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return HostPattern{}, ErrEmptyPattern
	}
	kind := PatternExact
	host := trimmed
	if suffix, found := strings.CutPrefix(trimmed, "*."); found {
		kind = PatternWildcard
		host = suffix
	}
	canonical, _, err := canonicalHostname(host)
	if err != nil {
		return HostPattern{}, &InvalidPatternError{Pattern: trimmed, Reason: err.Error()}
	}
	if kind == PatternWildcard && !strings.Contains(canonical, ".") {
		return HostPattern{}, &InvalidPatternError{
			Pattern: trimmed,
			Reason:  "a wildcard needs a suffix of at least two labels",
		}
	}
	return HostPattern{kind: kind, host: canonical}, nil
}

// canonicalHostname lower-cases a name, drops a trailing root dot, and rejects
// anything that is not a valid ASCII hostname, IP literals included. The
// returned DenyReason keeps "this is an address" distinguishable from "this is
// not a hostname" all the way out to the OPEN_ERROR code.
func canonicalHostname(raw string) (string, DenyReason, error) {
	host := strings.TrimSuffix(raw, ".")
	if host == "" {
		return "", DenyMalformedAuthority, errors.New("no labels")
	}
	if len(host) > maxHostnameLength {
		return "", DenyMalformedAuthority, fmt.Errorf("longer than %d characters", maxHostnameLength)
	}
	if strings.ContainsAny(host, "*") {
		return "", DenyMalformedAuthority, errors.New("a wildcard is only allowed as a leading \"*.\" label")
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return "", DenyIPLiteral, errors.New("IP literals are never permitted")
	}
	lowered := strings.ToLower(host)
	for _, label := range strings.Split(lowered, ".") {
		if err := validateLabel(label); err != nil {
			return "", DenyMalformedAuthority, err
		}
	}
	return lowered, DenyNone, nil
}

func validateLabel(label string) error {
	if label == "" {
		return errors.New("contains an empty label")
	}
	if len(label) > 63 {
		return fmt.Errorf("label %q is longer than 63 characters", label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q starts or ends with a hyphen", label)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return fmt.Errorf("label %q contains an unsupported character", label)
		}
	}
	return nil
}

// Allowlist is either an unrestricted destination policy or an ordered,
// deduplicated set of validated host patterns. The zero value permits nothing.
type Allowlist struct {
	patterns []HostPattern
	all      bool
}

// AllowAll returns a policy that permits every valid hostname. Port and
// resolved-address checks still apply.
func AllowAll() Allowlist { return Allowlist{all: true} }

// NewAllowlist builds a list from already-parsed patterns.
func NewAllowlist(patterns ...HostPattern) Allowlist {
	list := Allowlist{}
	for _, pattern := range patterns {
		list.add(pattern)
	}
	return list
}

func (a *Allowlist) add(pattern HostPattern) {
	for _, existing := range a.patterns {
		if existing == pattern {
			return
		}
	}
	a.patterns = append(a.patterns, pattern)
}

// Patterns returns a copy of the patterns, in configuration order.
func (a Allowlist) Patterns() []HostPattern {
	return append([]HostPattern(nil), a.patterns...)
}

// Len reports how many patterns the list carries.
func (a Allowlist) Len() int { return len(a.patterns) }

// IsEmpty reports a list that permits nothing.
func (a Allowlist) IsEmpty() bool { return !a.all && len(a.patterns) == 0 }

// AllowsAll reports whether the list permits every valid hostname.
func (a Allowlist) AllowsAll() bool { return a.all }

// String renders the list for diagnostics.
func (a Allowlist) String() string {
	if a.all {
		return "all"
	}
	parts := make([]string, 0, len(a.patterns))
	for _, pattern := range a.patterns {
		parts = append(parts, pattern.String())
	}
	return strings.Join(parts, " ")
}

// Permits decides whether a destination may be reached. Both components run
// it, from the same configuration type.
//
// The port check repeats NewDestination's: a Destination from a decoded OPEN
// crossed the network, and the remote never trusts the local side's checks.
func (a Allowlist) Permits(d Destination) Decision {
	if d.IsZero() {
		return Deny(DenyMalformedAuthority)
	}
	if d.port != AllowedPort {
		return Deny(DenyPortNotAllowed)
	}
	if a.all {
		return Allow()
	}
	for _, pattern := range a.patterns {
		if pattern.matches(d.host) {
			return Allow()
		}
	}
	return Deny(DenyNotAllowlisted)
}

// ParseAllowlist validates a sequence of pattern strings, reporting the first
// invalid entry rather than skipping it: a typo must not silently narrow or
// widen what is reachable.
func ParseAllowlist(entries []string) (Allowlist, error) {
	list := Allowlist{}
	for _, entry := range entries {
		pattern, err := ParseHostPattern(entry)
		if err != nil {
			return Allowlist{}, err
		}
		list.add(pattern)
	}
	return list, nil
}

// ReadAllowlist parses the allowlist file format: one pattern per line, "#"
// comments, blank lines ignored.
func ReadAllowlist(r io.Reader) (Allowlist, error) {
	scanner := bufio.NewScanner(r)
	list := Allowlist{}
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		pattern, err := ParseHostPattern(text)
		if err != nil {
			return Allowlist{}, fmt.Errorf("line %d: %w", line, err)
		}
		list.add(pattern)
	}
	if err := scanner.Err(); err != nil {
		return Allowlist{}, fmt.Errorf("read allowlist: %w", err)
	}
	return list, nil
}
