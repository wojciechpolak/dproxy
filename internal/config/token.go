// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
)

// MinTokenBytes is the shortest shared secret dproxy accepts. A shorter file
// is a configuration error, not a weaker deployment.
const MinTokenBytes = 32

// maxTokenBytes fits a token plus the HELLO type and version in the default
// 4096-byte control-message limit. It also makes pointing --token-file at the
// wrong file fail quickly.
const maxTokenBytes = 4094

// MaxServerTokens permits one active token and one previous token during a
// rotation overlap. More entries are a configuration error.
const MaxServerTokens = 2

// TokenFile is a path to the shared secret, a distinct type so it can never be
// passed where the secret itself is expected.
type TokenFile string

// String returns the path. The path is not the secret.
func (f TokenFile) String() string { return string(f) }

// Token is the shared secret in memory. String, GoString, Format, and LogValue
// all redact, so it cannot reach a log through fmt, slog, or %+v.
type Token struct {
	value []byte
}

// TokenSet is the remote's accepted token set. The zero value authenticates
// nothing. It holds fixed-size digests of at most two tokens so rotation cannot
// grow into an unbounded list of live credentials and different token lengths
// do not alter comparison time.
type TokenSet struct {
	digests [][sha256.Size]byte
}

// redactedToken is what any formatting of a Token produces.
const redactedToken = "[redacted]"

// String implements fmt.Stringer with redaction.
func (t Token) String() string { return redactedToken }

// GoString implements fmt.GoStringer with redaction, covering %#v.
func (t Token) GoString() string { return redactedToken }

// Format covers every other verb, including %s, %q, %x, and %v.
func (t Token) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		fmt.Fprintf(f, "%q", redactedToken)
	default:
		fmt.Fprint(f, redactedToken)
	}
}

// LogValue implements slog.LogValuer so a token logged as an attribute value
// is redacted too.
func (t Token) LogValue() slog.Value { return slog.StringValue(redactedToken) }

// IsZero reports a token that was never loaded.
func (t Token) IsZero() bool { return len(t.value) == 0 }

// Len reports the secret's length, which is not sensitive.
func (t Token) Len() int { return len(t.value) }

// Bytes returns a copy of the secret. Callers must not log the result.
func (t Token) Bytes() []byte { return append([]byte(nil), t.value...) }

// Equal compares two tokens in constant time. An unloaded token equals
// nothing: ConstantTimeCompare calls two empty slices equal, which would let an
// unconfigured secret authenticate an empty one.
func (t Token) Equal(other Token) bool {
	if t.IsZero() || other.IsZero() {
		return false
	}
	return subtle.ConstantTimeCompare(t.value, other.value) == 1
}

// EqualBytes compares a received secret against this token in constant time,
// false for an unloaded token as in Equal.
func (t Token) EqualBytes(candidate []byte) bool {
	if t.IsZero() || len(candidate) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(t.value, candidate) == 1
}

// NewTokenSet validates and copies the active tokens.
func NewTokenSet(tokens ...Token) (TokenSet, error) {
	if len(tokens) == 0 {
		return TokenSet{}, errors.New("token set is empty")
	}
	if len(tokens) > MaxServerTokens {
		return TokenSet{}, fmt.Errorf("token set has %d entries, want at most %d", len(tokens), MaxServerTokens)
	}
	set := TokenSet{digests: make([][sha256.Size]byte, len(tokens))}
	for index, token := range tokens {
		if token.IsZero() {
			return TokenSet{}, fmt.Errorf("token set entry %d is empty", index+1)
		}
		set.digests[index] = sha256.Sum256(token.value)
	}
	return set, nil
}

// Len reports the number of accepted tokens.
func (s TokenSet) Len() int { return len(s.digests) }

// Contains compares a candidate with every configured token. It does not
// return early when one matches, so rotation order does not affect timing.
func (s TokenSet) Contains(candidate Token) bool {
	if candidate.IsZero() || len(s.digests) == 0 {
		return false
	}
	candidateDigest := sha256.Sum256(candidate.value)
	matched := 0
	for _, digest := range s.digests {
		matched |= subtle.ConstantTimeCompare(digest[:], candidateDigest[:])
	}
	return matched == 1
}

// NewToken wraps raw secret bytes, enforcing the minimum length.
func NewToken(value []byte) (Token, error) {
	if len(value) < MinTokenBytes {
		return Token{}, fmt.Errorf("token is %d bytes, want at least %d", len(value), MinTokenBytes)
	}
	if len(value) > maxTokenBytes {
		return Token{}, fmt.Errorf("token is %d bytes, want at most %d", len(value), maxTokenBytes)
	}
	return Token{value: append([]byte(nil), value...)}, nil
}

// Read loads the token, enforcing restrictive permissions and the minimum
// length. Surrounding whitespace is trimmed so a trailing newline is not part
// of the secret. No error here contains file contents.
func (f TokenFile) Read() (Token, error) {
	if f == "" {
		return Token{}, errors.New("token file is not configured")
	}
	info, err := os.Stat(string(f))
	if err != nil {
		return Token{}, fmt.Errorf("token file: %w", err)
	}
	if info.IsDir() {
		return Token{}, fmt.Errorf("token file %s is a directory", f)
	}
	if permissionErr := checkTokenPermissions(info.Mode()); permissionErr != nil {
		return Token{}, fmt.Errorf("token file %s: %w", f, permissionErr)
	}
	if info.Size() > maxTokenBytes {
		return Token{}, fmt.Errorf("token file %s is larger than %d bytes", f, maxTokenBytes)
	}
	raw, err := os.ReadFile(string(f))
	if err != nil {
		return Token{}, fmt.Errorf("token file: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	token, err := NewToken([]byte(trimmed))
	if err != nil {
		return Token{}, fmt.Errorf("token file %s: %w", f, err)
	}
	return token, nil
}

// ReadSet loads one token per non-empty line for the remote. A second line is
// the previous token accepted during rotation. Clients use Read and therefore
// still send exactly one token.
func (f TokenFile) ReadSet() (TokenSet, error) {
	if f == "" {
		return TokenSet{}, errors.New("token file is not configured")
	}
	info, err := os.Stat(string(f))
	if err != nil {
		return TokenSet{}, fmt.Errorf("token file: %w", err)
	}
	if info.IsDir() {
		return TokenSet{}, fmt.Errorf("token file %s is a directory", f)
	}
	if permissionErr := checkTokenPermissions(info.Mode()); permissionErr != nil {
		return TokenSet{}, fmt.Errorf("token file %s: %w", f, permissionErr)
	}
	maxFileBytes := int64(MaxServerTokens * (maxTokenBytes + 1))
	if info.Size() > maxFileBytes {
		return TokenSet{}, fmt.Errorf("token file %s is larger than %d bytes", f, maxFileBytes)
	}
	raw, err := os.ReadFile(string(f))
	if err != nil {
		return TokenSet{}, fmt.Errorf("token file: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	tokens := make([]Token, 0, len(lines))
	for lineNumber, line := range lines {
		value := strings.TrimSpace(line)
		if value == "" {
			continue
		}
		token, err := NewToken([]byte(value))
		if err != nil {
			return TokenSet{}, fmt.Errorf("token file %s line %d: %w", f, lineNumber+1, err)
		}
		tokens = append(tokens, token)
	}
	set, err := NewTokenSet(tokens...)
	if err != nil {
		return TokenSet{}, fmt.Errorf("token file %s: %w", f, err)
	}
	return set, nil
}

// checkTokenPermissions rejects a secret that group or others can read.
func checkTokenPermissions(mode fs.FileMode) error {
	if mode&0o077 != 0 {
		return fmt.Errorf("permissions %#o are too open; use 0600", mode.Perm())
	}
	return nil
}
