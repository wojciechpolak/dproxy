// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "0123456789abcdef0123456789abcdef"

func writeToken(t *testing.T, content string, mode os.FileMode) TokenFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return TokenFile(path)
}

func TestTokenFileRead(t *testing.T) {
	file := writeToken(t, secret+"\n", 0o600)
	token, err := file.Read()
	if err != nil {
		t.Fatalf("Read() = %v", err)
	}
	if token.Len() != len(secret) {
		t.Errorf("Len() = %d, want %d", token.Len(), len(secret))
	}
	if !token.EqualBytes([]byte(secret)) {
		t.Error("EqualBytes(secret) = false; the trailing newline changed the secret")
	}
	if token.EqualBytes([]byte(secret + "x")) {
		t.Error("EqualBytes accepted a different secret")
	}
	other, err := NewToken([]byte(secret))
	if err != nil {
		t.Fatalf("NewToken = %v", err)
	}
	if !token.Equal(other) {
		t.Error("Equal = false for identical secrets")
	}
}

func TestTokenFileRejects(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		file := writeToken(t, "short", 0o600)
		if _, err := file.Read(); err == nil || !strings.Contains(err.Error(), "at least 32") {
			t.Fatalf("Read() = %v, want a minimum-length error", err)
		}
	})
	t.Run("group readable", func(t *testing.T) {
		file := writeToken(t, secret, 0o640)
		if _, err := file.Read(); err == nil || !strings.Contains(err.Error(), "too open") {
			t.Fatalf("Read() = %v, want a permissions error", err)
		}
	})
	t.Run("world readable", func(t *testing.T) {
		file := writeToken(t, secret, 0o644)
		if _, err := file.Read(); err == nil || !strings.Contains(err.Error(), "too open") {
			t.Fatalf("Read() = %v, want a permissions error", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		file := TokenFile(filepath.Join(t.TempDir(), "absent"))
		if _, err := file.Read(); err == nil {
			t.Fatal("Read() accepted a missing token file")
		}
	})
	t.Run("unconfigured", func(t *testing.T) {
		var file TokenFile
		if _, err := file.Read(); err == nil {
			t.Fatal("Read() accepted an empty path")
		}
	})
	t.Run("directory", func(t *testing.T) {
		file := TokenFile(t.TempDir())
		if _, err := file.Read(); err == nil {
			t.Fatal("Read() accepted a directory")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		file := writeToken(t, strings.Repeat("a", maxTokenBytes+1), 0o600)
		if _, err := file.Read(); err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("Read() = %v, want a size error", err)
		}
	})
}

// TestTokenNeverFormatsItsSecret: every path that turns a value into text must
// redact, whatever verb is used.
func TestTokenNeverFormatsItsSecret(t *testing.T) {
	token, err := NewToken([]byte(secret))
	if err != nil {
		t.Fatalf("NewToken = %v", err)
	}
	holder := struct {
		Name  string
		Token Token
	}{Name: "client", Token: token}

	rendered := []string{
		token.String(),
		token.GoString(),
		fmt.Sprint(token),
		fmt.Sprintf("%v", token),
		fmt.Sprintf("%+v", token),
		fmt.Sprintf("%#v", token),
		fmt.Sprintf("%s", token),
		fmt.Sprintf("%q", token),
		fmt.Sprintf("%x", token),
		fmt.Sprintf("%v", holder),
		fmt.Sprintf("%+v", holder),
	}
	for _, text := range rendered {
		if strings.Contains(text, secret) {
			t.Errorf("formatted output leaked the token: %s", text)
		}
		if !strings.Contains(text, "redacted") {
			t.Errorf("formatted output is not redacted: %s", text)
		}
	}

	var buffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buffer, nil))
	logger.Info("authenticating", "token", token, "token_file", TokenFile("/run/secrets/dproxy-token"))
	if strings.Contains(buffer.String(), secret) {
		t.Errorf("slog leaked the token: %s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "/run/secrets/dproxy-token") {
		t.Errorf("slog dropped the token path, which is not a secret: %s", buffer.String())
	}
}

func TestNewTokenRejectsShortSecret(t *testing.T) {
	if _, err := NewToken(bytes.Repeat([]byte("a"), MinTokenBytes-1)); err == nil {
		t.Fatal("NewToken accepted a secret below the minimum length")
	}
	if _, err := NewToken(bytes.Repeat([]byte("a"), maxTokenBytes+1)); err == nil {
		t.Fatal("NewToken accepted a secret above the maximum length")
	}
	var zero Token
	if !zero.IsZero() {
		t.Error("zero Token reports IsZero() = false")
	}
	if zero.EqualBytes(nil) {
		t.Error("the zero Token compared equal to an empty secret")
	}
}

func TestTokenFileReadSetSupportsOneRotationOverlap(t *testing.T) {
	oldSecret := strings.Repeat("o", MinTokenBytes)
	file := writeToken(t, secret+"\n"+oldSecret+"\n", 0o600)
	set, err := file.ReadSet()
	if err != nil {
		t.Fatalf("ReadSet: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}
	for _, raw := range []string{secret, oldSecret} {
		token, err := NewToken([]byte(raw))
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if !set.Contains(token) {
			t.Error("ReadSet did not accept a configured token")
		}
	}
	other, err := NewToken([]byte(strings.Repeat("x", MinTokenBytes)))
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if set.Contains(other) {
		t.Error("ReadSet accepted an unconfigured token")
	}
}

func TestTokenFileReadSetRejectsTooManyTokens(t *testing.T) {
	contents := strings.Repeat("a", MinTokenBytes) + "\n" +
		strings.Repeat("b", MinTokenBytes) + "\n" + strings.Repeat("c", MinTokenBytes)
	if _, err := writeToken(t, contents, 0o600).ReadSet(); err == nil {
		t.Fatal("ReadSet accepted more than two active tokens")
	}
}
