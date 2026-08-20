// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIdentityPersistsEd25519Key(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "identity.pem")
	first, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("identity mode = %#o, want 0600", got)
	}
	if _, ok := first.Certificate.PrivateKey.(ed25519.PrivateKey); !ok {
		t.Errorf("private key = %T, want Ed25519", first.Certificate.PrivateKey)
	}
	second, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateIdentity: %v", err)
	}
	if first.Pin != second.Pin {
		t.Errorf("identity changed across loads: %s then %s", first.Pin, second.Pin)
	}
}

func TestLoadIdentityRejectsOpenPermissionsAndMalformedPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.pem")
	if err := os.WriteFile(path, []byte("not PEM"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Fatal("LoadIdentity accepted group-readable key material")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Fatal("LoadIdentity accepted malformed PEM")
	}
}

func TestIdentityFileBoundaryErrors(t *testing.T) {
	if _, err := LoadOrCreateIdentity(""); err == nil {
		t.Fatal("empty identity path was accepted")
	}
	directory := t.TempDir()
	if _, err := LoadIdentity(directory); err == nil {
		t.Fatal("identity directory was accepted")
	}
	oversized := filepath.Join(t.TempDir(), "oversized.pem")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, maxIdentityFileBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadIdentity(oversized); err == nil {
		t.Fatal("oversized identity was accepted")
	}
	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadOrCreateIdentity(filepath.Join(parentFile, "identity.pem")); err == nil {
		t.Fatal("identity creation under a regular file succeeded")
	}
	malformed := filepath.Join(t.TempDir(), "malformed.pem")
	if err := os.WriteFile(malformed, []byte("not PEM"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadOrCreateIdentity(malformed); err == nil {
		t.Fatal("LoadOrCreateIdentity replaced a malformed identity")
	}
}
