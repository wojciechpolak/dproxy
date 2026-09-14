// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wojciechpolak/dproxy/internal/privatepath"
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
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Errorf("identity mode = %#o, want 0600", got)
	}
	if err := privatepath.Validate(path, info); err != nil {
		t.Errorf("identity permissions: %v", err)
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
	if runtime.GOOS != "windows" {
		if _, err := LoadIdentity(path); err == nil {
			t.Fatal("LoadIdentity accepted group-readable key material")
		}
	}
	if err := privatepath.Restrict(path, false); err != nil {
		t.Fatalf("protect identity: %v", err)
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
	if err := privatepath.Restrict(oversized, false); err != nil {
		t.Fatalf("protect oversized identity: %v", err)
	}
	if _, err := LoadIdentity(oversized); err == nil {
		t.Fatal("oversized identity was accepted")
	}
	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := privatepath.Restrict(parentFile, false); err != nil {
		t.Fatalf("protect parent file: %v", err)
	}
	if _, err := LoadOrCreateIdentity(filepath.Join(parentFile, "identity.pem")); err == nil {
		t.Fatal("identity creation under a regular file succeeded")
	}
	malformed := filepath.Join(t.TempDir(), "malformed.pem")
	if err := os.WriteFile(malformed, []byte("not PEM"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := privatepath.Restrict(malformed, false); err != nil {
		t.Fatalf("protect malformed identity: %v", err)
	}
	if _, err := LoadOrCreateIdentity(malformed); err == nil {
		t.Fatal("LoadOrCreateIdentity replaced a malformed identity")
	}
}

func TestLoadOrCreateIdentityKeepsServerExtendedKeyUsage(t *testing.T) {
	// Existing deployments hold identity files written by earlier versions.
	// Nothing about the server template may drift.
	identity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "identity.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	leaf := identity.Certificate.Leaf
	if got := leaf.Subject.CommonName; got != "dproxy inner TLS" {
		t.Errorf("common name = %q, want %q", got, "dproxy inner TLS")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("extended key usage = %v, want [ServerAuth]", leaf.ExtKeyUsage)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage = %v, want DigitalSignature", leaf.KeyUsage)
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		t.Errorf("public key = %T, want Ed25519", leaf.PublicKey)
	}
}

func TestLoadOrCreateClientIdentityUsesClientExtendedKeyUsage(t *testing.T) {
	identity, err := LoadOrCreateClientIdentity(filepath.Join(t.TempDir(), "client-identity.pem"))
	if err != nil {
		t.Fatalf("LoadOrCreateClientIdentity: %v", err)
	}
	leaf := identity.Certificate.Leaf
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("extended key usage = %v, want [ClientAuth]", leaf.ExtKeyUsage)
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		t.Errorf("public key = %T, want Ed25519", leaf.PublicKey)
	}
}

func TestLoadIdentityAcceptsEitherRole(t *testing.T) {
	// A server identity written before client pins existed must still load and
	// be usable as a client identity: LoadIdentity must not check the usage.
	path := filepath.Join(t.TempDir(), "identity.pem")
	created, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	reused, err := LoadOrCreateClientIdentity(path)
	if err != nil {
		t.Fatalf("LoadOrCreateClientIdentity on a server identity: %v", err)
	}
	if reused.Pin != created.Pin {
		t.Errorf("pin changed on reload: %s want %s", reused.Pin, created.Pin)
	}
}
