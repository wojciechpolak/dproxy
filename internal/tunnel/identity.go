// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/wojciechpolak/dproxy/internal/config"
	"github.com/wojciechpolak/dproxy/internal/privatepath"
)

const identityValidity = 10 * 365 * 24 * time.Hour

const maxIdentityFileBytes = 64 << 10

// identityRole selects the extended key usage of a generated identity. The
// verification path on both sides checks neither EKU nor chain, so this only
// records what a file was made for.
type identityRole uint8

const (
	roleServer identityRole = iota
	roleClient
)

// Identity is the remote's persistent inner-TLS identity and its operator
// pin. It contains no hostname because the client authenticates the SPKI.
type Identity struct {
	Certificate tls.Certificate
	Pin         config.Pin
}

// LoadOrCreateIdentity loads a PEM identity or creates the remote's Ed25519
// server identity at path. The parent directory is private when this function
// creates it. An existing directory's policy remains the operator's
// responsibility.
func LoadOrCreateIdentity(path string) (*Identity, error) {
	return loadOrCreateIdentity(path, roleServer)
}

// LoadOrCreateClientIdentity is the client half: the optional identity a local
// dproxy presents when the remote configures client pins.
func LoadOrCreateClientIdentity(path string) (*Identity, error) {
	return loadOrCreateIdentity(path, roleClient)
}

func loadOrCreateIdentity(path string, role identityRole) (*Identity, error) {
	if path == "" {
		return nil, errors.New("inner TLS identity file is not configured")
	}
	identity, err := LoadIdentity(path)
	if err == nil {
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	parent := filepath.Dir(path)
	_, statErr := os.Stat(parent)
	parentMissing := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !parentMissing {
		return nil, fmt.Errorf("stat identity directory: %w", statErr)
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create identity directory: %w", err)
	}
	if parentMissing {
		if err := privatepath.Restrict(parent, true); err != nil {
			return nil, fmt.Errorf("protect identity directory: %w", err)
		}
	}
	encoded, err := generateIdentityPEM(time.Now(), role)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return LoadIdentity(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create inner TLS identity: %w", err)
	}
	if err := privatepath.Restrict(path, false); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("protect inner TLS identity: %w", err)
	}
	writeErr := writeFull(file, encoded)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return nil, fmt.Errorf("write inner TLS identity: %w", writeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close inner TLS identity: %w", closeErr)
	}
	return LoadIdentity(path)
}

// LoadIdentity reads a PEM identity and rejects permissions that expose its
// private key to other users. It must never check the extended key usage:
// that would reject identities written by earlier versions and would stop an
// existing server identity being reused as a client identity.
func LoadIdentity(path string) (*Identity, error) {
	// #nosec G304 -- path is the operator's configured identity file.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("inner TLS identity: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat inner TLS identity: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("inner TLS identity %s is a directory", path)
	}
	if err := privatepath.Validate(path, info); err != nil {
		return nil, fmt.Errorf("inner TLS identity: %w", err)
	}
	if info.Size() > maxIdentityFileBytes {
		return nil, fmt.Errorf("inner TLS identity %s is larger than %d bytes", path, maxIdentityFileBytes)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxIdentityFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read inner TLS identity: %w", err)
	}
	certificate, err := tls.X509KeyPair(encoded, encoded)
	if err != nil {
		return nil, fmt.Errorf("parse inner TLS identity: %w", err)
	}
	if len(certificate.Certificate) != 1 {
		return nil, fmt.Errorf("parse inner TLS identity: got %d certificates, want one", len(certificate.Certificate))
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse inner TLS certificate: %w", err)
	}
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("parse inner TLS identity: public key is %T, want Ed25519", leaf.PublicKey)
	}
	certificate.Leaf = leaf
	return &Identity{Certificate: certificate, Pin: config.PinFromSPKI(leaf.RawSubjectPublicKeyInfo)}, nil
}

func generateIdentityPEM(now time.Time, role identityRole) ([]byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate inner TLS key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generate inner TLS certificate serial: %w", err)
	}
	usage := x509.ExtKeyUsageServerAuth
	if role == roleClient {
		usage = x509.ExtKeyUsageClientAuth
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dproxy inner TLS"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(identityValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create inner TLS certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal inner TLS key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	encoded = append(encoded, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})...)
	return encoded, nil
}
