// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build e2e_fixture

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wojciechpolak/dproxy/internal/tunnel"
)

const (
	originAddress = "9.9.9.2"
	originHost    = "origin.e2e.test"
	resolverHost  = "resolver.e2e.test"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: fixture init|serve DIRECTORY")
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initialize(os.Args[2])
	case "serve":
		err = serve(os.Args[2])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func initialize(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	ca, caKey, caPEM, err := newCA()
	if err != nil {
		return err
	}
	if err := writeFile(directory, "ca.pem", caPEM, 0o644); err != nil {
		return err
	}
	for _, hostname := range []string{originHost, resolverHost} {
		certificate, key, err := signedCertificate(ca, caKey, hostname)
		if err != nil {
			return err
		}
		base := hostname[:len(hostname)-len(".e2e.test")]
		if err := writeFile(directory, base+".pem", certificate, 0o644); err != nil {
			return err
		}
		if err := writeFile(directory, base+".key", key, 0o600); err != nil {
			return err
		}
	}
	token := []byte("docker-e2e-token-119bb1bb996a4f42a7c9a8f5800c5af7\n")
	if err := writeFile(directory, "token", token, 0o600); err != nil {
		return err
	}
	identity, err := tunnel.LoadOrCreateIdentity(filepath.Join(directory, "identity.pem"))
	if err != nil {
		return err
	}
	if err := writeFile(directory, "pin", []byte(identity.Pin.String()+"\n"), 0o600); err != nil {
		return err
	}
	configuration := []byte(`listen = "0.0.0.0:8686"
identity_file = "/run/e2e/identity.pem"
token_file = "/run/e2e/token"
doh_url = "https://resolver.e2e.test:8443/dns-query"
doh_bootstrap = ["9.9.9.2"]
allowlist = ["origin.e2e.test"]

[timeouts]
dial = "2s"
tls_handshake = "2s"
control = "2s"
idle = "10s"
max_lifetime = "0s"
shutdown = "2s"

[limits]
max_sessions = 8
max_control_message_bytes = 4096

[log]
level = "debug"
format = "text"
include_targets = false
`)
	return writeFile(directory, "server.toml", configuration, 0o600)
}

func serve(directory string) error {
	originCertificate, err := tls.LoadX509KeyPair(
		filepath.Join(directory, "origin.pem"), filepath.Join(directory, "origin.key"),
	)
	if err != nil {
		return err
	}
	resolverCertificate, err := tls.LoadX509KeyPair(
		filepath.Join(directory, "resolver.pem"), filepath.Join(directory, "resolver.key"),
	)
	if err != nil {
		return err
	}
	var wait sync.WaitGroup
	errors := make(chan error, 2)
	wait.Add(2)
	go func() {
		defer wait.Done()
		errors <- serveOrigin(originCertificate)
	}()
	go func() {
		defer wait.Done()
		errors <- serveDoH(resolverCertificate)
	}()
	err = <-errors
	return err
}

func serveOrigin(certificate tls.Certificate) error {
	listener, err := tls.Listen("tcp", ":443", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer func() { _ = conn.Close() }()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func serveDoH(certificate tls.Certificate) error {
	server := &http.Server{
		Addr: ":8443",
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost || request.URL.Path != "/dns-query" {
				http.NotFound(writer, request)
				return
			}
			query, err := io.ReadAll(io.LimitReader(request.Body, 65536))
			if err != nil {
				http.Error(writer, "bad query", http.StatusBadRequest)
				return
			}
			response, err := dnsResponse(query)
			if err != nil {
				http.Error(writer, "bad query", http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "application/dns-message")
			_, _ = writer.Write(response)
		}),
		ReadHeaderTimeout: 2 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		},
	}
	return server.ListenAndServeTLS("", "")
}

func dnsResponse(query []byte) ([]byte, error) {
	if len(query) < 17 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, errors.New("malformed DNS query")
	}
	offset := 12
	for {
		if offset >= len(query) {
			return nil, errors.New("truncated DNS name")
		}
		length := int(query[offset])
		offset++
		if length == 0 {
			break
		}
		if length > 63 || offset+length > len(query) {
			return nil, errors.New("invalid DNS label")
		}
		offset += length
	}
	if offset+4 != len(query) {
		return nil, errors.New("unexpected DNS query shape")
	}
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	answers := uint16(0)
	if qtype == 1 {
		answers = 1
	}
	response := make([]byte, 12, len(query)+16)
	copy(response[0:2], query[0:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], answers)
	response = append(response, query[12:]...)
	if answers == 1 {
		response = append(response, 0xc0, 0x0c)
		response = binary.BigEndian.AppendUint16(response, 1)
		response = binary.BigEndian.AppendUint16(response, 1)
		response = binary.BigEndian.AppendUint32(response, 60)
		response = binary.BigEndian.AppendUint16(response, 4)
		response = append(response, 9, 9, 9, 2)
	}
	return response, nil
}

func newCA() (*x509.Certificate, ed25519.PrivateKey, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dproxy E2E CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
}

func signedCertificate(ca *x509.Certificate, caKey ed25519.PrivateKey, hostname string) ([]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), nil
}

func writeFile(directory, name string, data []byte, mode os.FileMode) error {
	return os.WriteFile(filepath.Join(directory, name), data, mode)
}
