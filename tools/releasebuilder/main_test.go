// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParseTargets(t *testing.T) {
	want := []target{{goos: "darwin", goarch: "arm64"}, {goos: "linux", goarch: "amd64"}}
	got, err := parseTargets("darwin/arm64, linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets() = %#v, want %#v", got, want)
	}
	for _, value := range []string{"", "darwin", "darwin/arm64/extra", "darwin/arm64,darwin/arm64"} {
		if _, err := parseTargets(value); err == nil {
			t.Errorf("parseTargets(%q) unexpectedly succeeded", value)
		}
	}
}

func TestVersionPattern(t *testing.T) {
	for _, value := range []string{"v0.1.0", "v12.34.56-rc.1", "v1.2.3+build.4"} {
		if !versionPattern.MatchString(value) {
			t.Errorf("%q should be accepted", value)
		}
	}
	for _, value := range []string{"1.2.3", "v1.2", "v01.2.3", "v1.2.3/../../x"} {
		if versionPattern.MatchString(value) {
			t.Errorf("%q should be rejected", value)
		}
	}
}

func TestWriteArchiveIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "dproxy")
	license := filepath.Join(dir, "LICENSE")
	if err := os.WriteFile(binary, []byte("binary bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(license, []byte("license text"), 0o644); err != nil {
		t.Fatal(err)
	}
	files := []archivedFile{
		{name: "dproxy", path: binary, mode: 0o755},
		{name: "LICENSE", path: license, mode: 0o644},
	}
	epoch := time.Unix(1_700_000_000, 0).UTC()
	one := filepath.Join(dir, "one.tar.gz")
	two := filepath.Join(dir, "two.tar.gz")
	if err := writeArchive(one, append([]archivedFile(nil), files...), epoch); err != nil {
		t.Fatal(err)
	}
	if err := writeArchive(two, append([]archivedFile(nil), files...), epoch); err != nil {
		t.Fatal(err)
	}
	oneBytes, err := os.ReadFile(one)
	if err != nil {
		t.Fatal(err)
	}
	twoBytes, err := os.ReadFile(two)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(oneBytes, twoBytes) {
		t.Fatal("archives made from the same inputs differ")
	}

	input, err := os.Open(one)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	gzipReader, err := gzip.NewReader(input)
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(gzipReader)
	want := []struct {
		name string
		mode int64
	}{{name: "LICENSE", mode: 0o644}, {name: "dproxy", mode: 0o755}}
	for _, expected := range want {
		header, err := tarReader.Next()
		if err != nil {
			t.Fatal(err)
		}
		if header.Name != expected.name || header.Mode != expected.mode || !header.ModTime.Equal(epoch) {
			t.Errorf("header = %s %o %s", header.Name, header.Mode, header.ModTime)
		}
	}
}
