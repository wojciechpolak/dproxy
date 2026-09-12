// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build !windows

package privatepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestrictAndValidateUnixPath(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Restrict(directory, true); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %#o, want 0700", got)
	}

	path := filepath.Join(directory, "token")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(path, info); err == nil {
		t.Fatal("Validate accepted group-readable permissions")
	}
	if err := Restrict(path, false); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %#o, want 0600", got)
	}
	if err := Validate(path, info); err != nil {
		t.Fatal(err)
	}
}
