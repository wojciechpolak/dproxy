// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Command releasebuilder cross-compiles dproxy and writes deterministic
// release binaries, archives, and their SHA-256 manifest.
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultTargets = "darwin/arm64,darwin/amd64,linux/arm64,linux/amd64"

var versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

type target struct {
	goos   string
	goarch string
}

type archivedFile struct {
	name string
	path string
	mode int64
}

func main() {
	tag := flag.String("tag", "", "semantic version tag, including the leading v")
	output := flag.String("output", "dist", "directory for release files")
	targetList := flag.String("targets", defaultTargets, "comma-separated GOOS/GOARCH targets")
	flag.Parse()

	if !versionPattern.MatchString(*tag) {
		fatalf("tag %q is not a semantic version such as v1.2.3", *tag)
	}
	targets, err := parseTargets(*targetList)
	if err != nil {
		fatalf("%v", err)
	}
	epoch, err := sourceDateEpoch()
	if err != nil {
		fatalf("%v", err)
	}
	if err := buildRelease(*tag, *output, targets, epoch); err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "releasebuilder: "+format+"\n", args...)
	os.Exit(1)
}

func parseTargets(value string) ([]target, error) {
	parts := strings.Split(value, ",")
	targets := make([]target, 0, len(parts))
	seen := make(map[target]bool)
	for _, part := range parts {
		fields := strings.Split(strings.TrimSpace(part), "/")
		if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
			return nil, fmt.Errorf("invalid target %q; want GOOS/GOARCH", part)
		}
		item := target{goos: fields[0], goarch: fields[1]}
		if seen[item] {
			return nil, fmt.Errorf("duplicate target %q", part)
		}
		seen[item] = true
		targets = append(targets, item)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	return targets, nil
}

func sourceDateEpoch() (time.Time, error) {
	value := os.Getenv("SOURCE_DATE_EPOCH")
	if value == "" {
		return time.Unix(0, 0).UTC(), nil
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds < 0 {
		return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH must be a non-negative Unix timestamp")
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func buildRelease(tag, output string, targets []target, epoch time.Time) error {
	if err := os.MkdirAll(output, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	work, err := os.MkdirTemp("", "dproxy-release-")
	if err != nil {
		return fmt.Errorf("create work directory: %w", err)
	}
	defer os.RemoveAll(work)

	license, err := filepath.Abs("LICENSE")
	if err != nil {
		return fmt.Errorf("resolve LICENSE: %w", err)
	}
	var artifacts []string
	for _, item := range targets {
		binary := filepath.Join(work, item.goos+"_"+item.goarch, "dproxy")
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			return fmt.Errorf("create target work directory: %w", err)
		}
		if err := buildBinary(tag, item, binary); err != nil {
			return err
		}
		directName := fmt.Sprintf("dproxy-%s-%s", item.goos, item.goarch)
		directPath := filepath.Join(output, directName)
		contents, err := os.ReadFile(binary)
		if err != nil {
			return fmt.Errorf("read %s binary: %w", directName, err)
		}
		if err := os.WriteFile(directPath, contents, 0o755); err != nil {
			return fmt.Errorf("write %s: %w", directName, err)
		}
		artifacts = append(artifacts, directPath)

		name := fmt.Sprintf("dproxy_%s_%s_%s.tar.gz", tag, item.goos, item.goarch)
		path := filepath.Join(output, name)
		files := []archivedFile{
			{name: "LICENSE", path: license, mode: 0o644},
			{name: "dproxy", path: binary, mode: 0o755},
		}
		if err := writeArchive(path, files, epoch); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		artifacts = append(artifacts, path)
	}
	return writeChecksums(filepath.Join(output, "SHA256SUMS"), artifacts)
}

func buildBinary(tag string, item target, output string) error {
	ldflags := "-buildid= -s -w -X main.version=" + tag
	goExecutable := os.Getenv("GO")
	if goExecutable == "" {
		goExecutable = "go"
	}
	command := exec.Command(goExecutable, "build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags, "-o", output, "./cmd/dproxy")
	command.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+item.goos,
		"GOARCH="+item.goarch,
	)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("build %s/%s: %w", item.goos, item.goarch, err)
	}
	return nil
}

func writeArchive(path string, files []archivedFile, epoch time.Time) (err error) {
	output, err := os.Create(path) // #nosec G304 -- the release operator supplies the output directory.
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := output.Close(); err == nil {
			err = closeErr
		}
	}()

	gzipWriter, err := gzip.NewWriterLevel(output, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)

	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	for _, file := range files {
		contents, readErr := os.ReadFile(file.path) // #nosec G304 -- paths are created by this release builder.
		if readErr != nil {
			return readErr
		}
		header := &tar.Header{
			Name:       file.name,
			Mode:       file.mode,
			Size:       int64(len(contents)),
			ModTime:    epoch,
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
			Uid:        0,
			Gid:        0,
			Uname:      "root",
			Gname:      "root",
			Format:     tar.FormatUSTAR,
		}
		if writeErr := tarWriter.WriteHeader(header); writeErr != nil {
			return writeErr
		}
		if _, writeErr := tarWriter.Write(contents); writeErr != nil {
			return writeErr
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	return gzipWriter.Close()
}

func writeChecksums(path string, artifacts []string) (err error) {
	sort.Strings(artifacts)
	output, err := os.Create(path) // #nosec G304 -- the release operator supplies the output directory.
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := output.Close(); err == nil {
			err = closeErr
		}
	}()
	for _, artifact := range artifacts {
		input, openErr := os.Open(artifact) // #nosec G304 -- paths are created by this release builder.
		if openErr != nil {
			return openErr
		}
		digest := sha256.New()
		_, copyErr := io.Copy(digest, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if _, err := fmt.Fprintf(output, "%x  %s\n", digest.Sum(nil), filepath.Base(artifact)); err != nil {
			return err
		}
	}
	return nil
}
