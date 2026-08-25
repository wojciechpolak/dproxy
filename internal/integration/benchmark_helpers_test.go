// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build e2e || docker_e2e

package integration_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
)

func bytePattern(size int) []byte {
	data := make([]byte, size)
	for index := range data {
		data[index] = byte((index*131 + index/251) & 0xff)
	}
	return data
}

func benchmarkRoundTrip(conn net.Conn, payload, scratch []byte) error {
	read := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, scratch)
		read <- err
	}()
	if err := writeAll(conn, payload); err != nil {
		return fmt.Errorf("write benchmark payload: %w", err)
	}
	if err := <-read; err != nil {
		return fmt.Errorf("read benchmark payload: %w", err)
	}
	if !bytes.Equal(scratch, payload) {
		return fmt.Errorf("benchmark payload changed: got %d bytes", len(scratch))
	}
	return nil
}

func benchmarkConcurrentRoundTrips(connections []net.Conn, payload []byte, scratch [][]byte) error {
	var wait sync.WaitGroup
	errors := make(chan error, len(connections))
	for index, conn := range connections {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := benchmarkRoundTrip(conn, payload, scratch[index]); err != nil {
				errors <- fmt.Errorf("session %d: %w", index, err)
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		return err
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		data = data[written:]
	}
	return nil
}
