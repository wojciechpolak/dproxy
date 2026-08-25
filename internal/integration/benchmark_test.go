// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build e2e

package integration_test

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"testing"
)

const (
	benchmarkPayloadSize  = 1 << 20
	concurrentPayloadSize = 64 << 10
)

// BenchmarkTunnelSetup measures HTTP CONNECT through OPEN_OK. Each operation
// includes TCP to the local proxy, outer TLS, WebSocket upgrade, pinned inner
// TLS, authentication, policy checks, resolution, and the origin TCP dial. It
// excludes the application's own TLS handshake.
func BenchmarkTunnelSetup(b *testing.B) {
	topology := newTopology(b, topologyOptions{})
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		response, conn := topology.connect(b, testOriginHost+":443")
		if response.StatusCode != http.StatusOK {
			_ = conn.Close()
			b.Fatalf("CONNECT status = %d, want 200", response.StatusCode)
		}
		if err := conn.Close(); err != nil {
			b.Fatalf("close tunnel: %v", err)
		}
	}
}

// BenchmarkSteadyStateThroughput measures aggregate bytes in both directions
// over one established tunnel. Tunnel and application TLS setup are excluded.
func BenchmarkSteadyStateThroughput(b *testing.B) {
	topology := newTopology(b, topologyOptions{})
	conn, _ := topology.openTLS(b)
	payload := bytePattern(benchmarkPayloadSize)
	scratch := make([]byte, len(payload))
	b.SetBytes(int64(2 * len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := benchmarkRoundTrip(conn, payload, scratch); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConcurrentThroughput keeps a fixed set of tunnels open and moves
// one payload through every tunnel per operation. The session counts stop at
// the shipped remote limit of 64.
func BenchmarkConcurrentThroughput(b *testing.B) {
	for _, sessions := range []int{1, 8, 32, 64} {
		b.Run(fmt.Sprintf("sessions=%d", sessions), func(b *testing.B) {
			topology := newTopology(b, topologyOptions{})
			connections := make([]net.Conn, sessions)
			for index := range connections {
				connections[index], _ = topology.openTLS(b)
			}
			payload := bytePattern(concurrentPayloadSize)
			scratch := make([][]byte, sessions)
			for index := range scratch {
				scratch[index] = make([]byte, len(payload))
			}
			b.SetBytes(int64(2 * len(payload) * sessions))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := benchmarkConcurrentRoundTrips(connections, payload, scratch); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkLiveSessionFootprint reports the heap retained by established
// end-to-end sessions. The measurement excludes fixture servers and reports
// the additional Go heap after the requested sessions remain open.
func BenchmarkLiveSessionFootprint(b *testing.B) {
	for _, sessions := range []int{1, 8, 32, 64} {
		b.Run(fmt.Sprintf("sessions=%d", sessions), func(b *testing.B) {
			topology := newTopology(b, topologyOptions{})
			runtime.GC()
			before := runtime.MemStats{}
			runtime.ReadMemStats(&before)

			connections := make([]net.Conn, sessions)
			for index := range connections {
				connections[index], _ = topology.openTLS(b)
			}
			runtime.KeepAlive(connections)
			runtime.GC()
			after := runtime.MemStats{}
			runtime.ReadMemStats(&after)

			b.ResetTimer()
			b.ReportMetric(float64(memoryDelta(after.Alloc, before.Alloc))/float64(sessions), "live-alloc-B/session")
			b.ReportMetric(float64(memoryDelta(after.HeapInuse, before.HeapInuse))/float64(sessions), "live-heap-inuse-B/session")
			b.ReportMetric(float64(memoryDelta(after.HeapObjects, before.HeapObjects))/float64(sessions), "live-objects/session")
			for range b.N {
				runtime.KeepAlive(connections)
			}
		})
	}
}

func memoryDelta(after, before uint64) uint64 {
	if after <= before {
		return 0
	}
	return after - before
}
