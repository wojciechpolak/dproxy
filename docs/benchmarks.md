# Benchmark results

This record covers the first comparison of dproxy's one-tunnel-per-`CONNECT`
model. It answers whether the current model needs multiplexing. It does not
measure a public WSS deployment because that deployment was not configured on
the test host.

## Environment

| Field         | Value                             |
|---------------|-----------------------------------|
| Date          | 2026-08-25                        |
| Host          | Apple M3 Max, macOS 26.6.1, arm64 |
| Go            | go1.27.0                          |
| Docker client | 29.5.3, desktop-linux context     |
| Remote limit  | 64 sessions                       |

The in-process run used local TLS, WSS, relay, and origin fixtures. The Docker
run used the production remote image and the same fixture origin. Neither run
contacted a provider, public resolver, or public WSS front end.

## Commands

```sh
make benchmark
make benchmark-docker
BENCHPROFILE_DIR=/tmp/dproxy-benchmark BENCHTIME=2s make benchmark-profile
```

The setup benchmark uses five fixed 100-operation samples. The throughput and
memory benchmarks use five samples. This avoids exhausting the host's ephemeral
port range while preserving repeated observations.

## Results

Each range covers the five samples from the command above.

| Path          | Measurement            | Result                                        |
|---------------|------------------------|-----------------------------------------------|
| In process    | Tunnel setup           | 1.53 to 1.98 ms per `CONNECT`                 |
| In process    | One established tunnel | 621.5 to 626.4 MB/s aggregate echo throughput |
| In process    | 1 session              | 348.5 to 359.0 MB/s aggregate throughput      |
| In process    | 8 sessions             | 636.1 to 646.9 MB/s aggregate throughput      |
| In process    | 32 sessions            | 683.0 to 702.4 MB/s aggregate throughput      |
| In process    | 64 sessions            | 673.2 to 695.4 MB/s aggregate throughput      |
| Docker remote | Tunnel setup           | 3.97 to 4.35 ms per `CONNECT`                 |
| Docker remote | One established tunnel | 209.0 to 215.2 MB/s aggregate echo throughput |

The live-session benchmark reports Go heap retained after application TLS is
established. At 32 sessions it retained 309,204 to 311,828 bytes of `Alloc` and
308,224 to 350,976 bytes of `HeapInuse` per session. At 64 sessions it retained
308,123 to 309,902 bytes of `Alloc` and 302,720 to 345,088 bytes of `HeapInuse`
per session. These numbers exclude operating-system socket buffers and the
Docker container's resident memory.

The 64-session CPU profile spent most sampled time in I/O syscalls. Its
allocation profile attributed 81.9% of allocated space to
`tunnel.(*WebSocketConn).writeFrame`, which copies outgoing WebSocket frames.
That is a candidate for allocation reduction. It does not show that multiplexing
would increase throughput because a multiplexed protocol still writes WebSocket
frames.
