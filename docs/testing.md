# Testing

Run the local quality gate before submitting a change:

```sh
make check
```

`make ci` adds the deterministic end-to-end and Docker tests used in CI. The
main test targets are:

| Command                | Purpose                                         |
|------------------------|-------------------------------------------------|
| `make e2e-local`       | In-process client, relay, and origin tests      |
| `make e2e-docker`      | Production remote image on an isolated net      |
| `make e2e-docker-mtls` | Same image requiring pinned client certificates |
| `make e2e`             | All deterministic suites, both Docker runs      |
| `make provider-compat` | `curl`, Git, Codex CLI, and Claude Code         |
| `make e2e-cloudflare`  | Public deployment and packet-capture checks     |
| `make benchmark`       | Fixture tunnel setup and throughput             |

## Static analysis

`make check` also runs these, each blocking in CI. All of them cover the product
module and the `tools/` module.

| Command            | Purpose                                          |
|--------------------|--------------------------------------------------|
| `make vet`         | `go vet`                                         |
| `make analyze`     | The `x/tools` analyzers `go vet` does not enable |
| `make staticcheck` | staticcheck, every check, per `staticcheck.conf` |
| `make errcheck`    | Unchecked errors and type assertions             |
| `make gocyclo`     | Cyclomatic complexity ceiling                    |
| `make deadcode`    | Functions unreachable from `cmd/dproxy`          |

`make analyze` builds `tools/analyze`, a `multichecker` over the
`golang.org/x/tools` analysis passes missing from the `go vet` suite, including
`nilness`, `lostcancel`, `unusedwrite` and `waitgroup`. It is a binary in this
repository rather than a linter aggregator, which keeps the tool module's
dependency graph small. Extend static analysis by adding a pass to its list, not
by adding a tool.

`make errcheck` excludes the function signatures in
`scripts/errcheck-excludes.txt`. Those are writes to stderr and to usage
writers, where a failed write has nowhere to go.

`make gocyclo` fails above complexity 30. That is the current worst function, so
the limit blocks new complexity rather than naming a target.

GitHub Actions also runs `go test ./...` and the built CLI on a native Windows
amd64 runner. Release builds cross-compile and package both Windows amd64 and
arm64 binaries.

The deterministic topology uses generated credentials and local fixtures. It
tests byte preservation, streaming, half-close, cancellation, deadlines,
backpressure, policy rejection, and the absence of plaintext secrets after the
outer TLS layer terminates. It never contacts a provider or public resolver.

The Docker test runs the production remote image with fixture DoH and TLS
services on an isolated network. It exercises the normal resolver, address
policy, authentication, and relay code. The test removes its containers and
generated credentials when it exits.

## Pinned client certificates

`make e2e-docker` runs the configuration every existing deployment uses. The
generated `server.toml` leaves `client_pins` commented out, and the two mTLS
tests skip. `make e2e-docker-mtls` sets `DPROXY_E2E_CLIENT_PINS=1`. The fixture
then writes the generated client pin into `client_pins`, and the suite presents
the matching identity. Both read the same variable, so the container and the
client always match. `make e2e` runs both, so CI covers the option and the
default. The second run reuses the images the first one built.

The mTLS run adds two scenarios against the production image. A pinned client
streams end to end. A client holding a real but unpinned identity gets
`ErrClientCertificateRejected`. The second test uses an unpinned identity rather
than no identity, so it proves the remote checks the pin value, not only that a
certificate arrived. The container logs the refusal as
`authentication failed reason=client-pin`, the rate-limited path. It logs
`client_pins=N` at startup to report what it loaded.

The fixture always writes `client-identity.pem` and `client-pin` into the E2E
directory, so you can convert a default run by hand. Uncomment `client_pins` in
the generated `server.toml` and restart the container.

## Provider compatibility

`make provider-compat` starts Codex CLI and Claude Code with fake credentials
and local API base URLs. The fixture allowlist permits only `origin.e2e.test`,
and the test stops before either CLI can run a model. `curl` completes an HTTPS
request and `git ls-remote` reads a local smart-HTTP response.

The provider CLIs may still read their saved user profiles and initialize local
plugins or MCP services. Use a disposable OS account if that is unacceptable.
The ordinary `make e2e-local` target does not start either provider CLI.

## Benchmarks

`make benchmark` measures the v1 one-tunnel-per-`CONNECT` model against the same
local TLS origin and relay fixtures used by the end-to-end suite. It does not
use provider credentials, public DNS, or the public network.

The setup benchmark includes the local TCP connection, HTTP `CONNECT`, outer
TLS, WebSocket upgrade, pinned inner TLS, authentication, policy checks, fixture
resolution, and the origin TCP dial. It excludes the application's TLS
handshake. The throughput benchmarks reuse established tunnels and report the
combined bytes sent and echoed. Concurrent runs use 1, 8, 32, and 64 sessions;
64 is the shipped remote session limit.

The default command takes five fixed 100-operation setup samples and five
two-second throughput samples. Setup uses a fixed iteration count because each
operation consumes three short-lived TCP source ports. Letting the Go benchmark
runner increase that count until two seconds elapse can exhaust the macOS port
range before `TIME_WAIT` entries expire.

The command reports `ns/op`, `MB/s`, `B/op`, and `allocs/op`. Override the
sampling controls when a longer run is needed. Keep `BENCHSETUP` low enough for
the host's available source-port range:

```sh
BENCHSETUP=200x BENCHTIME=5s BENCHCOUNT=10 make benchmark
```

`BenchmarkLiveSessionFootprint` holds 1, 8, 32, and 64 application TLS sessions
open and reports the additional Go heap for each live session. It is a retained
heap measurement, not the total memory used by the operating system or a remote
Docker container.

`make benchmark-docker` starts the fixture services and the production remote
image, then measures setup and steady-state throughput through that image. It
uses the same sampling variables as `make benchmark`. Docker Desktop resource
limits belong in the saved environment details because they affect the result.

Use `make benchmark-profile` to write CPU and allocation profiles for 64
concurrent in-process sessions. Choose a disposable output directory:

```sh
BENCHPROFILE_DIR=/tmp/dproxy-benchmark BENCHTIME=5s make benchmark-profile
```

The profile includes the local proxy, relay, and fixture origin because they run
in one Go process. Compare it with the Docker run before assigning a limit to
any one component.

[Benchmark results](benchmarks.md) records the initial in-process and Docker
comparison.

## Public deployment check

The Cloudflare test requires a dedicated dproxy deployment. It sends a HEAD
request to IANA's reserved `example.com` domain through the relay, so it does
not require a separately deployed echo server. Configure:

| Variable               | Value                       |
|------------------------|-----------------------------|
| `DPROXY_CF_URL`        | `wss://` test relay URL     |
| `DPROXY_CF_PIN`        | remote inner-TLS SPKI pin   |
| `DPROXY_CF_TOKEN_FILE` | mode-0600 client token file |

Run this test from a maintainer-controlled host. It is deliberately not a GitHub
Actions job: shared hosted-runner addresses can trigger Cloudflare bot controls,
while packet capture depends on host networking and elevated privileges. Local
runs may override `DPROXY_CF_DOH_URL`, `DPROXY_CF_DOH_BOOTSTRAP`,
`DPROXY_CF_TARGET`, or `DPROXY_CF_EXPECTED_OUTER_SNI`; otherwise the test uses
the shipped Cloudflare DoH settings, `example.com`, and the public name accepted
by the ECH handshake.

Run `make e2e-cloudflare` on a host with `tcpdump` and `sudo` access for packet
capture. Linux captures on `any`; macOS captures on the default-route interface.
Set `DPROXY_CF_CAPTURE_INTERFACE` to override that choice, for example when a
VPN carries the traffic. The test checks ECH, both TLS layers, the remote pin,
and an HTTPS request through the relay. It also rejects ordinary DNS packets or
plaintext relay hostnames, target hostnames, and tokens in the capture.
