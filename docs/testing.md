# Testing

Run the local quality gate before submitting a change:

```sh
make check
```

`make ci` adds the deterministic end-to-end and Docker tests used in CI. The
main test targets are:

| Command                | Purpose                                     |
|------------------------|---------------------------------------------|
| `make e2e-local`       | In-process client, relay, and origin tests  |
| `make e2e-docker`      | Production remote image on an isolated net  |
| `make e2e`             | Both deterministic suites                   |
| `make provider-compat` | `curl`, Git, Codex CLI, and Claude Code     |
| `make e2e-cloudflare`  | Public deployment and packet-capture checks |

The deterministic topology uses generated credentials and local fixtures. It
tests byte preservation, streaming, half-close, cancellation, deadlines,
backpressure, policy rejection, and the absence of plaintext secrets after the
outer TLS layer terminates. It never contacts a provider or public resolver.

The Docker test runs the production remote image with fixture DoH and TLS
services on an isolated network. It exercises the normal resolver, address
policy, authentication, and relay code. The test removes its containers and
generated credentials when it exits.

## Provider compatibility

`make provider-compat` starts Codex CLI and Claude Code with fake credentials
and local API base URLs. The fixture allowlist permits only `origin.e2e.test`,
and the test stops before either CLI can run a model. `curl` completes an HTTPS
request and `git ls-remote` reads a local smart-HTTP response.

The provider CLIs may still read their saved user profiles and initialize local
plugins or MCP services. Use a disposable OS account if that is unacceptable.
The ordinary `make e2e-local` target does not start either provider CLI.

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
