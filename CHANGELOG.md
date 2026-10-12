# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Reject ECH configurations whose supported public name matches the relay
  hostname, so mandatory ECH cannot expose that hostname in outer SNI.
- Keep authentication-failure limiting bounded and active at capacity by
  evicting the oldest source instead of blocking the whole relay or dropping a
  new source's failures.
- Reject deprecated IPv6 site-local addresses and zone-scoped addresses as
  non-global destinations.
- Redact malformed pin and TOML array values from configuration errors.
- Upgrade the build and runtime baseline to Go 1.26.9.

### Fixed

- Pin Make recipes to the Go version declared in `go.mod`, preventing analyzer
  export-data incompatibilities when the host Go version is newer.

## [1.2.0] - 2026-09-14

### Added

- Optional mTLS (mutual TLS) on the inner TLS session, as pinned client
  certificates rather than a client CA. A remote configured with `client_pins`
  requires a client certificate whose SPKI digest is in that set, verified
  during the handshake before `HELLO` is read and metered by the authentication
  rate limiter. Clients set `client_identity_file`; the identity is created on
  first use with owner-only permissions and its `client_pin` is printed at
  startup. The shared token remains mandatory in every mode, the `dproxy/1`
  protocol is unchanged, and a remote without `client_pins` behaves exactly as
  before.

## [1.1.0] - 2026-09-12

### Added

- Native Windows amd64 and arm64 CLI binaries, Windows configuration discovery,
  private ACL validation for credentials, and Windows CI coverage.
- A fixture-only `make benchmark` harness for tunnel setup, steady-state
  throughput, concurrent-session throughput, live-session heap, CPU and
  allocation profiles, and the production remote Docker image.

## [1.0.0] - 2026-08-21

Initial public release.

### Added

- A discreet encrypted proxy for HTTPS and WebSocket traffic that carries local
  HTTP `CONNECT` connections through an ECH-capable WSS relay without
  terminating application TLS.
