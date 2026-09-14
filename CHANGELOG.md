# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
