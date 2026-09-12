# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
