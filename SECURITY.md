# Security policy

## Reporting a vulnerability

If you find a security vulnerability in this project, please report it privately
using
[GitHub's security advisory feature](https://github.com/wojciechpolak/dproxy/security/advisories/new)
rather than opening a public issue.

I'm a solo developer. I'll do my best to respond and release a fix as quickly as
I can, but please allow reasonable time.

## System and scope

dproxy is a Go HTTP `CONNECT` proxy and remote TCP relay. This policy covers the
local client, remote relay, `dproxy/1` protocol, transport and destination
policy, Docker and Compose deployment files, and release pipeline in this
repository.

The local proxy listens on loopback. It carries each accepted connection through
an ECH-capable WSS front end to a private remote relay. The calling
application's TLS session terminates at the destination provider, not at dproxy.

## Threat model and trust boundaries

The local machine and remote host are trusted to run the intended dproxy binary
and protect its configuration, token, and identity files. The DoH resolver and
WSS front-end operator are outside that trusted boundary. Provider responses,
DNS answers, WebSocket peers, and local `CONNECT` requests are untrusted input.

The WSS front end terminates outer TLS and can observe connection metadata. The
remote relay terminates the pinned inner TLS connection and learns the target
hostname, resolved address, and application ciphertext. The destination provider
terminates the original application TLS connection and sees its contents.

## Security invariants

- **Application TLS stays opaque.** dproxy must not terminate, decrypt, inspect,
  log, or rewrite the application's TLS session.
- **The outer transport fails closed.** The client uses in-process DoH, requires
  TLS 1.3 and accepted ECH, validates the public certificate, and rejects
  redirects. It never falls back to the operating-system resolver, TLS 1.2, or a
  connection without ECH.
- **The private channel is pinned.** Local and remote dproxy establish inner TLS
  1.3. The client verifies the remote's SPKI pin before sending the shared
  token, destination, or application bytes.
- **Authentication precedes network access.** The remote compares token digests
  in constant time and rejects an invalid token before resolving or dialing a
  destination. One previous token may remain active during rotation.
- **The remote enforces destination policy.** It accepts hostname destinations
  on port 443 only, applies its own optional allowlist, resolves through DoH,
  and rejects every private, loopback, link-local, multicast, unspecified, or
  other reserved address.
- **Protocol input is bounded.** HTTP headers and `dproxy/1` control messages
  have size limits. The remote limits concurrent sessions and authentication
  failures, and operators can bound idle time and session lifetime.
- **Logs omit secrets by default.** Tokens and application traffic must never
  enter logs. Destination hostnames remain redacted unless the operator
  explicitly enables target logging.
- **The remote listener stays private.** The WSS front end is the public entry
  point. The included container runs as a non-root user and does not publish the
  remote relay directly.

## Reportable findings and severity context

Report findings that break a security invariant or cross a documented trust
boundary, including:

- shared-token authentication bypass or token disclosure;
- remote identity pin bypass, transport downgrade, OS DNS fallback, ECH bypass,
  or certificate-validation bypass;
- destination-policy or address-classification bypass that permits SSRF or a
  connection to a forbidden host, IP literal, port, or non-public address;
- a way for the WSS front end, remote relay, or logs to recover information the
  threat model says they cannot see;
- malformed HTTP, WebSocket, TLS, DNS, or `dproxy/1` input that causes
  unauthorized dialing, cross-session data exposure, or practical resource
  exhaustion; and
- release or deployment behavior in this repository that defeats documented
  artifact verification, credential isolation, or listener isolation.

Severity depends on realistic reachability and impact. A remote unauthenticated
path to relay use, token theft, application plaintext, private-network access,
or remote code execution is high or critical. A finding that requires a trusted
host to be compromised first usually inherits that existing compromise.

## Out of scope

- Vulnerabilities solely in Go, an operating system, a container runtime, a DoH
  or WSS provider, or another external service. Report those upstream. A mistake
  in dproxy's use or configuration of one of them remains in scope.
- Physical access to, or prior compromise of, the trusted local machine or
  remote host.
- Social engineering.
- Availability attacks, traffic-flow analysis, anonymity from the destination
  provider, and other limits documented in
  [`docs/threat-model.md`](docs/threat-model.md), unless the report shows that a
  stated control or boundary does not hold.
- Missing traffic shaping, padding, obfuscation, TLS interception, content
  inspection, UDP, QUIC, SOCKS, or multiplexing. These are explicit v1
  non-goals, not hidden security controls.

## Known limitations

- The DoH endpoint, ECH public name, front-end addresses, timing, and traffic
  volume remain visible to the local network.
- The WSS front end sees the relay hostname, client address, remote origin,
  timing, and volume. Inner TLS prevents it from reading the token, target
  hostname, control messages, or application bytes.
- The remote relay learns each target hostname and resolved address. The
  application's TLS protects request and response contents from it.
- The default destination policy permits any valid public hostname on port 443.
  Operators must configure allowlists on both local and remote dproxy when they
  need a narrower policy. The remote list is authoritative.
- A stolen token authorizes relay use until rotation. A stolen remote identity
  key can impersonate that identity. Compromise of both permits a replacement
  relay to authenticate to clients and accept their sessions.

See [`docs/threat-model.md`](docs/threat-model.md) for the complete disclosure
matrix, residual risks, and compromise assumptions.

## Supported versions

| Version | Supported                 |
|---------|---------------------------|
| 0.9.x   | Yes, current pre-1.0 line |
| < 0.9   | No                        |

Only the latest 0.9.x patch release is supported. Fixes are released forward;
there are no long-term-support branches. This table will be updated when dproxy
1.0 is released.

## Patch policy

Target timelines from a confirmed report:

| Severity | Fix released within | Advisory                           |
|----------|---------------------|------------------------------------|
| Critical | 7 days              | GitHub advisory with a CVE request |
| High     | 30 days             | GitHub advisory                    |
| Medium   | next release        | `CHANGELOG.md` under **Security**  |
| Low      | next release        | `CHANGELOG.md` under **Security**  |

A high-severity finding is not waivable. It is fixed, or the affected path is
disabled, before the next release ships.

Releases publish deterministic archives, SHA-256 checksums, and signed build
provenance. The remote-server image also has signed provenance and an attested
SPDX software bill of materials. Verification commands are in the
[release guide](docs/release.md#verify-a-downloaded-release).

## Further reading

- [`docs/threat-model.md`](docs/threat-model.md), adversaries, trust boundaries,
  controls, and residual risks
- [`docs/protocol-v1.md`](docs/protocol-v1.md), wire format and authentication
- [`docs/deployment.md`](docs/deployment.md), setup and credential rotation
- [`docs/release.md`](docs/release.md), artifact publication and verification
