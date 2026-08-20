# Threat model

## Security goals

dproxy protects these values:

- the relay hostname from observers on the local network;
- provider hostnames and application bytes from the local network and WSS
  front-end operator;
- the shared dproxy token from every party except the local and remote dproxy;
- the remote host and its private network from unauthorized relay use and SSRF;
- the provider request and response from dproxy itself.

Availability, traffic-flow concealment, endpoint compromise, and anonymity from
the provider are outside these goals.

## Trust boundaries

The local machine and remote host are trusted to run the intended binary and
protect their files. The configured DoH resolver and WSS front-end operator can
observe connection metadata. The provider terminates the application's TLS
session and therefore sees its contents. Provider responses, DNS answers,
WebSocket peers, and local `CONNECT` requests are untrusted input.

| Party                  | Learns                                                                      |
|------------------------|-----------------------------------------------------------------------------|
| Local network          | DoH endpoint, ECH public name, front-end addresses, timing, and volume      |
| WSS front-end operator | Relay hostname, client address, remote origin, timing, and volume           |
| Remote dproxy          | Target hostname, resolved address, port, timing, and application ciphertext |
| Provider               | Remote host address and the original application request                    |

The inner TLS layer prevents the front-end operator from reading `HELLO`,
`OPEN`, the token, the provider hostname, or application bytes. ECH does not
hide the connection to the front-end service or its timing.

## Threats and controls

| Threat                                                | Control                                                                                             | Residual risk                                                            |
|-------------------------------------------------------|-----------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| Local DNS monitoring reveals the relay                | In-process DoH with configured bootstrap addresses and no OS resolver fallback                      | The DoH endpoint remains visible                                         |
| Outer SNI reveals the relay                           | ECH is mandatory and rejection is fatal                                                             | The shared ECH public name remains visible                               |
| Transport downgrade                                   | Both outer and inner TLS require version 1.3                                                        | Future TLS policy changes need review                                    |
| The WSS front end reads tunnel control data           | Pinned inner TLS encloses the token, destination, and application stream                            | The front end still sees connection metadata                             |
| A false remote steals the token                       | The client checks the remote SPKI pin before sending `HELLO`                                        | A stolen identity key defeats this check                                 |
| Unauthorized users turn the remote into an open proxy | A high-entropy token is required before `OPEN`, failures are rate-limited, and sessions are bounded | A stolen token works until rotation                                      |
| A compromised local client requests arbitrary targets | Port 443 is fixed, private addresses are blocked, and operators can configure allowlists            | The default policy permits any public hostname                           |
| DNS rebinding reaches private services                | The remote classifies every DoH answer before dialing                                               | A public address may route to infrastructure the operator did not intend |
| Parser input causes memory or state abuse             | HTTP and control messages have size limits, explicit types, and strict versioning                   | Long valid streams still consume one session each                        |
| Slow or abandoned sessions exhaust capacity           | Idle, lifetime, concurrent-session, and shutdown limits                                             | Operators may disable idle or lifetime limits for long provider streams  |
| Logs disclose secrets or destinations                 | Secret keys are always redacted and target logging is opt-in                                        | Host operators can inspect process memory and network metadata           |
| The WSS front end redirects a tunnel                  | The WebSocket client rejects redirects                                                              | The front end still chooses its edge and origin routing                  |

## Compromise assumptions

A compromised local process can read the token, provider plaintext, and client
configuration. A compromised remote can read destinations and relay encrypted
application bytes. A compromised provider account or endpoint exposes data at
the application layer. dproxy does not claim to protect against any of these.

Compromise of the remote identity key and token together permits a replacement
relay to authenticate to clients and accept their sessions. Treat either file as
an incident and follow the rotation steps in the
[deployment guide](deployment.md#rotate-credentials).

## Security review triggers

Review this model before adding another listener type, destination port,
authentication method, transport fallback, public remote listener, protocol
message, multiplexing, application parsing, or provider-specific transport
branch. Those changes alter a trust boundary or a stated security goal.
