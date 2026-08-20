# dproxy/1 inner protocol

`dproxy/1` runs inside TLS 1.3 over the WebSocket byte stream. Both inner TLS
peers offer only `dproxy/1` as ALPN and abort if negotiation produces anything
else.

The remote uses a persistent Ed25519 TLS identity. It stores the self-signed
certificate and private key in one PEM file with mode `0600`. The client does
not use DNS names or public PKI for this connection. It compares the SHA-256
digest of the leaf certificate's DER-encoded SubjectPublicKeyInfo with its
configured `server_pin`. A mismatch ends the connection before the client can
send `HELLO`.

## Session sequence

One connection has this fixed exchange:

```mermaid
sequenceDiagram
    accTitle: dproxy/1 session sequence
    accDescr: The local client verifies the remote identity before authentication, opens one destination, and switches from framed control messages to raw bytes only after OPEN_OK.

    participant client as local dproxy
    participant remote as remote dproxy

    client->>remote: Inner TLS 1.3 handshake with ALPN dproxy/1
    remote-->>client: Certificate with persistent Ed25519 identity
    Note over client: Verify the remote SHA-256 SPKI pin
    client->>remote: HELLO, version 1 and token
    remote-->>client: HELLO_OK, version 1
    client->>remote: OPEN, hostname and port 443

    alt Destination accepted
        remote-->>client: OPEN_OK
        Note over client,remote: Control framing stops
        client->>remote: Raw application bytes
        remote->>client: Raw origin bytes
    else Request rejected
        remote-->>client: OPEN_ERROR, code only
    end
```

The token appears only in `HELLO`. The client sends that message after inner TLS
and pin verification return successfully. `OPEN` cannot precede an accepted
`HELLO`. After `OPEN_OK`, both peers stop decoding frames and treat every byte
as application data.

## Framing

Every control message starts with a four-byte unsigned length in network byte
order. The length covers the message type and payload, but not the length field
itself. A zero length is invalid. Each peer rejects a length above its
configured control-message limit before allocating or reading the body.

Integers use network byte order. Text is UTF-8 where the hostname grammar allows
it, though canonical protocol hostnames are ASCII after policy validation. There
is no padding and no optional field in version 1.

| Type | Name         | Body after the one-byte type                |
|-----:|--------------|---------------------------------------------|
|    1 | `HELLO`      | version `u8`, token bytes                   |
|    2 | `HELLO_OK`   | version `u8`                                |
|    3 | `OPEN`       | hostname length `u16`, hostname, port `u16` |
|    4 | `OPEN_OK`    | empty                                       |
|    5 | `OPEN_ERROR` | error code `u16`                            |

The protocol version byte is `1`. An unknown version returns an explicit
unsupported-version error. There is no version fallback or best-effort decoding.

`HELLO` consumes the rest of its frame as the token. The token must contain 32
to 4094 bytes. The upper bound leaves room for the type and version in the
default 4096-byte control-message limit.

`OPEN` carries a canonical hostname and port `443`. The decoder rebuilds a
`policy.Destination`, which rejects IP literals, malformed names, and other
ports before remote policy evaluation.

## OPEN_ERROR codes

| Code | Meaning                   |
|-----:|---------------------------|
|    1 | unauthenticated           |
|    2 | forbidden destination     |
|    3 | resolution failed         |
|    4 | resolved address rejected |
|    5 | outbound dial failed      |
|    6 | server limit exceeded     |
|    7 | malformed control message |
|    8 | unsupported version       |
|    9 | internal failure          |

The message carries no free text. This keeps remote-controlled strings and
destination details out of normal client logs.

## WebSocket stream rules

The adapter sends each `net.Conn.Write` as one final binary WebSocket message.
It masks client frames and leaves server frames unmasked. Reads join binary and
continuation frames into one byte stream, answer ping frames, ignore pong
frames, and return EOF for a close frame.

The adapter rejects text frames, reserved bits, bad masking, unknown opcodes,
non-canonical lengths, invalid fragmentation, and frames larger than 16 MiB. The
opening handshake offers no WebSocket extension, so reserved bits never have a
negotiated meaning.

WebSocket payloads contain the inner TLS handshake and ciphertext. The token,
target hostname and port, and application bytes exist only inside that TLS
session.
