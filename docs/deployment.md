# Remote deployment

The remote implementation is the Go server in this repository, packaged as a
non-root, `scratch`-based image. dproxy does not depend on Cloudflare. It needs
a public WSS front end with all of these properties:

- the relay hostname publishes a DNS `HTTPS` record containing an ECH
  configuration;
- the outer connection accepts ECH and negotiates TLS 1.3;
- the front end presents a publicly trusted certificate for the relay hostname;
- it accepts WebSocket upgrades at `/v1/tunnel` without redirects;
- it forwards the WebSocket to dproxy over HTTP/1.1;
- the dproxy HTTP listener is not exposed directly to the Internet.

The client obtains DNS and ECH data through its configured HTTPS DoH resolver.
Cloudflare DoH is the shipped default, but operators can select another resolver
and provide its bootstrap IP addresses.

The included Compose file is the tested Cloudflare Tunnel example. It does not
publish port 8686 on the host, so only `cloudflared` can reach dproxy.

## Prepare dproxy files

The server reads its shared token from a file. Do not bake it into an image,
place it in an environment variable, or pass it on a command line.

```sh
mkdir -p secrets state
openssl rand -base64 48 > secrets/dproxy_token
chmod 700 secrets state
chmod 400 secrets/dproxy_token
```

The image runs as UID/GID 65532. On a Linux host, give that identity access to
the bind-mounted files and identity directory:

```sh
sudo chown -R 65532:65532 secrets state
```

If the host uses a different dedicated non-root account, set `DPROXY_UID` and
`DPROXY_GID` for Compose and make that account own both directories.

The dproxy token must contain at least 32 bytes after surrounding whitespace is
removed. The server creates its inner-TLS Ed25519 identity in
`state/identity.pem` on its first start. Keep that directory persistent and back
it up: changing the identity changes the client pin.

## Cloudflare Tunnel example

### Prepare the connector credential

Write the remotely managed Tunnel token to the file mounted by the Compose
service:

```sh
printf '%s\n' 'the remotely managed Tunnel token' \
  > secrets/cloudflare_tunnel_token
chmod 400 secrets/cloudflare_tunnel_token
sudo chown 65532:65532 secrets/cloudflare_tunnel_token
```

### Configure Cloudflare Tunnel

Create a remotely managed Tunnel and add a public hostname with these values:

- Service: `http://dproxy:8686`
- Path: `/v1/tunnel`
- HTTP/2 connection to origin: disabled

HTTP/1.1 to the origin is required because the Go server upgrades and hijacks
that connection. `http2Origin` is disabled by default, but keeping it explicit
prevents a later dashboard change from breaking the endpoint. Cloudflare's
[origin parameters](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/)
document that setting.

The path restriction keeps `/healthz` private. The server also returns 404 for
every unrelated path and rejects query strings on the tunnel endpoint. A locally
managed alternative is shown in `configs/cloudflared.example.yml`; Cloudflare
requires the final ingress rule to be a catch-all, as described in its
[configuration-file documentation](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/).

The Compose service reads the remotely managed connector token with
`--token-file`. This needs cloudflared 2025.4.0 or newer according to the
[run-parameter reference](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/run-parameters/).
Pin the tested cloudflared image by digest in production instead of relying on
the example's `latest` tag.

### Start and pin the server

```sh
docker compose build
docker compose up -d
docker compose logs dproxy
```

The first startup record includes `identity_pin=sha256:...`. Put that exact pin
in each client's `server_pin` setting. It is safe to distribute; it identifies
the public key and contains no private key material.

### Transfer client bootstrap values

Each client needs two values from this deployment:

- copy the contents of `secrets/dproxy_token` to the client's token file;
- copy the `identity_pin=sha256:...` value from the startup record to the
  client's `server_pin` setting.

Use an authenticated secure channel for both values. The dproxy token must stay
confidential. The identity pin is public, but its integrity matters because the
client uses it to authenticate the server. Do not copy `state/identity.pem`; it
contains the server's private key. Do not copy `secrets/cloudflare_tunnel_token`
either. That credential belongs only to the Cloudflare connector.

The client also needs the public `wss://` relay URL. It is deployment
configuration, not a secret. Continue with
[Configure the local client](../README.md#configure-the-local-client) to install
the token and edit `client.toml`.

Cloudflare supports proxying WebSockets. Its edge deployments can terminate
long-lived WebSocket connections, so a future local client must reconnect by
opening a new tunnel rather than assuming a connection lasts forever. See
Cloudflare's
[WebSocket documentation](https://developers.cloudflare.com/network/websockets/).

### Stop the server

`docker compose stop` sends SIGTERM. dproxy stops accepting upgrades, marks its
private health endpoint unavailable, and waits up to `timeouts.shutdown` for
active relays before closing the remainder.

The deployment has outbound network access for mandatory DoH and permitted
public TCP port 443 destinations. Apply the host firewall as a second layer:
allow outbound TCP 443 and deny unsolicited inbound traffic to the container
host. Never add a Compose `ports` entry for dproxy.

## Rotate credentials

The server accepts two token lines during rotation. Put the new token first and
the old token second, restart the server, then update and test every client.
Remove the old line and restart the server again. If the token was exposed,
disable ingress and replace it without an overlap period.

The client pins one remote identity. To rotate the identity without an outage,
start a second relay with a new identity and hostname. Test its pin, move the
clients, then remove the old relay. If the identity key was exposed, disable the
old public route before replacing it. Never bypass pin verification.

To rotate the Cloudflare Tunnel credential, revoke it in Cloudflare, write the
replacement to `secrets/cloudflare_tunnel_token`, and restart `cloudflared`.
Confirm that the public route exposes `/v1/tunnel` but not `/healthz`.

After any recovery, run `dproxy test`. For the included Cloudflare deployment,
also run `make e2e-cloudflare` from a maintainer-controlled host.

## Other WSS front ends

The same dproxy image can run behind another ingress, edge service, or
self-managed TLS endpoint. Keep its plain HTTP listener on a private network.
Route only `/v1/tunnel` to it with HTTP/1.1 WebSocket forwarding and keep
`/healthz` private.

The public endpoint must satisfy every transport requirement listed above. It is
not enough to enable ordinary TLS or publish an HTTPS certificate. The hostname
must publish a usable ECH configuration, the endpoint must accept ECH, and the
completed connection must negotiate TLS 1.3. Run `dproxy test` against the final
public `wss://` URL before sending application traffic.
