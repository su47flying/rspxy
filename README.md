# rspxy

A SOCKS5 / HTTP proxy that tunnels traffic to an exit server over UDP, using QUIC for
reliability and a lightweight obfuscation layer (SSU) so the wire traffic has no fixed
bytes or recognizable protocol headers.

```
socks5/http client ──TCP──> rspxy (local) ══UDP: SSU + QUIC══> rspxy (exit) ──> internet
```

- **SOCKS5** (RFC 1928/1929): CONNECT and UDP ASSOCIATE, so apps that use UDP/QUIC keep working.
- **HTTP proxy**: CONNECT tunnels and plain absolute-form requests.
- **Shadowsocks server** (`-L ss://`): AEAD ciphers (`chacha20-ietf-poly1305`, `aes-256-gcm`,
  `aes-128-gcm`) with TCP and UDP on the same port. With `-F`, standard ss clients such as phone apps
  connect into the tunnel.
- **QUIC transport** (quinn): one stream per TCP flow over a single shared connection, and UDP relayed
  as QUIC datagrams. The default congestion control is a loss-tolerant BBR that keeps throughput on
  links with heavy random packet loss, while bounding its window by queueing delay and excess loss.
- **Relay mode**: an `ssu://` server with `-F` forwards through another tunnel (multi-hop).
- **SSU obfuscation**:
  - Each UDP packet carries a random nonce and is XORed with a per-packet keystream derived from a
    pre-shared key.
  - Only a 16-bit key id is sent, never the key.
  - Packets that fail validation are silently dropped, so the server never answers probes.
- gost-style command line: `-L` (listen) and `-F` (forward) nodes.

## Build

Requires a stable Rust toolchain (<https://rustup.rs>).

```bash
cargo build --release
# binary: target/release/rspxy
```

A fully static binary, handy for servers with an older glibc:

```bash
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=gcc cargo build --release --target x86_64-unknown-linux-musl
# binary: target/x86_64-unknown-linux-musl/release/rspxy
```

## Run

### 1. Exit server

Create a key table with one `id secret` pair per line. Give each client its own id so it can be
revoked on its own:

```bash
cat > keys.txt <<EOF
# id  secret
1     $(head -c 18 /dev/urandom | base64)
2     $(head -c 18 /dev/urandom | base64)
EOF
chmod 600 keys.txt

rspxy "-L=ssu://:5023?keys=keys.txt"
```

Open UDP port 5023 in the server's firewall. No TCP port is needed.

### 2. Local client

Use one id/secret pair from the server's `keys.txt`:

```bash
rspxy -L=socks5://:1080 -L=http://:8080 -F=ssu://1:SECRET@server.example.com:5023
```

### 3. Use it

```bash
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8080 https://example.com

# UDP through SOCKS5 UDP ASSOCIATE (a DNS query)
python3 scripts/socks5_udp_dns.py 127.0.0.1:1080 example.com 8.8.8.8
```

### More examples

```bash
# Proxy authentication on the local listeners
rspxy -L=socks5://user:pass@:1080 -L=http://user:pass@127.0.0.1:8080 -F=ssu://1:SECRET@server.example.com:5023

# Keys given inline instead of a file (repeat key= for several)
rspxy "-L=ssu://:5023?key=1:SECRET1&key=2:SECRET2"

# Tune the tunnel: congestion control, larger MTU, padding of data packets
rspxy -L=socks5://:1080 "-F=ssu://1:SECRET@server.example.com:5023?cc=bbr&mtu=1350&pad=0-32"

# No -F: listeners connect directly (useful for local testing)
rspxy -L=socks5://127.0.0.1:1080 -D
```

### Shadowsocks

`-L ss://METHOD:PASSWORD@[ip]:port` runs a Shadowsocks server that any standard client can use.
It listens on TCP and UDP on the same port:

```bash
# Standalone ss server that connects directly
rspxy -L=ss://chacha20-ietf-poly1305:PASSWORD@:8388

# ss entry into the tunnel: ss clients -> this host -> SSU/QUIC -> exit server
rspxy -L=ss://chacha20-ietf-poly1305:PASSWORD@:8388 -F=ssu://1:SECRET@server.example.com:5023

# TCP only (no UDP port)
rspxy "-L=ss://aes-256-gcm:PASSWORD@:8388?mode=tcp_only"
```

In the password, write `?` as `%3F` and `%` as `%25`. Other characters, including `:` and `@`,
work as is. Quote the argument so the shell leaves it alone.

### Relay (multi-hop)

An `ssu://` server started with `-F` forwards through its own tunnel instead of connecting
directly. Use this when the client cannot reach the exit server over UDP but a middle host can:

```
client ══UDP══> relay.example.com:9023 ══UDP══> exit.example.com:9023 ──> internet
```

```bash
# exit
rspxy "-L=ssu://:9023?keys=keys.txt"
# relay: accepts clients with its own keys.txt, forwards to the exit with an exit key
rspxy "-L=ssu://:9023?keys=keys.txt" -F=ssu://1:EXIT_SECRET@exit.example.com:9023
# client
rspxy -L=socks5://:1080 -F=ssu://1:RELAY_SECRET@relay.example.com:9023
```

## Options

| Flag | Description |
|---|---|
| `-L NODE` | Listen node, repeatable: `socks5://`, `http://`, `ss://` (Shadowsocks server), or `ssu://` (tunnel server) |
| `-F NODE` | Forward node: `ssu://ID:SECRET@host:port` (at most one). Applies to all listeners, including an `ssu://` server, which then acts as a relay |
| `-D` | Debug logging (`RUST_LOG` is also honored) |

Node format: `scheme://[user:pass@][host]:port[?key=value&...]`. An empty host listens on all
IPv4 interfaces. `sockssimple://` is accepted as an alias of `ssu://`.

`ss://` parameters:

| Param | Default | Meaning |
|---|---|---|
| `mode` | `tcp_and_udp` | `tcp_and_udp`, `tcp_only` or `udp_only`, as in shadowsocks configs |
| `ota` | – | Accepted, but ignored with a warning: one-time auth exists only for the legacy stream ciphers, and the AEAD ciphers already authenticate every chunk and packet |

Supported methods are `chacha20-ietf-poly1305`, `aes-256-gcm` and `aes-128-gcm`. The
go-shadowsocks2 names `AEAD_CHACHA20_POLY1305`, `AEAD_AES_256_GCM` and `AEAD_AES_128_GCM` also work.
The legacy stream ciphers (`aes-256-cfb`, `chacha20` and so on) are rejected: they have no
integrity protection. A UDP session per client address closes after 5 minutes without traffic.

`ssu://` parameters:

| Param | Default | Where | Meaning |
|---|---|---|---|
| `keys` | – | server | Path to an `id secret` key table |
| `key` | – | server | Inline `id:secret`, repeatable (`id:secret@` in the URL also works) |
| `cc` | `bbr` | both | `bbr`: BBR that ignores random loss, with a window ceiling driven by queueing delay and excess loss. Also `bbr1` (quinn's stock BBRv1), `cubic`, `newreno`. Each side controls its sending direction |
| `mtu` | `1200` | both | Fixed QUIC packet size (1200–1439); there is no path MTU discovery. Raise it only on paths known to carry larger UDP packets reliably |
| `pad` | off | both | Random padding range for data packets, e.g. `0-64`. Handshake packets are always padded |
| `timeout` | `10s` | client | Handshake timeout when (re)connecting |

## Protocol

SSU packet (every UDP datagram):

```
nonce u32 (random) | kid' u16 | XOR( magic u32 | flags u8 | len u16 | QUIC packet | padding )

kid'      = kid ^ mask16(nonce)
keystream = wyrand( SipHash-2-4(key[kid], nonce || kid) )
```

The ss server follows SIP004: `salt | [len][tag] [payload][tag] ...` with HKDF-SHA1 subkeys over an
EVP_BytesToKey master key. It also defends against replay and probing:

- **Replay filter**: the server remembers the last 131k–262k salts that passed authentication, plus
  the salts it sends itself. TCP and UDP keep separate filters. A replayed or reflected request is
  never dialed.
- **No reply to probes**: a connection that fails authentication gets no reply. The server keeps
  reading and discards the data until the 30 s handshake deadline, then closes the connection.
  So a prober can't tell how many bytes the check needed.
- **UDP**: packets that fail to decrypt are dropped without a reply.

Inside QUIC, each stream starts with `ver u8 | cmd u8 (1=TCP, 2=UDP) | SOCKS5 address`. The reply
is a SOCKS5 REP status byte, followed by a `u32` association id for UDP. UDP payloads travel as QUIC
datagrams tagged with that association id. See `src/ssu.rs` and `src/proto.rs` for details.

## Development

```bash
cargo test    # unit tests + in-process end-to-end tests (incl. a 20%-loss link and ss over the tunnel)
cargo clippy --all-targets
```

Helper scripts in `scripts/`:

| Script | Purpose |
|---|---|
| `deploy.sh SSH_HOST` | Build a static binary, upload it, and restart the server. Env: `PORT`, `JUMP=host` (upload via a jump host), `SERVER_ARGS='-F=...'` (relay mode), `SERVER_LOG='rspxy=debug,info'` (periodic QUIC stats) |
| `bench.sh name=PROXY ...` | A/B benchmark of proxies: download/upload throughput, TLS handshake and TTFB medians |
| `udpperf.py` | Raw UDP throughput/loss test between two hosts over a single UDP port |
| `socks5_udp_dns.py` | DNS query through SOCKS5 UDP ASSOCIATE, to check UDP relaying |
