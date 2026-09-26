# rspxy

A SOCKS5 / HTTP proxy that tunnels traffic to an exit server over UDP, using QUIC for
reliability and a lightweight obfuscation layer (SSU) so the wire traffic has no fixed
bytes or recognizable protocol headers.

```
socks5/http client ──TCP──> rspxy (local) ══UDP: SSU + QUIC══> rspxy (exit) ──> internet
```

- **SOCKS5** (RFC 1928/1929): CONNECT and UDP ASSOCIATE, so apps that use UDP/QUIC keep working.
- **HTTP proxy**: CONNECT tunnels and plain absolute-form requests.
- **QUIC transport** (quinn): one stream per TCP flow over a single shared connection, and UDP relayed
  as QUIC datagrams. The default congestion control is a loss-tolerant BBR that keeps throughput on
  links with heavy random packet loss.
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

## Options

| Flag | Description |
|---|---|
| `-L NODE` | Listen node, repeatable: `socks5://`, `http://`, or `ssu://` (exit server) |
| `-F NODE` | Forward node: `ssu://ID:SECRET@host:port` (at most one) |
| `-D` | Debug logging (`RUST_LOG` is also honored) |

Node format: `scheme://[user:pass@][host]:port[?key=value&...]`. An empty host listens on all
IPv4 interfaces. `sockssimple://` is accepted as an alias of `ssu://`.

`ssu://` parameters:

| Param | Default | Where | Meaning |
|---|---|---|---|
| `keys` | – | server | Path to an `id secret` key table |
| `key` | – | server | Inline `id:secret`, repeatable (`id:secret@` in the URL also works) |
| `cc` | `bbr` | both | `bbr` (loss-tolerant), `bbr1` (quinn's stock BBRv1), `cubic`, `newreno`. Each side controls its sending direction |
| `mtu` | `1200` | both | QUIC initial/minimum MTU (1200–1439). Raise it only on paths known to carry larger packets |
| `pad` | off | both | Random padding range for data packets, e.g. `0-64`. Handshake packets are always padded |
| `timeout` | `10s` | client | Handshake timeout when (re)connecting |

## Protocol

SSU packet (every UDP datagram):

```
nonce u32 (random) | kid' u16 | XOR( magic u32 | flags u8 | len u16 | QUIC packet | padding )

kid'      = kid ^ mask16(nonce)
keystream = wyrand( SipHash-2-4(key[kid], nonce || kid) )
```

Inside QUIC, each stream starts with `ver u8 | cmd u8 (1=TCP, 2=UDP) | SOCKS5 address`. The reply
is a SOCKS5 REP status byte, followed by a `u32` association id for UDP. UDP payloads travel as QUIC
datagrams tagged with that association id. See `src/ssu.rs` and `src/proto.rs` for details.

## Development

```bash
cargo test    # unit tests + in-process end-to-end tests (incl. a 20%-loss link)
cargo clippy --all-targets
```

Helper scripts in `scripts/`:

| Script | Purpose |
|---|---|
| `deploy.sh SSH_HOST` | Build a static binary, upload it, and restart the exit server (`JUMP=host` to upload via a jump host) |
| `bench.sh name=PROXY ...` | A/B benchmark of proxies: download/upload throughput, TLS handshake and TTFB medians |
| `udpperf.py` | Raw UDP throughput/loss test between two hosts over a single UDP port |
| `socks5_udp_dns.py` | DNS query through SOCKS5 UDP ASSOCIATE, to check UDP relaying |
