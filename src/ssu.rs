//! SSU (sockssimple-udp): per-packet obfuscation layer that sits under QUIC.
//!
//! Wire format of every UDP datagram:
//!
//! ```text
//! nonce u32 (random, plain) | kid' u16 | XOR( magic u32 | flags u8 | len u16 | payload | padding )
//!
//! kid'      = kid ^ mask16(nonce)
//! keystream = wyrand( seed = SipHash-2-4(key[kid], nonce || kid) )
//! ```
//!
//! Compared with gost sockssimple there are no fixed bytes on the wire: the
//! magic only exists inside the ciphertext, the keystream differs per packet,
//! and only a key id is transmitted (never the key).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::Hasher;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use siphasher::sip::SipHasher24;

pub const MAGIC: u32 = 0x0000_3193;
const PLAIN_HDR: usize = 6;
const ENC_HDR: usize = 7;
/// Bytes SSU adds to every QUIC packet (excluding padding).
pub const OVERHEAD: usize = PLAIN_HDR + ENC_HDR;
/// Largest datagram we put on the wire (fits IPv6 / PPPoE paths).
pub const MAX_WIRE: usize = 1452;
/// Handshake (QUIC long header) packets are padded to a random size up to this.
const MAX_LONG_WIRE: usize = 1350;
const MIN_LONG_WIRE: usize = 1200 + OVERHEAD;

const TYPE_QUIC: u8 = 1;
const FLAG_PAD: u8 = 0x10;

const REPLAY_WINDOW: Duration = Duration::from_secs(60);
const PEER_TTL: Duration = Duration::from_secs(600);

/// A 128-bit SipHash key derived from a key id and its secret.
#[derive(Clone)]
pub struct Key {
    k0: u64,
    k1: u64,
}

impl Key {
    pub fn derive(kid: u16, secret: &str) -> Key {
        let mut h = SipHasher24::new_with_keys(0x7273_7078_7973_7375, u64::from(kid));
        h.write(secret.as_bytes());
        let k0 = h.finish();
        let mut h = SipHasher24::new_with_keys(k0, 0x5353_555f_6b65_7931);
        h.write(secret.as_bytes());
        Key { k0, k1: h.finish() }
    }

    fn seed(&self, nonce: u32, kid: u16) -> u64 {
        let mut h = SipHasher24::new_with_keys(self.k0, self.k1);
        h.write(&nonce.to_be_bytes());
        h.write(&kid.to_be_bytes());
        h.finish()
    }
}

/// 32-byte secret derived from the whole key table. Used as the QUIC stateless
/// reset key so a restarted server can reset its clients' stale connections
/// immediately instead of leaving them to time out.
pub fn table_secret(keys: &HashMap<u16, Key>) -> [u8; 32] {
    let mut kids: Vec<u16> = keys.keys().copied().collect();
    kids.sort_unstable();
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = SipHasher24::new_with_keys(0x7265_7365_745f_6b65, i as u64);
        for kid in &kids {
            let k = &keys[kid];
            h.write_u16(*kid);
            h.write_u64(k.k0);
            h.write_u64(k.k1);
        }
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    out
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

#[inline]
fn wyrand(s: &mut u64) -> u64 {
    *s = s.wrapping_add(0xa076_1d64_78bd_642f);
    let t = u128::from(*s) * u128::from(*s ^ 0xe703_7ed1_a0b4_28db);
    ((t >> 64) ^ t) as u64
}

fn xor_stream(seed: u64, buf: &mut [u8]) {
    let mut s = seed;
    let (chunks, rem) = buf.as_chunks_mut::<8>();
    for c in chunks {
        *c = (u64::from_le_bytes(*c) ^ wyrand(&mut s)).to_le_bytes();
    }
    if !rem.is_empty() {
        let k = wyrand(&mut s).to_le_bytes();
        for (b, k) in rem.iter_mut().zip(k) {
            *b ^= k;
        }
    }
}

fn mask16(nonce: u32) -> u16 {
    // murmur3 fmix32
    let mut h = nonce;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    (h ^ (h >> 16)) as u16
}

/// Encodes `payload` into `out` (cleared first) with `pad` bytes of padding.
pub fn encode(key: &Key, kid: u16, payload: &[u8], pad: usize, out: &mut Vec<u8>) {
    let nonce: u32 = rand::random();
    out.clear();
    out.reserve(OVERHEAD + payload.len() + pad);
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(&(kid ^ mask16(nonce)).to_be_bytes());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.push(TYPE_QUIC | if pad > 0 { FLAG_PAD } else { 0 });
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    // Padding is zeros before XOR, i.e. keystream bytes on the wire.
    out.resize(out.len() + pad, 0);
    xor_stream(key.seed(nonce, kid), &mut out[PLAIN_HDR..]);
}

/// Reads the plain part of the header: `(nonce, kid)`.
pub fn peek(buf: &[u8]) -> Option<(u32, u16)> {
    if buf.len() < OVERHEAD {
        return None;
    }
    let nonce = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let kid = u16::from_be_bytes(buf[4..6].try_into().unwrap()) ^ mask16(nonce);
    Some((nonce, kid))
}

/// Decrypts in place and returns the payload length; the payload starts at
/// `OVERHEAD`. `None` means the packet is not ours and must be dropped.
pub fn decode(key: &Key, nonce: u32, kid: u16, buf: &mut [u8]) -> Option<usize> {
    if buf.len() < OVERHEAD {
        return None;
    }
    xor_stream(key.seed(nonce, kid), &mut buf[PLAIN_HDR..]);
    let magic = u32::from_be_bytes(buf[6..10].try_into().unwrap());
    let flags = buf[10];
    let len = usize::from(u16::from_be_bytes(buf[11..13].try_into().unwrap()));
    if magic != MAGIC || flags & 0x0f != TYPE_QUIC || OVERHEAD + len > buf.len() {
        return None;
    }
    Some(len)
}

/// Padding policy for outgoing packets.
#[derive(Debug, Clone, Copy, Default)]
pub struct Padding {
    /// Random padding range for short-header (data) packets; `None` = no padding.
    pub short: Option<(usize, usize)>,
}

impl Padding {
    fn pick(&self, payload: &[u8]) -> usize {
        let base = OVERHEAD + payload.len();
        let long = payload.first().is_some_and(|b| b & 0x80 != 0);
        if long {
            let lo = base.max(MIN_LONG_WIRE);
            // With a raised MTU the Initial is already past MAX_LONG_WIRE; keep varying it.
            let hi = if lo < MAX_LONG_WIRE { MAX_LONG_WIRE } else { MAX_WIRE };
            if lo >= hi {
                return 0;
            }
            return rand::random_range(lo..=hi) - base;
        }
        match self.short {
            Some((a, b)) if b > 0 => {
                let pad = rand::random_range(a..=b);
                pad.min(MAX_WIRE.saturating_sub(base))
            }
            _ => 0,
        }
    }

    /// Largest QUIC packet size that still fits `MAX_WIRE` after SSU framing.
    pub fn max_quic_mtu(&self) -> u16 {
        let pad = self.short.map_or(0, |(_, b)| b);
        (MAX_WIRE - OVERHEAD - pad).max(1200) as u16
    }
}

enum Role {
    Client {
        kid: u16,
        key: Key,
    },
    Server {
        keys: HashMap<u16, Key>,
        peers: Mutex<PeerTable>,
        replay: Mutex<ReplayWindow>,
    },
}

#[derive(Default)]
struct PeerTable {
    map: HashMap<SocketAddr, (u16, Instant)>,
    last_gc: Option<Instant>,
}

impl PeerTable {
    fn touch(&mut self, peer: SocketAddr, kid: u16, now: Instant) {
        self.map.insert(peer, (kid, now));
        if self.last_gc.is_none_or(|t| now - t > Duration::from_secs(60)) {
            self.map.retain(|_, (_, t)| now - *t < PEER_TTL);
            self.last_gc = Some(now);
        }
    }
}

#[derive(Default)]
struct ReplayWindow {
    seen: HashMap<(u16, u32), Instant>,
    last_gc: Option<Instant>,
}

impl ReplayWindow {
    /// Returns false if `(kid, nonce)` was already seen within the window.
    fn check(&mut self, kid: u16, nonce: u32, now: Instant) -> bool {
        if self.last_gc.is_none_or(|t| now - t > Duration::from_secs(10)) || self.seen.len() > 65536 {
            self.seen.retain(|_, t| now - *t < REPLAY_WINDOW);
            self.last_gc = Some(now);
        }
        match self.seen.insert((kid, nonce), now) {
            Some(t) => now - t >= REPLAY_WINDOW,
            None => true,
        }
    }
}

/// UDP socket that applies SSU framing to every datagram quinn sends/receives.
pub struct SsuSocket {
    io: tokio::net::UdpSocket,
    role: Role,
    padding: Padding,
}

impl fmt::Debug for SsuSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SsuSocket")
            .field("local", &self.io.local_addr())
            .finish()
    }
}

thread_local! {
    static SEND_BUF: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::with_capacity(2048));
}

impl SsuSocket {
    pub fn client(sock: std::net::UdpSocket, kid: u16, key: Key, padding: Padding) -> io::Result<Self> {
        Self::new(sock, Role::Client { kid, key }, padding)
    }

    pub fn server(sock: std::net::UdpSocket, keys: HashMap<u16, Key>, padding: Padding) -> io::Result<Self> {
        let role = Role::Server {
            keys,
            peers: Mutex::default(),
            replay: Mutex::default(),
        };
        Self::new(sock, role, padding)
    }

    fn new(sock: std::net::UdpSocket, role: Role, padding: Padding) -> io::Result<Self> {
        sock.set_nonblocking(true)?;
        let s2 = socket2::SockRef::from(&sock);
        let _ = s2.set_recv_buffer_size(4 << 20);
        let _ = s2.set_send_buffer_size(4 << 20);
        set_dont_fragment(&sock);
        Ok(SsuSocket {
            io: tokio::net::UdpSocket::from_std(sock)?,
            role,
            padding,
        })
    }

    fn send_one(&self, dest: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let (kid, key) = match &self.role {
            Role::Client { kid, key } => (*kid, key),
            Role::Server { keys, peers, .. } => {
                let Some(kid) = peers.lock().unwrap().map.get(&dest).map(|(k, _)| *k) else {
                    // Never answer a peer that has not authenticated.
                    return Ok(());
                };
                match keys.get(&kid) {
                    Some(k) => (kid, k),
                    None => return Ok(()),
                }
            }
        };
        let pad = self.padding.pick(payload);
        SEND_BUF.with_borrow_mut(|buf| {
            encode(key, kid, payload, pad, buf);
            match self.io.try_send_to(buf, dest) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
                // Like quinn-udp: other send errors are treated as packet loss.
                Err(e) => {
                    tracing::trace!("ssu send to {dest}: {e}");
                    Ok(())
                }
            }
        })
    }

    /// Decodes a received datagram in place; returns the QUIC payload length
    /// (moved to the start of `buf`) or `None` to drop it.
    fn open(&self, buf: &mut [u8], from: SocketAddr) -> Option<usize> {
        let (nonce, kid) = peek(buf)?;
        let len = match &self.role {
            Role::Client { kid: my, key } => {
                if kid != *my {
                    return None;
                }
                decode(key, nonce, kid, buf)?
            }
            Role::Server { keys, peers, replay } => {
                let key = keys.get(&kid)?;
                let len = decode(key, nonce, kid, buf)?;
                let now = Instant::now();
                let long = len > 0 && buf[OVERHEAD] & 0x80 != 0;
                if long && !replay.lock().unwrap().check(kid, nonce, now) {
                    tracing::debug!("ssu: replayed handshake packet from {from} dropped");
                    return None;
                }
                peers.lock().unwrap().touch(from, kid, now);
                len
            }
        };
        buf.copy_within(OVERHEAD..OVERHEAD + len, 0);
        Some(len)
    }
}

fn set_dont_fragment(sock: &std::net::UdpSocket) {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    let v4: libc::c_int = libc::IP_PMTUDISC_PROBE;
    let v6: libc::c_int = libc::IPV6_PMTUDISC_PROBE;
    // SAFETY: plain setsockopt on a valid fd with correctly sized int values.
    unsafe {
        let sz = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            (&v4 as *const libc::c_int).cast(),
            sz,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            (&v6 as *const libc::c_int).cast(),
            sz,
        );
    }
}

impl AsyncUdpSocket for SsuSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller { sock: self, fut: None })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let seg = transmit.segment_size.unwrap_or(transmit.contents.len()).max(1);
        for chunk in transmit.contents.chunks(seg) {
            self.send_one(transmit.destination, chunk)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let mut n = 0;
            while n < bufs.len() {
                match self.io.try_recv_from(&mut bufs[n]) {
                    Ok((len, from)) => {
                        if let Some(plen) = self.open(&mut bufs[n][..len], from) {
                            meta[n] = RecvMeta {
                                addr: from,
                                len: plen,
                                stride: plen,
                                ecn: None,
                                dst_ip: None,
                            };
                            n += 1;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    // ICMP errors (e.g. port unreachable) surface here; ignore them.
                    Err(e) => {
                        tracing::trace!("ssu recv: {e}");
                        if n > 0 {
                            break;
                        }
                    }
                }
            }
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

type WritableFut = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

struct Poller {
    sock: Arc<SsuSocket>,
    fut: Option<WritableFut>,
}

impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SsuPoller")
    }
}

impl UdpPoller for Poller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.fut.is_none() {
            let sock = this.sock.clone();
            this.fut = Some(Box::pin(async move { sock.io.writable().await }));
        }
        let res = this.fut.as_mut().unwrap().as_mut().poll(cx);
        if res.is_ready() {
            this.fut = None;
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(key: &Key, kid: u16, payload: &[u8], pad: usize) -> Option<Vec<u8>> {
        let mut wire = Vec::new();
        encode(key, kid, payload, pad, &mut wire);
        let (nonce, got_kid) = peek(&wire)?;
        assert_eq!(got_kid, kid);
        let len = decode(key, nonce, got_kid, &mut wire)?;
        Some(wire[OVERHEAD..OVERHEAD + len].to_vec())
    }

    #[test]
    fn encode_decode_roundtrip() {
        let key = Key::derive(7, "secret");
        for len in [0, 1, 7, 8, 9, 1200, 1439] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            for pad in [0, 3, 64] {
                assert_eq!(roundtrip(&key, 7, &payload, pad).unwrap(), payload);
            }
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = Key::derive(7, "secret");
        let other = Key::derive(7, "Secret");
        let mut wire = Vec::new();
        encode(&key, 7, b"hello quic", 0, &mut wire);
        let (nonce, kid) = peek(&wire).unwrap();
        assert!(decode(&other, nonce, kid, &mut wire).is_none());
    }

    #[test]
    fn tampered_header_is_rejected() {
        let key = Key::derive(1, "k");
        // magic + type bytes. (A flipped `len` may still fit; QUIC's AEAD rejects that packet.)
        for pos in PLAIN_HDR..OVERHEAD - 2 {
            let mut wire = Vec::new();
            encode(&key, 1, b"payload", 0, &mut wire);
            wire[pos] ^= 0x01;
            let (nonce, kid) = peek(&wire).unwrap();
            assert!(decode(&key, nonce, kid, &mut wire).is_none(), "flip at {pos} accepted");
        }
        // Flipping the nonce changes the keystream, so the magic check fails too.
        let mut wire = Vec::new();
        encode(&key, 1, b"payload", 0, &mut wire);
        wire[0] ^= 0x80;
        let (nonce, kid) = peek(&wire).unwrap();
        let ok = Key::derive(kid, "k");
        assert!(decode(&ok, nonce, kid, &mut wire).is_none());
    }

    #[test]
    fn same_payload_differs_on_wire() {
        let key = Key::derive(3, "k");
        let (mut a, mut b) = (Vec::new(), Vec::new());
        encode(&key, 3, &[0u8; 64], 0, &mut a);
        encode(&key, 3, &[0u8; 64], 0, &mut b);
        assert_ne!(a, b);
        // No shared prefix bytes that could act as a fingerprint (probabilistic, 2^-8 per byte).
        let same = a[..OVERHEAD].iter().zip(&b[..OVERHEAD]).filter(|(x, y)| x == y).count();
        assert!(same < 6, "too many equal header bytes: {same}");
    }

    #[test]
    fn long_header_padding_range() {
        let p = Padding::default();
        let mut initial = vec![0u8; 1200];
        initial[0] = 0xc0;
        for _ in 0..1000 {
            let total = OVERHEAD + initial.len() + p.pick(&initial);
            assert!((MIN_LONG_WIRE..=MAX_LONG_WIRE).contains(&total));
        }
        let short = vec![0x40u8; 500];
        assert_eq!(p.pick(&short), 0);
        let p = Padding { short: Some((4, 16)) };
        for _ in 0..1000 {
            assert!((4..=16).contains(&p.pick(&short)));
        }
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        let now = Instant::now();
        assert!(w.check(1, 42, now));
        assert!(!w.check(1, 42, now + Duration::from_secs(1)));
        assert!(w.check(2, 42, now));
        assert!(w.check(1, 42, now + REPLAY_WINDOW + Duration::from_secs(1)));
    }
}
