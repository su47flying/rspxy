//! Shadowsocks UDP relay: every packet is `salt | seal(ATYP ADDR PORT | data)`.
//! Each client address gets its own outbound UDP association, closed after
//! `IDLE_TIMEOUT` without traffic in either direction.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::Ctx;
use super::aead::{Key, TAG_LEN};
use crate::proto::Address;

const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const GC_INTERVAL: Duration = Duration::from_secs(60);
/// Packets queued per client while its association is being set up or is busy.
const QUEUE: usize = 256;

type Packet = (Address, Bytes);

pub(super) async fn serve(sock: UdpSocket, ctx: Arc<Ctx>) -> anyhow::Result<()> {
    let sock = Arc::new(sock);
    let mut sessions: HashMap<SocketAddr, mpsc::Sender<Packet>> = HashMap::new();
    let mut last_gc = Instant::now();
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, client) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
            Err(e) => return Err(e.into()),
        };
        // Packets that fail to decrypt are dropped without a reply.
        let Some((salt, addr, data)) = open_packet(&ctx.key, &mut buf[..n]) else {
            continue;
        };
        // Checked after decryption, so junk can't flush the filter.
        if !ctx.udp_salts.check(salt) {
            tracing::debug!("ss udp: replayed packet from {client} dropped");
            continue;
        }
        if last_gc.elapsed() >= GC_INTERVAL {
            sessions.retain(|_, tx| !tx.is_closed());
            last_gc = Instant::now();
        }
        let tx = match sessions.get(&client) {
            Some(tx) if !tx.is_closed() => tx.clone(),
            _ => {
                let (tx, rx) = mpsc::channel(QUEUE);
                tokio::spawn(session(sock.clone(), client, ctx.clone(), rx));
                sessions.insert(client, tx.clone());
                tx
            }
        };
        // Full queue: drop, like a congested UDP path would.
        let _ = tx.try_send((addr, Bytes::copy_from_slice(data)));
    }
}

async fn session(sock: Arc<UdpSocket>, client: SocketAddr, ctx: Arc<Ctx>, mut rx: mpsc::Receiver<Packet>) {
    let assoc = match ctx.dialer.udp_associate().await {
        Ok(a) => a,
        Err(e) => {
            tracing::info!("ss udp associate for {client}: {e}");
            return;
        }
    };
    tracing::debug!("ss udp session for {client}");
    let mut buf = vec![0u8; 65536];
    let mut out = Vec::with_capacity(2048);
    let idle = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            p = rx.recv() => {
                let Some((addr, data)) = p else { break };
                if let Err(e) = assoc.send(&addr, &data).await {
                    tracing::debug!("ss udp send to {addr}: {e}");
                    if e.kind() == io::ErrorKind::ConnectionAborted {
                        break;
                    }
                }
            }
            r = assoc.recv(&mut buf) => {
                let Ok((from, n)) = r else { break };
                seal_packet(&ctx.key, &from, &buf[..n], &mut out);
                // Our own salts are recorded too, so a reflected reply is rejected.
                ctx.udp_salts.check(&out[..ctx.key.salt_len()]);
                if let Err(e) = sock.send_to(&out, client).await {
                    tracing::debug!("ss udp reply to {client}: {e}");
                }
            }
            _ = &mut idle => break,
        }
        idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
    }
    tracing::debug!("ss udp session for {client} closed");
}

/// Encrypts `ATYP ADDR PORT | data` into `out` (cleared first) under a fresh salt.
pub fn seal_packet(key: &Key, addr: &Address, data: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&key.new_salt());
    let start = out.len();
    addr.encode(out);
    out.extend_from_slice(data);
    let mut cipher = key.cipher(&out[..start]);
    cipher.seal(out, start);
}

/// Decrypts a packet in place; returns `(salt, address, data)`.
pub fn open_packet<'a>(key: &Key, pkt: &'a mut [u8]) -> Option<(&'a [u8], Address, &'a [u8])> {
    let salt_len = key.salt_len();
    if pkt.len() < salt_len + TAG_LEN {
        return None;
    }
    let (salt, body) = pkt.split_at_mut(salt_len);
    let plain: &'a [u8] = key.cipher(salt).open(body)?;
    let (addr, off) = Address::decode(plain)?;
    Some((salt, addr, &plain[off..]))
}

#[cfg(test)]
mod tests {
    use super::super::aead::Method;
    use super::*;

    #[test]
    fn packet_roundtrip() {
        for method in [Method::Chacha20Poly1305, Method::Aes128Gcm, Method::Aes256Gcm] {
            let key = Key::new(method, "pw");
            let addr = Address::Domain("dns.google".into(), 53);
            let mut pkt = Vec::new();
            seal_packet(&key, &addr, b"query", &mut pkt);
            assert_eq!(pkt.len(), key.salt_len() + 1 + 1 + 10 + 2 + 5 + TAG_LEN);
            let salt = pkt[..key.salt_len()].to_vec();
            let (s, a, d) = open_packet(&key, &mut pkt).unwrap();
            assert_eq!((s, &a, d), (&salt[..], &addr, &b"query"[..]), "{method}");
        }
    }

    #[test]
    fn bad_packets_are_rejected() {
        let key = Key::new(Method::Chacha20Poly1305, "pw");
        let mut pkt = Vec::new();
        seal_packet(&key, &Address::Ip("1.2.3.4:53".parse().unwrap()), b"q", &mut pkt);

        let mut wrong = pkt.clone();
        assert!(open_packet(&Key::new(Method::Chacha20Poly1305, "other"), &mut wrong).is_none());
        for pos in [0, 40, pkt.len() - 1] {
            let mut t = pkt.clone();
            t[pos] ^= 0x40;
            assert!(open_packet(&key, &mut t).is_none(), "flip at {pos} accepted");
        }
        assert!(open_packet(&key, &mut pkt[..40]).is_none());
        assert!(open_packet(&key, &mut []).is_none());
    }
}
