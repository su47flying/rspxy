//! Shadowsocks server, `-L ss://METHOD:PASSWORD@[ip]:port`: the AEAD ciphers
//! (SIP004) over TCP and UDP on the same port. Outbound traffic goes through
//! the dialer, so with `-F` it enters the SSU tunnel.

pub mod aead;
pub mod tcp;
pub mod udp;

use std::collections::HashSet;
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use tokio::net::{TcpListener, UdpSocket};

use crate::dialer::Dialer;
use crate::node::Node;
use crate::sys;
use aead::{Key, Method};

/// Salts per filter generation; the filter keeps two generations.
const SALT_GENERATION: usize = 1 << 17;
/// Ports tried, with port 0, for one that is free for both TCP and UDP.
const PORT_ATTEMPTS: usize = 16;

struct Ctx {
    key: Key,
    dialer: Dialer,
    tcp_salts: SaltFilter,
    udp_salts: SaltFilter,
}

pub struct Server {
    tcp: Option<TcpListener>,
    udp: Option<UdpSocket>,
    ctx: Arc<Ctx>,
}

impl Server {
    pub async fn bind(node: &Node, dialer: Dialer) -> anyhow::Result<Server> {
        let (key, tcp, udp) = parse(node)?;
        let (tcp, udp) = bind_sockets(node.bind_addr()?, tcp, udp).await?;
        if let Some(s) = &udp {
            sys::disable_udp_connreset(s)?;
            let s2 = socket2::SockRef::from(s);
            let _ = s2.set_recv_buffer_size(4 << 20);
            let _ = s2.set_send_buffer_size(4 << 20);
        }
        let via = match &dialer {
            Dialer::Direct => "direct".to_string(),
            Dialer::Tunnel(t) => format!("via ssu://{}", t.server()),
        };
        let proto = match (&tcp, &udp) {
            (Some(_), Some(_)) => "tcp+udp",
            (Some(_), None) => "tcp",
            _ => "udp",
        };
        let ctx = Arc::new(Ctx {
            key,
            dialer,
            tcp_salts: SaltFilter::new(SALT_GENERATION),
            udp_salts: SaltFilter::new(SALT_GENERATION),
        });
        let server = Server { tcp, udp, ctx };
        tracing::info!(
            "ss server on {proto} {} ({}, {via})",
            server.local_addr()?,
            server.ctx.key.method()
        );
        Ok(server)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match (&self.tcp, &self.udp) {
            (Some(l), _) => l.local_addr(),
            (None, Some(s)) => s.local_addr(),
            (None, None) => unreachable!("ss server binds tcp or udp"),
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let Server { tcp, udp, ctx } = self;
        let tcp = async {
            match tcp {
                Some(l) => tcp::serve(l, ctx.clone()).await,
                None => Ok(()),
            }
        };
        let udp = async {
            match udp {
                Some(s) => udp::serve(s, ctx.clone()).await,
                None => Ok(()),
            }
        };
        tokio::try_join!(tcp, udp)?;
        Ok(())
    }
}

pub async fn serve(node: Node, dialer: Dialer) -> anyhow::Result<()> {
    Server::bind(&node, dialer).await?.run().await
}

/// Binds TCP and/or UDP on `addr`. With port 0 both share one port: TCP picks it
/// and UDP takes the same number. That UDP port can be in use, or on Windows lie
/// in an excluded port range (WSAEACCES), so then another port is tried.
async fn bind_sockets(
    addr: SocketAddr,
    tcp: bool,
    udp: bool,
) -> anyhow::Result<(Option<TcpListener>, Option<UdpSocket>)> {
    let mut attempt = 1;
    loop {
        let l = if tcp {
            let l = TcpListener::bind(addr)
                .await
                .with_context(|| format!("listen tcp {addr}"))?;
            Some(l)
        } else {
            None
        };
        if !udp {
            return Ok((l, None));
        }
        let uaddr = match &l {
            Some(l) => l.local_addr()?,
            None => addr,
        };
        match UdpSocket::bind(uaddr).await {
            Ok(s) => return Ok((l, Some(s))),
            Err(e) if l.is_some() && addr.port() == 0 && attempt < PORT_ATTEMPTS => {
                tracing::debug!("ss: udp port {} unavailable ({e}), trying another", uaddr.port());
                attempt += 1;
            }
            Err(e) => return Err(e).with_context(|| format!("listen udp {uaddr}")),
        }
    }
}

/// Returns the key and whether TCP / UDP are enabled.
fn parse(node: &Node) -> anyhow::Result<(Key, bool, bool)> {
    let (Some(method), Some(password)) = (&node.user, &node.pass) else {
        bail!("ss:// needs METHOD:PASSWORD@, e.g. ss://chacha20-ietf-poly1305:PASSWORD@:8388");
    };
    let method = Method::parse(method).with_context(|| {
        format!(
            "unsupported ss method {method:?}: use chacha20-ietf-poly1305, aes-256-gcm or aes-128-gcm \
             (legacy stream ciphers are not supported)"
        )
    })?;
    if password.is_empty() {
        bail!("empty ss password");
    }
    let (tcp, udp) = match node.param("mode").unwrap_or("tcp_and_udp") {
        "tcp_and_udp" => (true, true),
        "tcp_only" => (true, false),
        "udp_only" => (false, true),
        other => bail!("unknown ss mode {other:?} (tcp_and_udp|tcp_only|udp_only)"),
    };
    if node.param("ota").is_some_and(|v| !matches!(v, "0" | "false")) {
        tracing::warn!(
            "ss: ota ignored: one-time auth only exists for the legacy stream ciphers; \
             {method} already authenticates every chunk and packet"
        );
    }
    Ok((Key::new(method, password), tcp, udp))
}

/// Salts seen recently, as 64-bit keyed hashes in two rotating generations,
/// so a replayed connection or packet is recognised. AEAD shadowsocks has no
/// timestamps, so this is the only replay defence the protocol allows.
struct SaltFilter {
    hasher: RandomState,
    cap: usize,
    sets: Mutex<[HashSet<u64>; 2]>,
}

impl SaltFilter {
    fn new(cap: usize) -> Self {
        SaltFilter {
            hasher: RandomState::new(),
            cap,
            sets: Mutex::default(),
        }
    }

    /// Records `salt`; returns false if it was already seen.
    fn check(&self, salt: &[u8]) -> bool {
        let h = self.hasher.hash_one(salt);
        let mut sets = self.sets.lock().unwrap();
        if sets.iter().any(|s| s.contains(&h)) {
            return false;
        }
        if sets[0].len() >= self.cap {
            sets[1] = std::mem::take(&mut sets[0]);
        }
        sets[0].insert(h);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_filter_rotates() {
        let f = SaltFilter::new(2);
        assert!(f.check(b"a"));
        assert!(!f.check(b"a"));
        assert!(f.check(b"b"));
        assert!(f.check(b"c")); // rotates: {c} + {a, b}
        assert!(!f.check(b"a"));
        assert!(f.check(b"d"));
        assert!(f.check(b"e")); // rotates: {e} + {c, d}; a and b are forgotten
        assert!(f.check(b"a"));
        assert!(!f.check(b"d"));
    }

    #[tokio::test]
    async fn port_0_gives_tcp_and_udp_the_same_port() {
        for _ in 0..20 {
            let (l, s) = bind_sockets("127.0.0.1:0".parse().unwrap(), true, true).await.unwrap();
            let (l, s) = (l.unwrap(), s.unwrap());
            assert_eq!(l.local_addr().unwrap(), s.local_addr().unwrap());
        }
    }

    #[test]
    fn parse_node() {
        let n = Node::parse("ss://chacha20-ietf-poly1305:pa:ss@:8388").unwrap();
        let (key, tcp, udp) = parse(&n).unwrap();
        assert_eq!((key.method(), tcp, udp), (Method::Chacha20Poly1305, true, true));

        let n = Node::parse("ss://aes-128-gcm:pw@127.0.0.1:8388?mode=udp_only&ota=true").unwrap();
        let (key, tcp, udp) = parse(&n).unwrap();
        assert_eq!((key.method(), tcp, udp), (Method::Aes128Gcm, false, true));

        for bad in [
            "ss://:8388",
            "ss://chacha20-ietf-poly1305@:8388",
            "ss://chacha20-ietf-poly1305:@:8388",
            "ss://aes-256-cfb:pw@:8388",
            "ss://aes-256-gcm:pw@:8388?mode=both",
        ] {
            assert!(parse(&Node::parse(bad).unwrap()).is_err(), "{bad}");
        }
    }
}
