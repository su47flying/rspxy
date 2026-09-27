//! QUIC tunnel carried over SSU-framed UDP.

pub mod cc;
pub mod client;
pub mod server;
pub mod udp;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use quinn::congestion::{BbrConfig, CubicConfig, NewRenoConfig};
use quinn::rustls;
use quinn::{TransportConfig, VarInt};

use crate::node::Node;
use crate::ssu::{Key, Padding};

const ALPN: &[u8] = b"ssu";
const STATS_INTERVAL: Duration = Duration::from_secs(5);

/// With debug logging on, periodically logs the QUIC path state of `conn`
/// (RTT, congestion window, loss) as deltas over the interval.
fn spawn_stats(conn: quinn::Connection) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    tokio::spawn(async move {
        let peer = conn.remote_address();
        let mut prev = conn.stats();
        let mut tick = tokio::time::interval(STATS_INTERVAL);
        tick.tick().await;
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = conn.closed() => break,
            }
            let s = conn.stats();
            let (p, q) = (&s.path, &prev.path);
            let secs = STATS_INTERVAL.as_secs_f64();
            tracing::debug!(
                "quic {peer}: rtt={}ms min_rtt={}ms cwnd={}KB mtu={} tx={:.1}Mbps rx={:.1}Mbps sent={} lost={} ({:.1}%) cong_events={} black_holes={}",
                p.rtt.as_millis(),
                p.min_rtt.as_millis(),
                p.cwnd / 1024,
                p.current_mtu,
                (s.udp_tx.bytes - prev.udp_tx.bytes) as f64 * 8.0 / 1e6 / secs,
                (s.udp_rx.bytes - prev.udp_rx.bytes) as f64 * 8.0 / 1e6 / secs,
                p.sent_packets - q.sent_packets,
                p.lost_packets - q.lost_packets,
                (p.lost_packets - q.lost_packets) as f64 * 100.0 / (p.sent_packets - q.sent_packets).max(1) as f64,
                p.congestion_events - q.congestion_events,
                p.black_holes_detected,
            );
            prev = s;
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    /// BBR that ignores random (non-persistent) loss; see `cc.rs`.
    Bbr,
    /// quinn's stock BBRv1.
    Bbr1,
    Cubic,
    NewReno,
}

#[derive(Debug, Clone)]
pub struct TunnelOpts {
    pub cc: Congestion,
    pub padding: Padding,
    /// Handshake timeout when (re)connecting to the server.
    pub connect_timeout: Duration,
    /// Fixed QUIC packet size (no MTU discovery); raise it only on paths known
    /// to carry larger UDP packets reliably.
    pub min_mtu: u16,
}

impl Default for TunnelOpts {
    fn default() -> Self {
        TunnelOpts {
            cc: Congestion::Bbr,
            padding: Padding::default(),
            connect_timeout: Duration::from_secs(10),
            min_mtu: 1200,
        }
    }
}

impl TunnelOpts {
    pub fn from_node(node: &Node) -> anyhow::Result<Self> {
        let mut o = TunnelOpts::default();
        if let Some(cc) = node.param("cc") {
            o.cc = match cc.to_ascii_lowercase().as_str() {
                "bbr" => Congestion::Bbr,
                "bbr1" => Congestion::Bbr1,
                "cubic" => Congestion::Cubic,
                "newreno" | "reno" => Congestion::NewReno,
                other => bail!("unknown cc {other:?} (bbr|bbr1|cubic|newreno)"),
            };
        }
        if let Some(p) = node.param("pad") {
            let (a, b) = p.split_once('-').unwrap_or((p, p));
            let (a, b): (usize, usize) = (a.parse()?, b.parse()?);
            if a > b || b > 256 {
                bail!("bad pad range {p:?} (e.g. 0-64, max 256)");
            }
            o.padding.short = (b > 0).then_some((a, b));
        }
        if let Some(m) = node.param("mtu") {
            let max = o.padding.max_quic_mtu();
            o.min_mtu = m.parse().with_context(|| format!("bad mtu {m:?}"))?;
            if !(1200..=max).contains(&o.min_mtu) {
                bail!("mtu must be within 1200..={max}");
            }
        }
        if let Some(t) = node.param("timeout") {
            o.connect_timeout = parse_duration(t)?;
        }
        Ok(o)
    }
}

fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let (num, mul) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1)
    } else if let Some(v) = s.strip_suffix('s') {
        (v, 1000)
    } else {
        (s, 1000)
    };
    Ok(Duration::from_millis(
        num.parse::<u64>().with_context(|| format!("bad duration {s:?}"))? * mul,
    ))
}

/// Keys for a server node: `user:pass@`, `?key=id:secret` (repeatable) and `?keys=file`.
pub fn parse_keys(node: &Node) -> anyhow::Result<HashMap<u16, Key>> {
    let mut entries: Vec<(String, String)> = Vec::new();
    if let (Some(u), Some(p)) = (&node.user, &node.pass) {
        entries.push((u.clone(), p.clone()));
    }
    for kv in node.params("key") {
        let (id, secret) = kv
            .split_once(':')
            .with_context(|| format!("key must be id:secret, got {kv:?}"))?;
        entries.push((id.into(), secret.into()));
    }
    for path in node.params("keys") {
        let text = std::fs::read_to_string(path).with_context(|| format!("read keys file {path}"))?;
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let mut it = line.split_whitespace();
            match (it.next(), it.next()) {
                (Some(id), Some(secret)) => entries.push((id.into(), secret.into())),
                _ => bail!("{path}: expected `id secret`, got {line:?}"),
            }
        }
    }
    let mut keys = HashMap::new();
    for (id, secret) in entries {
        let kid: u16 = id
            .parse()
            .with_context(|| format!("key id must be 0-65535, got {id:?}"))?;
        if secret.is_empty() {
            bail!("empty secret for key id {kid}");
        }
        keys.insert(kid, Key::derive(kid, &secret));
    }
    if keys.is_empty() {
        bail!(
            "{}:// server needs at least one key (user:pass@, ?key=id:secret or ?keys=file)",
            node.scheme
        );
    }
    Ok(keys)
}

/// Client credentials from `id:secret@`.
pub fn client_key(node: &Node) -> anyhow::Result<(u16, Key)> {
    let (id, secret) = node.auth().context("-F ssu:// needs id:secret@ credentials")?;
    let kid: u16 = id
        .parse()
        .with_context(|| format!("key id must be 0-65535, got {id:?}"))?;
    if secret.is_empty() {
        bail!("empty secret");
    }
    Ok((kid, Key::derive(kid, &secret)))
}

fn transport_config(opts: &TunnelOpts) -> TransportConfig {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    t.max_concurrent_bidi_streams(VarInt::from_u32(4096));
    t.max_concurrent_uni_streams(VarInt::from_u32(0));
    t.stream_receive_window(VarInt::from_u32(4 << 20));
    t.receive_window(VarInt::from_u32(16 << 20));
    t.send_window(16 << 20);
    t.datagram_receive_buffer_size(Some(1 << 20));
    t.datagram_send_buffer_size(1 << 20);
    t.initial_rtt(Duration::from_millis(200));
    // Fixed MTU, no path MTU discovery: on real paths full-size UDP packets
    // were probed successfully and then lost at 75-94%, with quinn flapping
    // between sizes through black-hole detection. Larger MTUs save only a few
    // percent of header overhead.
    t.initial_mtu(opts.min_mtu);
    t.min_mtu(opts.min_mtu);
    t.mtu_discovery_config(None);
    match opts.cc {
        Congestion::Bbr => t.congestion_controller_factory(Arc::new(cc::LossTolerantBbrConfig::default())),
        Congestion::Bbr1 => t.congestion_controller_factory(Arc::new(BbrConfig::default())),
        Congestion::Cubic => t.congestion_controller_factory(Arc::new(CubicConfig::default())),
        Congestion::NewReno => t.congestion_controller_factory(Arc::new(NewRenoConfig::default())),
    };
    t
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_config(opts: &TunnelOpts) -> anyhow::Result<quinn::ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    sc.transport_config(Arc::new(transport_config(opts)));
    Ok(sc)
}

fn client_config(opts: &TunnelOpts) -> anyhow::Result<quinn::ClientConfig> {
    let p = provider();
    let mut crypto = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(p)))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    let mut cc = quinn::ClientConfig::new(Arc::new(qcc));
    cc.transport_config(Arc::new(transport_config(opts)));
    Ok(cc)
}

/// The server's certificate is self-signed and not checked: only a peer that
/// knows an SSU key can get any packet through, so the SSU key is the identity.
#[derive(Debug)]
struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
