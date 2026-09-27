//! Tunnel server: accepts SSU/QUIC connections and connects onwards -- directly
//! (exit node), or through its own `-F` tunnel (relay node).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::io::AsyncReadExt;

use super::{TunnelOpts, parse_keys, server_config, udp};
use crate::dialer::{Dialer, UdpAssoc};
use crate::node::Node;
use crate::proto::{Address, CMD_TCP, CMD_UDP, VER, decode_datagram, rep};
use crate::relay::relay;
use crate::ssu::{Key, SsuSocket, table_secret};

type Assocs = Arc<Mutex<HashMap<u32, Arc<UdpAssoc>>>>;

/// Binds the SSU server endpoint.
pub fn bind(addr: SocketAddr, keys: HashMap<u16, Key>, opts: &TunnelOpts) -> anyhow::Result<Endpoint> {
    let sock = std::net::UdpSocket::bind(addr)?;
    // Both the stateless-reset key and the connection-ID check key derive from
    // the key table, so after a restart the server still recognises its old
    // connection IDs and resets those clients at once (instead of dropping
    // their packets as forged and leaving them to hit the idle timeout).
    let secret = table_secret(&keys);
    let reset_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret);
    let cid_key = u64::from_le_bytes(secret[..8].try_into().unwrap()) ^ 0x6369_645f_6b65_7931;
    let mut endpoint_config = quinn::EndpointConfig::new(Arc::new(reset_key));
    endpoint_config.cid_generator(move || Box::new(quinn_proto::HashedConnectionIdGenerator::from_key(cid_key)));
    let ssu = SsuSocket::server(sock, keys, opts.padding)?;
    Ok(Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(server_config(opts)?),
        Arc::new(ssu),
        Arc::new(quinn::TokioRuntime),
    )?)
}

pub async fn serve(node: Node, dialer: Dialer) -> anyhow::Result<()> {
    let keys = parse_keys(&node)?;
    let opts = TunnelOpts::from_node(&node)?;
    let mut ids: Vec<_> = keys.keys().copied().collect();
    ids.sort_unstable();
    let ep = bind(node.bind_addr()?, keys, &opts)?;
    let via = match &dialer {
        Dialer::Direct => "direct".to_string(),
        Dialer::Tunnel(t) => format!("relay via {}", t.server()),
    };
    tracing::info!(
        "ssu server on udp {} (key ids {ids:?}, cc {:?}, {via})",
        ep.local_addr()?,
        opts.cc
    );
    run(ep, dialer).await;
    Ok(())
}

pub async fn run(ep: Endpoint, dialer: Dialer) {
    while let Some(incoming) = ep.accept().await {
        let dialer = dialer.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => handle_conn(conn, dialer).await,
                Err(e) => tracing::debug!("ssu handshake failed: {e}"),
            }
        });
    }
}

async fn handle_conn(conn: Connection, dialer: Dialer) {
    let peer = conn.remote_address();
    tracing::info!("ssu: connection from {peer}");
    let assocs: Assocs = Arc::default();
    let dgram = tokio::spawn(datagram_loop(conn.clone(), assocs.clone()));
    super::spawn_stats(conn.clone());
    let next_id = Arc::new(AtomicU32::new(1));
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let (conn, assocs, next_id, dialer) = (conn.clone(), assocs.clone(), next_id.clone(), dialer.clone());
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(conn, assocs, next_id, dialer, send, recv).await {
                        tracing::debug!("ssu stream: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::info!("ssu: connection from {peer} closed: {e}");
                break;
            }
        }
    }
    dgram.abort();
}

async fn datagram_loop(conn: Connection, assocs: Assocs) {
    while let Ok(d) = conn.read_datagram().await {
        let Some((id, addr, off)) = decode_datagram(&d) else {
            continue;
        };
        let assoc = assocs.lock().unwrap().get(&id).cloned();
        if let Some(assoc) = assoc
            && let Err(e) = assoc.send(&addr, &d[off..]).await
        {
            tracing::debug!("udp assoc {id} send to {addr}: {e}");
        }
    }
}

async fn handle_stream(
    conn: Connection,
    assocs: Assocs,
    next_id: Arc<AtomicU32>,
    dialer: Dialer,
    mut send: SendStream,
    mut recv: RecvStream,
) -> anyhow::Result<()> {
    let ver = recv.read_u8().await?;
    let cmd = recv.read_u8().await?;
    if ver != VER {
        anyhow::bail!("unsupported version {ver}");
    }
    let addr = Address::read_from(&mut recv).await?;
    match cmd {
        CMD_TCP => match dialer.connect_tcp(&addr).await {
            Ok(up) => {
                tracing::debug!("tcp {addr} via {}", conn.remote_address());
                send.write_all(&[rep::SUCCEEDED]).await?;
                relay(tokio::io::join(recv, send), up).await?;
            }
            Err(e) => {
                tracing::info!("tcp {e}");
                send.write_all(&[e.rep]).await?;
                send.finish()?;
            }
        },
        CMD_UDP => udp_assoc(conn, assocs, next_id, &dialer, send, recv).await?,
        _ => {
            send.write_all(&[rep::CMD_UNSUPPORTED]).await?;
            send.finish()?;
        }
    }
    Ok(())
}

async fn udp_assoc(
    conn: Connection,
    assocs: Assocs,
    next_id: Arc<AtomicU32>,
    dialer: &Dialer,
    mut send: SendStream,
    mut recv: RecvStream,
) -> anyhow::Result<()> {
    let sock = match dialer.udp_associate().await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            send.write_all(&[e.rep]).await?;
            send.finish()?;
            anyhow::bail!("udp associate: {e}");
        }
    };
    let id = next_id.fetch_add(1, Ordering::Relaxed);
    let mut resp = vec![rep::SUCCEEDED];
    resp.extend_from_slice(&id.to_be_bytes());
    send.write_all(&resp).await?;
    assocs.lock().unwrap().insert(id, sock.clone());
    tracing::debug!("udp assoc {id} for {}", conn.remote_address());

    let send = Arc::new(tokio::sync::Mutex::new(send));
    let down = {
        let (conn, sock, send) = (conn.clone(), sock.clone(), send.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (from, n) = sock.recv(&mut buf).await?;
                udp::send(&conn, &send, id, &from, &buf[..n]).await?;
            }
            #[allow(unreachable_code)]
            Ok::<_, std::io::Error>(())
        })
    };
    // The association lives as long as its stream; oversized datagrams also arrive here.
    let mut buf = Vec::new();
    let res = loop {
        match udp::read_frame(&mut recv, &mut buf).await {
            Ok(Some((addr, off))) => {
                if let Err(e) = sock.send(&addr, &buf[off..]).await {
                    tracing::debug!("udp assoc {id} send to {addr}: {e}");
                }
            }
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    down.abort();
    assocs.lock().unwrap().remove(&id);
    tracing::debug!("udp assoc {id} closed");
    res.or_else(|e| {
        if e.kind() == std::io::ErrorKind::ConnectionReset {
            Ok(())
        } else {
            Err(e)
        }
    })?;
    Ok(())
}
