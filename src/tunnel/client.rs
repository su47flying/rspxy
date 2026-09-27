//! Tunnel entry: one shared QUIC connection to the server, a bi-stream per flow.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{TunnelOpts, client_config, client_key, udp};
use crate::dialer::{BoxStream, DialError, resolve};
use crate::node::Node;
use crate::proto::{Address, CMD_TCP, CMD_UDP, decode_datagram, rep, request};
use crate::ssu::{Key, SsuSocket};

type AssocTx = mpsc::Sender<(Address, Bytes)>;

struct ConnState {
    conn: Connection,
    assocs: Mutex<HashMap<u32, AssocTx>>,
}

pub struct TunnelClient {
    endpoint: Endpoint,
    server: Address,
    config: quinn::ClientConfig,
    opts: TunnelOpts,
    state: tokio::sync::Mutex<Option<Arc<ConnState>>>,
}

impl TunnelClient {
    pub fn from_node(node: &Node) -> anyhow::Result<Arc<Self>> {
        let (kid, key) = client_key(node)?;
        let opts = TunnelOpts::from_node(node)?;
        let server = Address::parse(&node.host_port()?, None).ok_or_else(|| anyhow::anyhow!("bad server address"))?;
        Self::new(server, kid, key, opts)
    }

    pub fn new(server: Address, kid: u16, key: Key, opts: TunnelOpts) -> anyhow::Result<Arc<Self>> {
        let bind_ip: IpAddr = match &server {
            Address::Ip(sa) if sa.is_ipv6() => Ipv6Addr::UNSPECIFIED.into(),
            _ => Ipv4Addr::UNSPECIFIED.into(),
        };
        let sock = std::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))?;
        let ssu = SsuSocket::client(sock, kid, key, opts.padding)?;
        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            Arc::new(ssu),
            Arc::new(quinn::TokioRuntime),
        )?;
        Ok(Arc::new(TunnelClient {
            endpoint,
            server,
            config: client_config(&opts)?,
            opts,
            state: tokio::sync::Mutex::new(None),
        }))
    }

    /// The server this client tunnels to.
    pub fn server(&self) -> &Address {
        &self.server
    }

    async fn state(&self) -> Result<Arc<ConnState>, DialError> {
        let mut guard = self.state.lock().await;
        if let Some(st) = &*guard
            && st.conn.close_reason().is_none()
        {
            return Ok(st.clone());
        }
        let addr = resolve(&self.server).await?[0];
        let connecting = self
            .endpoint
            .connect_with(self.config.clone(), addr, "localhost")
            .map_err(|e| DialError::new(rep::GENERAL, format!("ssu connect {addr}: {e}")))?;
        let conn = match tokio::time::timeout(self.opts.connect_timeout, connecting).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(DialError::new(rep::NET_UNREACHABLE, format!("ssu connect {addr}: {e}"))),
            Err(_) => {
                return Err(DialError::new(
                    rep::NET_UNREACHABLE,
                    format!("ssu connect {addr}: timeout"),
                ));
            }
        };
        tracing::info!("ssu: connected to {addr} (rtt {:?})", conn.rtt());
        let st = Arc::new(ConnState {
            conn,
            assocs: Mutex::default(),
        });
        tokio::spawn(datagram_loop(st.clone()));
        super::spawn_stats(st.conn.clone());
        *guard = Some(st.clone());
        Ok(st)
    }

    async fn invalidate(&self, st: &Arc<ConnState>) {
        let mut guard = self.state.lock().await;
        if guard.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, st)) {
            *guard = None;
        }
    }

    /// Opens a stream and sends `req`, reconnecting once if the connection is dead.
    async fn open(&self, req: &[u8]) -> Result<(SendStream, RecvStream, Arc<ConnState>), DialError> {
        let mut last = None;
        for _ in 0..2 {
            let st = self.state().await?;
            let res = async {
                let (mut send, recv) = st.conn.open_bi().await?;
                send.write_all(req).await?;
                Ok::<_, anyhow::Error>((send, recv))
            }
            .await;
            match res {
                Ok((send, recv)) => return Ok((send, recv, st)),
                Err(e) => {
                    tracing::debug!("ssu open stream: {e}; reconnecting");
                    self.invalidate(&st).await;
                    last = Some(e);
                }
            }
        }
        Err(DialError::new(
            rep::GENERAL,
            format!("ssu open stream: {}", last.unwrap()),
        ))
    }

    /// Sends `req` and reads the status byte. If the connection dies before the
    /// status arrives (e.g. the server restarted and reset it), the request was
    /// never answered, so it is retried once on a fresh connection.
    async fn call(&self, req: &[u8]) -> Result<(SendStream, RecvStream, Arc<ConnState>, u8), DialError> {
        let mut retried = false;
        loop {
            let (send, mut recv, st) = self.open(req).await?;
            match recv.read_u8().await {
                Ok(status) => return Ok((send, recv, st, status)),
                Err(e) if !retried && st.conn.close_reason().is_some() => {
                    tracing::debug!("ssu connection lost before reply ({e}); retrying");
                    self.invalidate(&st).await;
                    retried = true;
                }
                Err(e) => return Err(DialError::new(rep::GENERAL, format!("ssu request: {e}"))),
            }
        }
    }

    pub async fn connect_tcp(&self, addr: &Address) -> Result<BoxStream, DialError> {
        let (send, recv, _, status) = self.call(&request(CMD_TCP, addr)).await?;
        if status != rep::SUCCEEDED {
            return Err(DialError::new(status, format!("remote connect {addr} failed")));
        }
        Ok(Box::new(tokio::io::join(recv, send)))
    }

    pub async fn udp_associate(&self) -> Result<TunnelUdp, DialError> {
        let any = Address::Ip(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
        let (send, mut recv, st, status) = self.call(&request(CMD_UDP, &any)).await?;
        let err = |e: io::Error| DialError::new(rep::GENERAL, format!("ssu udp associate: {e}"));
        if status != rep::SUCCEEDED {
            return Err(DialError::new(status, "remote udp associate failed"));
        }
        let id = recv.read_u32().await.map_err(err)?;
        let (tx, rx) = mpsc::channel(512);
        st.assocs.lock().unwrap().insert(id, tx.clone());
        let reader = tokio::spawn(async move {
            let mut buf = Vec::new();
            while let Ok(Some((addr, off))) = udp::read_frame(&mut recv, &mut buf).await {
                if tx.send((addr, Bytes::copy_from_slice(&buf[off..]))).await.is_err() {
                    break;
                }
            }
        });
        Ok(TunnelUdp {
            id,
            state: st,
            send: tokio::sync::Mutex::new(send),
            rx: tokio::sync::Mutex::new(rx),
            reader,
        })
    }
}

async fn datagram_loop(st: Arc<ConnState>) {
    while let Ok(d) = st.conn.read_datagram().await {
        let Some((id, addr, off)) = decode_datagram(&d) else {
            continue;
        };
        let tx = st.assocs.lock().unwrap().get(&id).cloned();
        if let Some(tx) = tx {
            // Full queue: drop, like a congested UDP path would.
            let _ = tx.try_send((addr, d.slice(off..)));
        }
    }
}

/// A UDP association relayed through the tunnel.
pub struct TunnelUdp {
    id: u32,
    state: Arc<ConnState>,
    send: tokio::sync::Mutex<SendStream>,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Address, Bytes)>>,
    reader: JoinHandle<()>,
}

impl TunnelUdp {
    pub async fn send(&self, addr: &Address, data: &[u8]) -> io::Result<()> {
        udp::send(&self.state.conn, &self.send, self.id, addr, data).await
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(Address, usize)> {
        let (addr, data) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "udp association closed"))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((addr, n))
    }
}

impl Drop for TunnelUdp {
    fn drop(&mut self) {
        self.reader.abort();
        self.state.assocs.lock().unwrap().remove(&self.id);
        // Dropping the SendStream finishes it, which tells the server to tear down.
    }
}
