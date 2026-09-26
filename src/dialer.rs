//! Outbound connections: either directly or through the SSU tunnel.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket, lookup_host};

use crate::proto::{Address, rep, rep_from_io};
use crate::tunnel::client::{TunnelClient, TunnelUdp};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxStream = Box<dyn AsyncStream>;

#[derive(Debug)]
pub struct DialError {
    /// SOCKS5 REP code describing the failure.
    pub rep: u8,
    pub msg: String,
}

impl DialError {
    pub fn new(rep: u8, msg: impl fmt::Display) -> Self {
        DialError {
            rep,
            msg: msg.to_string(),
        }
    }
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (rep={})", self.msg, self.rep)
    }
}

impl From<io::Error> for DialError {
    fn from(e: io::Error) -> Self {
        DialError::new(rep_from_io(&e), e)
    }
}

#[derive(Clone)]
pub enum Dialer {
    Direct,
    Tunnel(Arc<TunnelClient>),
}

impl Dialer {
    pub async fn connect_tcp(&self, addr: &Address) -> Result<BoxStream, DialError> {
        match self {
            Dialer::Direct => Ok(Box::new(connect_direct(addr).await?)),
            Dialer::Tunnel(t) => t.connect_tcp(addr).await,
        }
    }

    pub async fn udp_associate(&self) -> Result<UdpAssoc, DialError> {
        match self {
            Dialer::Direct => Ok(UdpAssoc::Direct(DirectUdp::bind().await?)),
            Dialer::Tunnel(t) => Ok(UdpAssoc::Tunnel(t.udp_associate().await?)),
        }
    }
}

/// Resolves an address, IPv4 first (the exit host has no IPv6 route).
pub async fn resolve(addr: &Address) -> Result<Vec<SocketAddr>, DialError> {
    match addr {
        Address::Ip(sa) => Ok(vec![*sa]),
        Address::Domain(host, port) => {
            let mut v: Vec<SocketAddr> = lookup_host((host.as_str(), *port))
                .await
                .map_err(|e| DialError::new(rep::HOST_UNREACHABLE, format!("resolve {host}: {e}")))?
                .collect();
            if v.is_empty() {
                return Err(DialError::new(
                    rep::HOST_UNREACHABLE,
                    format!("resolve {host}: no address"),
                ));
            }
            v.sort_by_key(SocketAddr::is_ipv6);
            Ok(v)
        }
    }
}

pub async fn connect_direct(addr: &Address) -> Result<TcpStream, DialError> {
    let addrs = resolve(addr).await?;
    let mut last = DialError::new(rep::GENERAL, "no address");
    for sa in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(sa)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = DialError::new(rep_from_io(&e), format!("connect {addr} ({sa}): {e}")),
            Err(_) => last = DialError::new(rep::TTL_EXPIRED, format!("connect {addr} ({sa}): timeout")),
        }
    }
    Err(last)
}

pub enum UdpAssoc {
    Direct(DirectUdp),
    Tunnel(TunnelUdp),
}

impl UdpAssoc {
    pub async fn send(&self, addr: &Address, data: &[u8]) -> io::Result<()> {
        match self {
            UdpAssoc::Direct(d) => d.send(addr, data).await,
            UdpAssoc::Tunnel(t) => t.send(addr, data).await,
        }
    }

    /// Receives one datagram into `buf`, returning its source and length.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(Address, usize)> {
        match self {
            UdpAssoc::Direct(d) => d.recv(buf).await,
            UdpAssoc::Tunnel(t) => t.recv(buf).await,
        }
    }
}

/// A plain UDP socket that relays to arbitrary targets, caching DNS lookups.
pub struct DirectUdp {
    sock: UdpSocket,
    dns: Mutex<HashMap<(String, u16), SocketAddr>>,
}

impl DirectUdp {
    pub async fn bind() -> io::Result<Self> {
        Ok(DirectUdp {
            sock: UdpSocket::bind("0.0.0.0:0").await?,
            dns: Mutex::default(),
        })
    }

    pub async fn send(&self, addr: &Address, data: &[u8]) -> io::Result<()> {
        let target = match addr {
            Address::Ip(sa) => *sa,
            Address::Domain(host, port) => {
                let cached = self.dns.lock().unwrap().get(&(host.clone(), *port)).copied();
                match cached {
                    Some(sa) => sa,
                    None => {
                        let sa = resolve(addr)
                            .await
                            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.msg))?[0];
                        let mut dns = self.dns.lock().unwrap();
                        if dns.len() > 1024 {
                            dns.clear();
                        }
                        dns.insert((host.clone(), *port), sa);
                        sa
                    }
                }
            }
        };
        self.sock.send_to(data, target).await.map(|_| ())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(Address, usize)> {
        loop {
            match self.sock.recv_from(buf).await {
                Ok((n, from)) => return Ok((Address::Ip(from), n)),
                // ICMP port unreachable from an earlier send; not fatal for the association.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
                Err(e) => return Err(e),
            }
        }
    }
}
