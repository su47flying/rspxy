//! SOCKS5 server (RFC 1928 / RFC 1929): CONNECT and UDP ASSOCIATE.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::bail;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::dialer::Dialer;
use crate::proto::{Address, rep};
use crate::relay::relay;

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

pub async fn serve(listener: TcpListener, auth: Option<(String, String)>, dialer: Dialer) -> anyhow::Result<()> {
    let auth = Arc::new(auth);
    loop {
        let (s, peer) = listener.accept().await?;
        let _ = s.set_nodelay(true);
        let (auth, dialer) = (auth.clone(), dialer.clone());
        tokio::spawn(async move {
            if let Err(e) = handle(s, &auth, &dialer).await {
                tracing::debug!("socks5 {peer}: {e}");
            }
        });
    }
}

fn reply(code: u8, bnd: SocketAddr) -> Vec<u8> {
    let mut out = vec![5, code, 0];
    Address::Ip(bnd).encode(&mut out);
    out
}

fn unspecified() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
}

async fn handle(mut s: TcpStream, auth: &Option<(String, String)>, dialer: &Dialer) -> anyhow::Result<()> {
    if s.read_u8().await? != 5 {
        bail!("not socks5");
    }
    let n = usize::from(s.read_u8().await?);
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;
    let method = match auth {
        Some(_) if methods.contains(&2) => 2,
        Some(_) => 0xff,
        None if methods.contains(&0) => 0,
        None if methods.contains(&2) => 2,
        None => 0xff,
    };
    s.write_all(&[5, method]).await?;
    if method == 0xff {
        bail!("no acceptable auth method");
    }
    if method == 2 {
        let _ver = s.read_u8().await?;
        let mut user = vec![0u8; usize::from(s.read_u8().await?)];
        s.read_exact(&mut user).await?;
        let mut pass = vec![0u8; usize::from(s.read_u8().await?)];
        s.read_exact(&mut pass).await?;
        let ok = auth
            .as_ref()
            .is_none_or(|(u, p)| u.as_bytes() == user && p.as_bytes() == pass);
        s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
        if !ok {
            bail!("auth failed");
        }
    }

    let mut hdr = [0u8; 3];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        bail!("bad request version");
    }
    let addr = match Address::read_from(&mut s).await {
        Ok(a) => a,
        Err(e) => {
            s.write_all(&reply(rep::ATYP_UNSUPPORTED, unspecified())).await?;
            return Err(e.into());
        }
    };
    match hdr[1] {
        CMD_CONNECT => connect(s, addr, dialer).await,
        CMD_UDP_ASSOCIATE => udp_associate(s, dialer).await,
        cmd => {
            s.write_all(&reply(rep::CMD_UNSUPPORTED, unspecified())).await?;
            bail!("unsupported command {cmd}");
        }
    }
}

async fn connect(mut s: TcpStream, addr: Address, dialer: &Dialer) -> anyhow::Result<()> {
    match dialer.connect_tcp(&addr).await {
        Ok(up) => {
            tracing::debug!("socks5 connect {addr}");
            s.write_all(&reply(rep::SUCCEEDED, unspecified())).await?;
            relay(s, up).await?;
        }
        Err(e) => {
            tracing::info!("socks5 connect {addr}: {e}");
            s.write_all(&reply(e.rep, unspecified())).await?;
        }
    }
    Ok(())
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

async fn udp_associate(mut s: TcpStream, dialer: &Dialer) -> anyhow::Result<()> {
    // Bind on the address the client reached us at, so the BND address is routable for it.
    let udp = UdpSocket::bind(SocketAddr::new(s.local_addr()?.ip(), 0)).await?;
    let assoc = match dialer.udp_associate().await {
        Ok(a) => a,
        Err(e) => {
            tracing::info!("socks5 udp associate: {e}");
            s.write_all(&reply(e.rep, unspecified())).await?;
            return Ok(());
        }
    };
    s.write_all(&reply(rep::SUCCEEDED, udp.local_addr()?)).await?;
    let client_ip = canonical(s.peer_addr()?.ip());
    tracing::debug!("socks5 udp associate for {client_ip} on {}", udp.local_addr()?);

    let mut client: Option<SocketAddr> = None;
    let mut cbuf = vec![0u8; 65536];
    let mut rbuf = vec![0u8; 65536];
    let mut tcp_buf = [0u8; 64];
    loop {
        tokio::select! {
            // The association ends when the control connection closes.
            r = s.read(&mut tcp_buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
            r = udp.recv_from(&mut cbuf) => {
                let (n, from) = match r {
                    Ok(v) => v,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
                    Err(e) => return Err(e.into()),
                };
                if canonical(from.ip()) != client_ip {
                    continue;
                }
                client = Some(from);
                // RSV(2) FRAG(1) ATYP ADDR PORT DATA; fragments are not supported.
                if n < 4 || cbuf[2] != 0 {
                    continue;
                }
                let Some((addr, off)) = Address::decode(&cbuf[3..n]) else { continue };
                if let Err(e) = assoc.send(&addr, &cbuf[3 + off..n]).await {
                    tracing::debug!("socks5 udp send to {addr}: {e}");
                    if e.kind() == io::ErrorKind::ConnectionAborted {
                        break;
                    }
                }
            }
            r = assoc.recv(&mut rbuf) => {
                let Ok((from, n)) = r else { break };
                if let Some(c) = client {
                    let mut pkt = Vec::with_capacity(n + 22);
                    pkt.extend_from_slice(&[0, 0, 0]);
                    from.encode(&mut pkt);
                    pkt.extend_from_slice(&rbuf[..n]);
                    let _ = udp.send_to(&pkt, c).await;
                }
            }
        }
    }
    Ok(())
}
