//! Inner protocol spoken on QUIC streams/datagrams, plus SOCKS5 address codec.
//!
//! Stream request:  `ver u8 = 1 | cmd u8 | ATYP ADDR PORT`
//! Stream response: `status u8 (SOCKS5 REP code) | [assoc_id u32 BE if UDP_ASSOC ok]`
//! UDP datagram:    `assoc_id u32 BE | ATYP ADDR PORT | data`
//! Oversized UDP datagrams go on the association stream as `len u16 BE | ATYP ADDR PORT | data`.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

pub const VER: u8 = 1;
pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;

/// SOCKS5 reply codes, reused as tunnel status codes.
pub mod rep {
    pub const SUCCEEDED: u8 = 0;
    pub const GENERAL: u8 = 1;
    pub const NET_UNREACHABLE: u8 = 3;
    pub const HOST_UNREACHABLE: u8 = 4;
    pub const REFUSED: u8 = 5;
    pub const TTL_EXPIRED: u8 = 6;
    pub const CMD_UNSUPPORTED: u8 = 7;
    pub const ATYP_UNSUPPORTED: u8 = 8;
}

pub fn rep_from_io(e: &io::Error) -> u8 {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => rep::REFUSED,
        io::ErrorKind::NetworkUnreachable => rep::NET_UNREACHABLE,
        io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => rep::HOST_UNREACHABLE,
        io::ErrorKind::TimedOut => rep::TTL_EXPIRED,
        _ => rep::GENERAL,
    }
}

const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Address {
    /// Parses `host:port` / `[v6]:port`; `default_port` is used when absent.
    pub fn parse(s: &str, default_port: Option<u16>) -> Option<Address> {
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return Some(Address::Ip(sa));
        }
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (h, p) = rest.split_once(']')?;
            let port = match p.strip_prefix(':') {
                Some(p) => p.parse().ok()?,
                None if p.is_empty() => default_port?,
                None => return None,
            };
            (h, port)
        } else {
            match s.rsplit_once(':') {
                Some((h, p)) => (h, p.parse().ok()?),
                None => (s, default_port?),
            }
        };
        if host.is_empty() {
            return None;
        }
        Some(match host.parse::<IpAddr>() {
            Ok(ip) => Address::Ip(SocketAddr::new(ip, port)),
            Err(_) => Address::Domain(host.to_string(), port),
        })
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::Ip(sa) => sa.port(),
            Address::Domain(_, p) => *p,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Address::Ip(SocketAddr::V4(sa)) => {
                out.push(ATYP_V4);
                out.extend_from_slice(&sa.ip().octets());
            }
            Address::Ip(SocketAddr::V6(sa)) => {
                out.push(ATYP_V6);
                out.extend_from_slice(&sa.ip().octets());
            }
            Address::Domain(host, _) => {
                let h = &host.as_bytes()[..host.len().min(255)];
                out.push(ATYP_DOMAIN);
                out.push(h.len() as u8);
                out.extend_from_slice(h);
            }
        }
        out.extend_from_slice(&self.port().to_be_bytes());
    }

    /// Decodes from the start of `buf`; returns the address and bytes consumed.
    pub fn decode(buf: &[u8]) -> Option<(Address, usize)> {
        let (ip, n): (IpAddr, usize) = match *buf.first()? {
            ATYP_V4 => {
                let b: [u8; 4] = buf.get(1..5)?.try_into().ok()?;
                (Ipv4Addr::from(b).into(), 5)
            }
            ATYP_V6 => {
                let b: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
                (Ipv6Addr::from(b).into(), 17)
            }
            ATYP_DOMAIN => {
                let len = usize::from(*buf.get(1)?);
                let host = std::str::from_utf8(buf.get(2..2 + len)?).ok()?.to_string();
                let port = u16::from_be_bytes(buf.get(2 + len..4 + len)?.try_into().ok()?);
                return Some((Address::Domain(host, port), 4 + len));
            }
            _ => return None,
        };
        let port = u16::from_be_bytes(buf.get(n..n + 2)?.try_into().ok()?);
        Some((Address::Ip(SocketAddr::new(ip, port)), n + 2))
    }

    /// Reads `ATYP ADDR PORT` from a stream.
    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Address> {
        let atyp = r.read_u8().await?;
        let ip: IpAddr = match atyp {
            ATYP_V4 => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b).await?;
                Ipv4Addr::from(b).into()
            }
            ATYP_V6 => {
                let mut b = [0u8; 16];
                r.read_exact(&mut b).await?;
                Ipv6Addr::from(b).into()
            }
            ATYP_DOMAIN => {
                let len = usize::from(r.read_u8().await?);
                let mut b = vec![0u8; len];
                r.read_exact(&mut b).await?;
                let host =
                    String::from_utf8(b).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad domain"))?;
                let port = r.read_u16().await?;
                return Ok(Address::Domain(host, port));
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad address type")),
        };
        let port = r.read_u16().await?;
        Ok(Address::Ip(SocketAddr::new(ip, port)))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(sa) => sa.fmt(f),
            Address::Domain(h, p) => write!(f, "{h}:{p}"),
        }
    }
}

pub fn request(cmd: u8, addr: &Address) -> Vec<u8> {
    let mut out = vec![VER, cmd];
    addr.encode(&mut out);
    out
}

pub fn encode_datagram(id: u32, addr: &Address, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 19 + data.len());
    out.extend_from_slice(&id.to_be_bytes());
    addr.encode(&mut out);
    out.extend_from_slice(data);
    out
}

/// Returns `(assoc_id, address, data offset)`.
pub fn decode_datagram(buf: &[u8]) -> Option<(u32, Address, usize)> {
    let id = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?);
    let (addr, n) = Address::decode(&buf[4..])?;
    Some((id, addr, 4 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip() {
        for a in [
            Address::Ip("1.2.3.4:80".parse().unwrap()),
            Address::Ip("[2001:db8::1]:443".parse().unwrap()),
            Address::Domain("www.youtube.com".into(), 443),
        ] {
            let mut buf = Vec::new();
            a.encode(&mut buf);
            buf.extend_from_slice(b"tail");
            let (b, n) = Address::decode(&buf).unwrap();
            assert_eq!(a, b);
            assert_eq!(&buf[n..], b"tail");
        }
    }

    #[test]
    fn address_parse() {
        assert_eq!(
            Address::parse("example.com:443", None),
            Some(Address::Domain("example.com".into(), 443))
        );
        assert_eq!(
            Address::parse("example.com", Some(80)),
            Some(Address::Domain("example.com".into(), 80))
        );
        assert_eq!(
            Address::parse("[::1]:8080", None),
            Some(Address::Ip("[::1]:8080".parse().unwrap()))
        );
        assert_eq!(
            Address::parse("[::1]", Some(80)),
            Some(Address::Ip("[::1]:80".parse().unwrap()))
        );
        assert_eq!(Address::parse("example.com", None), None);
    }

    #[test]
    fn datagram_roundtrip() {
        let a = Address::Domain("dns.google".into(), 53);
        let d = encode_datagram(9, &a, b"query");
        let (id, b, off) = decode_datagram(&d).unwrap();
        assert_eq!((id, &b, &d[off..]), (9, &a, &b"query"[..]));
    }
}
