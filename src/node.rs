//! gost-style node URLs: `scheme://[user:pass@]host:port[?k=v&k=v]`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub scheme: String,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub host: String,
    pub port: u16,
    pub params: Vec<(String, String)>,
}

impl Node {
    pub fn parse(s: &str) -> anyhow::Result<Node> {
        let (scheme, rest) = s
            .split_once("://")
            .with_context(|| format!("missing scheme in {s:?}"))?;
        let scheme = scheme.to_ascii_lowercase();
        let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (user, pass) = match userinfo {
            Some(u) => match u.split_once(':') {
                Some((u, p)) => (Some(pct_decode(u)), Some(pct_decode(p))),
                None => (Some(pct_decode(u)), None),
            },
            None => (None, None),
        };
        let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
            let (h, p) = h
                .split_once("]:")
                .with_context(|| format!("bad address {hostport:?}"))?;
            (h.to_string(), p)
        } else {
            let (h, p) = hostport
                .rsplit_once(':')
                .with_context(|| format!("missing port in {hostport:?}"))?;
            (h.to_string(), p)
        };
        let port = port
            .trim_end_matches('/')
            .parse()
            .with_context(|| format!("bad port in {s:?}"))?;
        let params = query
            .split('&')
            .filter(|kv| !kv.is_empty())
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => (pct_decode(k), pct_decode(v)),
                None => (pct_decode(kv), String::new()),
            })
            .collect();
        Ok(Node {
            scheme,
            user,
            pass,
            host,
            port,
            params,
        })
    }

    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn params<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.params
            .iter()
            .filter(move |(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Address to listen on; an empty host means all IPv4 interfaces.
    pub fn bind_addr(&self) -> anyhow::Result<SocketAddr> {
        if self.host.is_empty() {
            return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.port));
        }
        let ip: IpAddr = self
            .host
            .parse()
            .with_context(|| format!("listen host must be an IP: {:?}", self.host))?;
        Ok(SocketAddr::new(ip, self.port))
    }

    /// `host:port` suitable for DNS resolution.
    pub fn host_port(&self) -> anyhow::Result<String> {
        if self.host.is_empty() {
            bail!("{}:// node needs a host", self.scheme);
        }
        Ok(if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        })
    }

    /// `user:pass` credentials if both are present.
    pub fn auth(&self) -> Option<(String, String)> {
        Some((self.user.clone()?, self.pass.clone().unwrap_or_default()))
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_nodes() {
        let n = Node::parse("socks5://:1080").unwrap();
        assert_eq!((n.scheme.as_str(), n.host.as_str(), n.port), ("socks5", "", 1080));
        assert_eq!(n.bind_addr().unwrap(), "0.0.0.0:1080".parse().unwrap());

        let n = Node::parse("http://u:p%40ss@127.0.0.1:8080").unwrap();
        assert_eq!(n.auth(), Some(("u".into(), "p@ss".into())));

        let n = Node::parse("SocksSimple://:5023?keys=/tmp/k.txt&key=1:a&key=2:b").unwrap();
        assert_eq!(n.scheme, "sockssimple");
        assert_eq!(n.param("keys"), Some("/tmp/k.txt"));
        assert_eq!(n.params("key").collect::<Vec<_>>(), ["1:a", "2:b"]);

        let n = Node::parse("socks5://[::1]:1080").unwrap();
        assert_eq!(n.bind_addr().unwrap(), "[::1]:1080".parse().unwrap());
    }

    #[test]
    fn parse_forward_node() {
        let n = Node::parse("ssu://7:sec:ret@203.0.113.10:5023?cc=bbr").unwrap();
        assert_eq!(n.user.as_deref(), Some("7"));
        assert_eq!(n.pass.as_deref(), Some("sec:ret"));
        assert_eq!(n.host_port().unwrap(), "203.0.113.10:5023");
        assert_eq!(n.param("cc"), Some("bbr"));
        assert!(Node::parse("ssu://host").is_err());
        assert!(Node::parse("host:1").is_err());
    }
}
