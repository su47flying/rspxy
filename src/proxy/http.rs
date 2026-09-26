//! HTTP proxy: CONNECT tunnels and plain absolute-form requests.

use std::io;
use std::sync::Arc;

use anyhow::bail;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dialer::Dialer;
use crate::proto::Address;
use crate::relay::relay;

const MAX_HEAD: usize = 64 << 10;

pub async fn serve(listener: TcpListener, auth: Option<(String, String)>, dialer: Dialer) -> anyhow::Result<()> {
    let expected = Arc::new(auth.map(|(u, p)| format!("Basic {}", base64(format!("{u}:{p}").as_bytes()))));
    loop {
        let (s, peer) = listener.accept().await?;
        let _ = s.set_nodelay(true);
        let (expected, dialer) = (expected.clone(), dialer.clone());
        tokio::spawn(async move {
            if let Err(e) = handle(s, expected.as_deref(), &dialer).await {
                tracing::debug!("http {peer}: {e}");
            }
        });
    }
}

async fn read_head(s: &mut TcpStream) -> io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let start = buf.len().saturating_sub(3);
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf[start..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = start + i;
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            return Ok((head, buf[end + 4..].to_vec()));
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request head too large"));
        }
    }
}

async fn respond(s: &mut TcpStream, status: &str, extra: &str) -> io::Result<()> {
    let msg = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n");
    s.write_all(msg.as_bytes()).await
}

async fn handle(mut s: TcpStream, expected_auth: Option<&str>, dialer: &Dialer) -> anyhow::Result<()> {
    let (head, rest) = read_head(&mut s).await?;
    let mut lines = head.split("\r\n");
    let mut req = lines.next().unwrap_or_default().splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (req.next(), req.next(), req.next()) else {
        respond(&mut s, "400 Bad Request", "").await?;
        bail!("bad request line");
    };
    let headers: Vec<(&str, &str)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();

    if let Some(expected) = expected_auth {
        let ok = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("proxy-authorization") && *v == expected);
        if !ok {
            respond(
                &mut s,
                "407 Proxy Authentication Required",
                "Proxy-Authenticate: Basic realm=\"rspxy\"\r\n",
            )
            .await?;
            bail!("proxy auth failed");
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some(addr) = Address::parse(target, Some(443)) else {
            respond(&mut s, "400 Bad Request", "").await?;
            bail!("bad CONNECT target {target:?}");
        };
        let mut up = match dialer.connect_tcp(&addr).await {
            Ok(up) => up,
            Err(e) => {
                tracing::info!("http connect {addr}: {e}");
                respond(&mut s, "502 Bad Gateway", "").await?;
                return Ok(());
            }
        };
        tracing::debug!("http connect {addr}");
        s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
        // Bytes pipelined after the CONNECT head (e.g. a TLS ClientHello) belong upstream.
        if !rest.is_empty() {
            up.write_all(&rest).await?;
        }
        relay(s, up).await?;
        return Ok(());
    }

    // Plain HTTP: absolute-form -> origin-form, one request per upstream connection.
    let url = target
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("http://"))
        .map(|_| &target[7..]);
    let Some(url) = url else {
        respond(&mut s, "400 Bad Request", "").await?;
        bail!("unsupported request target {target:?}");
    };
    let split = url.find(['/', '?']).unwrap_or(url.len());
    let (authority, path) = url.split_at(split);
    let path = match path {
        "" => "/".to_string(),
        p if p.starts_with('?') => format!("/{p}"),
        p => p.to_string(),
    };
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let Some(addr) = Address::parse(hostport, Some(80)) else {
        respond(&mut s, "400 Bad Request", "").await?;
        bail!("bad host {hostport:?}");
    };
    let mut up = match dialer.connect_tcp(&addr).await {
        Ok(up) => up,
        Err(e) => {
            tracing::info!("http {addr}: {e}");
            respond(&mut s, "502 Bad Gateway", "").await?;
            return Ok(());
        }
    };
    tracing::debug!("http {method} {addr}{path}");
    let mut out = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for (k, v) in &headers {
        let lower = k.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive"
        ) {
            continue;
        }
        has_host |= lower == "host";
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_host {
        out.push_str(&format!("Host: {hostport}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    up.write_all(out.as_bytes()).await?;
    if !rest.is_empty() {
        up.write_all(&rest).await?;
    }
    relay(s, up).await?;
    Ok(())
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_encodes() {
        assert_eq!(super::base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(super::base64(b"a"), "YQ==");
        assert_eq!(super::base64(b"ab"), "YWI=");
        assert_eq!(super::base64(b""), "");
    }
}
