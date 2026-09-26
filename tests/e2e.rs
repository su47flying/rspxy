//! End-to-end: socks5/http client -> local proxy -> SSU/QUIC tunnel -> server -> target,
//! all in-process on loopback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rspxy::dialer::Dialer;
use rspxy::proto::Address;
use rspxy::proxy::{http, socks5};
use rspxy::ssu::Key;
use rspxy::tunnel::client::TunnelClient;
use rspxy::tunnel::{TunnelOpts, server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(60);

fn opts() -> TunnelOpts {
    TunnelOpts {
        connect_timeout: Duration::from_secs(5),
        ..TunnelOpts::default()
    }
}

async fn start_server(keys: &[(u16, &str)]) -> SocketAddr {
    let keys: HashMap<u16, Key> = keys.iter().map(|(id, s)| (*id, Key::derive(*id, s))).collect();
    let ep = server::bind("127.0.0.1:0".parse().unwrap(), keys, &opts()).unwrap();
    let addr = ep.local_addr().unwrap();
    tokio::spawn(server::run(ep));
    addr
}

fn tunnel(server: SocketAddr, kid: u16, secret: &str, opts: TunnelOpts) -> Dialer {
    Dialer::Tunnel(TunnelClient::new(Address::Ip(server), kid, Key::derive(kid, secret), opts).unwrap())
}

async fn start_socks(dialer: Dialer) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(socks5::serve(l, None, dialer));
    addr
}

async fn start_http(dialer: Dialer) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(http::serve(l, None, dialer));
    addr
}

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Serves `len` bytes of a deterministic pattern to every connection.
async fn tcp_source(len: usize) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let data = pattern(len);
                let _ = s.write_all(&data).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, from) = s.recv_from(&mut buf).await.unwrap();
            s.send_to(&buf[..n], from).await.unwrap();
        }
    });
    addr
}

/// UDP relay in front of `server` that drops `loss` of packets in each direction.
async fn lossy_relay(server: SocketAddr, loss: f64) -> SocketAddr {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = Arc::new(Mutex::new(None::<SocketAddr>));
    let addr = front.local_addr().unwrap();
    {
        let (front, back, client) = (front.clone(), back.clone(), client.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, from) = front.recv_from(&mut buf).await.unwrap();
                *client.lock().unwrap() = Some(from);
                if rand::random::<f64>() >= loss {
                    let _ = back.send_to(&buf[..n], server).await;
                }
            }
        });
    }
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, _) = back.recv_from(&mut buf).await.unwrap();
            let c = *client.lock().unwrap();
            if let Some(c) = c
                && rand::random::<f64>() >= loss
            {
                let _ = front.send_to(&buf[..n], c).await;
            }
        }
    });
    addr
}

/// SOCKS5 CONNECT; returns the stream and the reply code.
async fn socks_connect(proxy: SocketAddr, target: &Address) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, 1, 0];
    target.encode(&mut req);
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    (s, rep[1])
}

async fn socks_echo_roundtrip(proxy: SocketAddr, echo: SocketAddr, len: usize) {
    let (s, rep) = socks_connect(proxy, &Address::Ip(echo)).await;
    assert_eq!(rep, 0);
    let data = pattern(len);
    let (mut r, mut w) = s.into_split();
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();
    assert_eq!(got.len(), data.len());
    assert!(got == data, "echoed data differs");
}

#[tokio::test]
async fn socks5_connect_through_tunnel() {
    timeout(T, async {
        let server = start_server(&[(7, "secret")]).await;
        let proxy = start_socks(tunnel(server, 7, "secret", opts())).await;
        let echo = tcp_echo().await;
        socks_echo_roundtrip(proxy, echo, 1 << 20).await;
        // Several concurrent flows share one QUIC connection.
        let mut flows = Vec::new();
        for _ in 0..8 {
            flows.push(tokio::spawn(socks_echo_roundtrip(proxy, echo, 64 << 10)));
        }
        for f in flows {
            f.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks5_connect_direct_mode() {
    timeout(T, async {
        let proxy = start_socks(Dialer::Direct).await;
        socks_echo_roundtrip(proxy, tcp_echo().await, 100_000).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks5_connect_refused_maps_reply_code() {
    timeout(T, async {
        let server = start_server(&[(1, "k")]).await;
        let proxy = start_socks(tunnel(server, 1, "k", opts())).await;
        // Bind then drop to get a closed port.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let (_, rep) = socks_connect(proxy, &Address::Ip(closed)).await;
        assert_eq!(rep, 5, "connection refused");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_connect_forwards_pipelined_bytes() {
    timeout(T, async {
        let server = start_server(&[(1, "k")]).await;
        let proxy = start_http(tunnel(server, 1, "k", opts())).await;
        let echo = tcp_echo().await;
        let mut s = TcpStream::connect(proxy).await.unwrap();
        // CONNECT head and the first payload bytes in a single write.
        let req = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\nearly-hello");
        s.write_all(req.as_bytes()).await.unwrap();
        let expect = b"HTTP/1.1 200 Connection established\r\n\r\nearly-hello";
        let mut got = vec![0u8; expect.len()];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expect);
        s.write_all(b" more").await.unwrap();
        let mut more = [0u8; 5];
        s.read_exact(&mut more).await.unwrap();
        assert_eq!(&more, b" more");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn http_plain_request_is_rewritten() {
    timeout(T, async {
        let server = start_server(&[(1, "k")]).await;
        let proxy = start_http(tunnel(server, 1, "k", opts())).await;
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let oaddr = origin.local_addr().unwrap();
        let seen = tokio::spawn(async move {
            let (mut s, _) = origin.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut tmp).await.unwrap();
                buf.extend_from_slice(&tmp[..n]);
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            String::from_utf8(buf).unwrap()
        });
        let mut s = TcpStream::connect(proxy).await.unwrap();
        let req =
            format!("GET http://{oaddr}/path?q=1 HTTP/1.1\r\nHost: {oaddr}\r\nProxy-Connection: keep-alive\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200 OK"));
        assert!(resp.ends_with(b"ok"));
        let head = seen.await.unwrap();
        assert!(head.starts_with("GET /path?q=1 HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("Connection: close"));
        assert!(!head.to_ascii_lowercase().contains("proxy-connection"));
    })
    .await
    .unwrap();
}

/// SOCKS5 UDP ASSOCIATE; returns the control stream and the relay address.
async fn socks_udp_associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut rep = [0u8; 3];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    let Address::Ip(bnd) = Address::read_from(&mut s).await.unwrap() else {
        panic!()
    };
    (s, bnd)
}

#[tokio::test]
async fn socks5_udp_associate_through_tunnel() {
    timeout(T, async {
        let server = start_server(&[(1, "k")]).await;
        let proxy = start_socks(tunnel(server, 1, "k", opts())).await;
        let echo = udp_echo().await;
        let (_ctrl, relay) = socks_udp_associate(proxy).await;
        let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // 1200 fits a QUIC datagram; 3000 exercises the stream fallback.
        for size in [16, 1200, 3000] {
            let payload = pattern(size);
            let mut pkt = vec![0, 0, 0];
            Address::Ip(echo).encode(&mut pkt);
            pkt.extend_from_slice(&payload);
            let mut buf = vec![0u8; 65536];
            let mut ok = false;
            for _ in 0..5 {
                u.send_to(&pkt, relay).await.unwrap();
                if let Ok(Ok((n, _))) = timeout(Duration::from_secs(2), u.recv_from(&mut buf)).await {
                    let (from, off) = Address::decode(&buf[3..n]).unwrap();
                    assert_eq!(from, Address::Ip(echo));
                    assert_eq!(&buf[3 + off..n], &payload[..], "size {size}");
                    ok = true;
                    break;
                }
            }
            assert!(ok, "no udp echo for size {size}");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wrong_key_cannot_connect() {
    timeout(T, async {
        let server = start_server(&[(1, "right")]).await;
        let o = TunnelOpts {
            connect_timeout: Duration::from_secs(1),
            ..TunnelOpts::default()
        };
        let proxy = start_socks(tunnel(server, 1, "wrong", o)).await;
        let (_, rep) = socks_connect(proxy, &Address::Ip(tcp_echo().await)).await;
        assert_ne!(rep, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn multiple_key_ids_coexist() {
    timeout(T, async {
        let server = start_server(&[(1, "alpha"), (2, "beta")]).await;
        let echo = tcp_echo().await;
        let a = start_socks(tunnel(server, 1, "alpha", opts())).await;
        let b = start_socks(tunnel(server, 2, "beta", opts())).await;
        socks_echo_roundtrip(a, echo, 10_000).await;
        socks_echo_roundtrip(b, echo, 10_000).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn server_never_answers_probes() {
    timeout(T, async {
        let server = start_server(&[(1, "k")]).await;
        let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for len in [1, 13, 100, 1200, 1400] {
            let junk: Vec<u8> = (0..len).map(|_| rand::random()).collect();
            u.send_to(&junk, server).await.unwrap();
        }
        let mut buf = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(500), u.recv_from(&mut buf))
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bulk_transfer_survives_20pct_loss() {
    timeout(Duration::from_secs(120), async {
        let server = start_server(&[(1, "k")]).await;
        let relay = lossy_relay(server, 0.2).await;
        let o = TunnelOpts {
            connect_timeout: Duration::from_secs(20),
            ..TunnelOpts::default()
        };
        let proxy = start_socks(tunnel(relay, 1, "k", o)).await;
        let len = 10 << 20;
        let src = tcp_source(len).await;
        let (mut s, rep) = socks_connect(proxy, &Address::Ip(src)).await;
        assert_eq!(rep, 0);
        let start = std::time::Instant::now();
        let mut got = Vec::with_capacity(len);
        s.read_to_end(&mut got).await.unwrap();
        eprintln!("10MB over 20% loss in {:?}", start.elapsed());
        assert!(got == pattern(len), "data mismatch (got {} bytes)", got.len());
    })
    .await
    .unwrap();
}
