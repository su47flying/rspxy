//! Shadowsocks TCP relay: `salt | chunks` in each direction, with the target
//! address as the first plaintext from the client.

use std::io;
use std::net::SocketAddr;
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use anyhow::bail;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout_at};

use super::Ctx;
use super::aead::{Cipher, MAX_PAYLOAD, TAG_LEN};
use crate::proto::Address;

/// Time a client has to send its salt and target address.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Holds a few full chunks, so one socket read can complete several.
const READ_BUF: usize = 4 * (2 + MAX_PAYLOAD + 2 * TAG_LEN);

pub(super) async fn serve(listener: TcpListener, ctx: Arc<Ctx>) -> anyhow::Result<()> {
    loop {
        let (s, peer) = listener.accept().await?;
        let _ = s.set_nodelay(true);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(s, peer, &ctx).await {
                tracing::debug!("ss {peer}: {e}");
            }
        });
    }
}

async fn handle(s: TcpStream, peer: SocketAddr, ctx: &Ctx) -> anyhow::Result<()> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let (mut r, mut w) = s.into_split();
    let mut salt = vec![0u8; ctx.key.salt_len()];
    match timeout_at(deadline, r.read_exact(&mut salt)).await {
        Ok(res) => res?,
        Err(_) => bail!("handshake timeout"),
    };
    let mut reader = DecryptReader::new(r, ctx.key.cipher(&salt));
    let addr = match timeout_at(deadline, Address::read_from(&mut reader)).await {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) if e.kind() == io::ErrorKind::InvalidData => {
            drain(reader.into_inner(), deadline).await;
            bail!("rejected: {e}");
        }
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => bail!("handshake timeout"),
    };
    // Checked only once the first chunk authenticated, so junk can't flush the filter.
    if !ctx.tcp_salts.check(&salt) {
        drain(reader.into_inner(), deadline).await;
        bail!("replayed salt (target {addr})");
    }

    let up = match ctx.dialer.connect_tcp(&addr).await {
        Ok(up) => up,
        Err(e) => {
            tracing::info!("ss connect {addr}: {e}");
            return Ok(());
        }
    };
    tracing::debug!("ss connect {addr} from {peer}");
    let (mut up_r, mut up_w) = tokio::io::split(up);
    let salt = ctx.key.new_salt();
    // Our own salts are recorded too, so a reflected server stream is rejected.
    ctx.tcp_salts.check(&salt);
    let mut enc = ctx.key.cipher(&salt);
    let upload = async {
        tokio::io::copy_buf(&mut reader, &mut up_w).await?;
        up_w.shutdown().await
    };
    let download = async {
        copy_encrypt(&mut up_r, &mut w, &salt, &mut enc).await?;
        w.shutdown().await
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

/// A connection that failed authentication gets no reply and no early close:
/// keep reading until the client gives up or the handshake deadline passes,
/// so a prober can't learn anything from how many bytes it sent.
async fn drain<R: AsyncRead + Unpin>(mut r: R, deadline: Instant) {
    let _ = timeout_at(deadline, tokio::io::copy(&mut r, &mut tokio::io::sink())).await;
}

/// Copies `r` to `w` as encrypted chunks; the first write starts with `salt`.
/// Nothing is written if `r` ends without data.
pub async fn copy_encrypt<R, W>(r: &mut R, w: &mut W, salt: &[u8], cipher: &mut Cipher) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut plain = vec![0u8; 4 * MAX_PAYLOAD];
    let mut out = Vec::with_capacity(salt.len() + plain.len() + 4 * (2 + 2 * TAG_LEN));
    out.extend_from_slice(salt);
    let mut total = 0;
    loop {
        let n = r.read(&mut plain).await?;
        if n == 0 {
            return Ok(total);
        }
        for chunk in plain[..n].chunks(MAX_PAYLOAD) {
            cipher.seal_chunk(chunk, &mut out);
        }
        w.write_all(&out).await?;
        out.clear();
        total += n as u64;
    }
}

/// Decrypts a chunk stream (after the salt) from `inner`. Authentication
/// failures surface as `InvalidData` errors.
pub struct DecryptReader<R> {
    inner: R,
    cipher: Cipher,
    /// Raw bytes read from `inner`, decrypted in place.
    buf: Box<[u8]>,
    /// Not yet decrypted bytes.
    start: usize,
    end: usize,
    /// Decrypted bytes not yet consumed.
    plain: Range<usize>,
    /// Length of the chunk whose length prefix was already decrypted.
    pending: Option<usize>,
}

impl<R> DecryptReader<R> {
    pub fn new(inner: R, cipher: Cipher) -> Self {
        DecryptReader {
            inner,
            cipher,
            buf: vec![0u8; READ_BUF].into_boxed_slice(),
            start: 0,
            end: 0,
            plain: 0..0,
            pending: None,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Decrypts the next length prefix or payload if it is fully buffered.
    /// Returns false when more input is needed.
    fn decode(&mut self) -> io::Result<bool> {
        let avail = self.end - self.start;
        match self.pending {
            None if avail >= 2 + TAG_LEN => {
                let unit = &mut self.buf[self.start..self.start + 2 + TAG_LEN];
                let p = self
                    .cipher
                    .open(unit)
                    .ok_or_else(|| bad_data("ss: chunk length authentication failed"))?;
                let len = usize::from(u16::from_be_bytes([p[0], p[1]]));
                if len > MAX_PAYLOAD {
                    return Err(bad_data("ss: chunk too large"));
                }
                self.start += 2 + TAG_LEN;
                self.pending = Some(len);
                Ok(true)
            }
            Some(len) if avail >= len + TAG_LEN => {
                let unit = &mut self.buf[self.start..self.start + len + TAG_LEN];
                self.cipher
                    .open(unit)
                    .ok_or_else(|| bad_data("ss: chunk authentication failed"))?;
                self.plain = self.start..self.start + len;
                self.start += len + TAG_LEN;
                self.pending = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

fn bad_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl<R: AsyncRead + Unpin> AsyncBufRead for DecryptReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        loop {
            if !this.plain.is_empty() {
                return Poll::Ready(Ok(&this.buf[this.plain.clone()]));
            }
            if this.decode()? {
                continue;
            }
            // Nothing decrypted is pending, so the partial unit can move to the front.
            if this.start > 0 {
                this.buf.copy_within(this.start..this.end, 0);
                this.end -= this.start;
                this.start = 0;
                this.plain = 0..0;
            }
            let mut rb = ReadBuf::new(&mut this.buf[this.end..]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                if this.end == 0 && this.pending.is_none() {
                    return Poll::Ready(Ok(&[]));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ss: stream ended inside a chunk",
                )));
            }
            this.end += n;
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        this.plain.start = (this.plain.start + amt).min(this.plain.end);
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DecryptReader<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let n = data.len().min(out.remaining());
        out.put_slice(&data[..n]);
        self.consume(n);
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::aead::{Key, Method};
    use super::*;

    fn stream(key: &Key, salt: &[u8], payloads: &[&[u8]]) -> Vec<u8> {
        let mut c = key.cipher(salt);
        let mut out = Vec::new();
        for p in payloads {
            for chunk in p.chunks(MAX_PAYLOAD) {
                c.seal_chunk(chunk, &mut out);
            }
        }
        out
    }

    /// Feeds `wire` in `step`-byte writes and reads everything back.
    async fn read_all(key: &Key, salt: &[u8], wire: Vec<u8>, step: usize) -> io::Result<Vec<u8>> {
        let (mut tx, rx) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            for part in wire.chunks(step) {
                tx.write_all(part).await.unwrap();
            }
        });
        let mut r = DecryptReader::new(rx, key.cipher(salt));
        let mut got = Vec::new();
        r.read_to_end(&mut got).await?;
        Ok(got)
    }

    #[tokio::test]
    async fn reader_reassembles_chunks() {
        let key = Key::new(Method::Chacha20Poly1305, "pw");
        let salt = key.new_salt();
        let big: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        let wire = stream(&key, &salt, &[b"first", &big, b"", b"last"]);
        let mut want = b"first".to_vec();
        want.extend_from_slice(&big);
        want.extend_from_slice(b"last");
        for step in [1, 7, 18, 4096, 1 << 16] {
            assert_eq!(
                read_all(&key, &salt, wire.clone(), step).await.unwrap(),
                want,
                "step {step}"
            );
        }
    }

    #[tokio::test]
    async fn reader_parses_address_split_across_chunks() {
        let key = Key::new(Method::Aes128Gcm, "pw");
        let salt = key.new_salt();
        let mut hdr = Vec::new();
        Address::Domain("example.com".into(), 443).encode(&mut hdr);
        let wire = stream(&key, &salt, &[&hdr[..3], &hdr[3..], b"GET /"]);
        let (mut tx, rx) = tokio::io::duplex(4096);
        tx.write_all(&wire).await.unwrap();
        drop(tx);
        let mut r = DecryptReader::new(rx, key.cipher(&salt));
        let addr = Address::read_from(&mut r).await.unwrap();
        assert_eq!(addr, Address::Domain("example.com".into(), 443));
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"GET /");
    }

    #[tokio::test]
    async fn reader_rejects_tamper_and_truncation() {
        let key = Key::new(Method::Aes256Gcm, "pw");
        let salt = key.new_salt();
        let wire = stream(&key, &salt, &[b"hello world"]);

        let mut flipped = wire.clone();
        *flipped.last_mut().unwrap() ^= 1;
        let e = read_all(&key, &salt, flipped, 1 << 16).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);

        let other = Key::new(Method::Aes256Gcm, "other");
        let e = read_all(&other, &salt, wire.clone(), 64).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);

        let e = read_all(&key, &salt, wire[..wire.len() - 1].to_vec(), 64)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn copy_encrypt_roundtrip() {
        let key = Key::new(Method::Chacha20Poly1305, "pw");
        let salt = key.new_salt();
        let data: Vec<u8> = (0..200_000).map(|i| (i * 7 % 256) as u8).collect();
        let mut wire = Vec::new();
        copy_encrypt(&mut &data[..], &mut wire, &salt, &mut key.cipher(&salt))
            .await
            .unwrap();
        assert_eq!(&wire[..salt.len()], &salt[..]);
        let got = read_all(&key, &salt, wire[salt.len()..].to_vec(), 5000).await.unwrap();
        assert_eq!(got, data);

        let mut empty = Vec::new();
        copy_encrypt(&mut &b""[..], &mut empty, &salt, &mut key.cipher(&salt))
            .await
            .unwrap();
        assert!(empty.is_empty());
    }
}
