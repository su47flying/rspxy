//! UDP association transport shared by both tunnel ends: QUIC datagrams, with
//! the association stream as fallback for datagrams that don't fit.

use std::io;

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendDatagramError, SendStream};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use crate::proto::{Address, encode_datagram};

pub async fn send(
    conn: &Connection,
    stream: &Mutex<SendStream>,
    id: u32,
    addr: &Address,
    data: &[u8],
) -> io::Result<()> {
    let d = Bytes::from(encode_datagram(id, addr, data));
    if conn.max_datagram_size().is_some_and(|max| d.len() <= max) {
        match conn.send_datagram(d) {
            Ok(()) => return Ok(()),
            Err(SendDatagramError::TooLarge) => {}
            Err(e) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, e)),
        }
    }
    // Oversized: `len u16 | ATYP ADDR PORT | data` on the association stream.
    let mut f = vec![0u8; 2];
    addr.encode(&mut f);
    f.extend_from_slice(data);
    let Ok(len) = u16::try_from(f.len() - 2) else {
        return Ok(()); // can't happen for real UDP payloads; drop like the network would
    };
    f[..2].copy_from_slice(&len.to_be_bytes());
    stream.lock().await.write_all(&f).await.map_err(io::Error::from)
}

/// Reads one stream-carried datagram into `buf`; returns `None` on clean EOF.
pub async fn read_frame(r: &mut RecvStream, buf: &mut Vec<u8>) -> io::Result<Option<(Address, usize)>> {
    let len = match r.read_u16().await {
        Ok(l) => usize::from(l),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    buf.resize(len, 0);
    AsyncReadExt::read_exact(r, buf).await?;
    let (addr, off) =
        Address::decode(buf).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad udp frame"))?;
    Ok(Some((addr, off)))
}
