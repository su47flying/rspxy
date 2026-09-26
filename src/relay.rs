use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

const BUF: usize = 64 << 10;

/// Copies both directions until both are done, propagating half-close.
pub async fn relay<A, B>(mut a: A, mut b: B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional_with_sizes(&mut a, &mut b, BUF, BUF).await
}
