pub mod http;
pub mod socks5;
pub mod ss;

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

/// Accepts the next connection, with TCP_NODELAY set. Accept errors never end
/// the listener: a connection that died in the backlog is skipped, and anything
/// else (EMFILE when out of file descriptors) is retried with a backoff, so the
/// loop doesn't spin while descriptors are freed.
pub(crate) async fn accept(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    let mut delay = Duration::from_millis(5);
    loop {
        match listener.accept().await {
            Ok((s, peer)) => {
                let _ = s.set_nodelay(true);
                return (s, peer);
            }
            Err(e) if matches!(e.kind(), ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset) => {
                tracing::debug!("accept: {e}");
            }
            Err(e) => {
                tracing::warn!("accept: {e}; retrying in {delay:?}");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(1));
            }
        }
    }
}
