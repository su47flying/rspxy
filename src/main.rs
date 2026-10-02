use anyhow::{Context, bail};
use clap::{ArgAction, Parser};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use rspxy::dialer::Dialer;
use rspxy::node::Node;
use rspxy::proxy::{http, socks5, ss};
use rspxy::tunnel::{self, client::TunnelClient};

/// socks5/http/shadowsocks proxy tunnelled over SSU-obfuscated QUIC on UDP.
///
/// Server: rspxy -L=ssu://:5023?keys=keys.txt
/// Client: rspxy -L=socks5://:1080 -L=http://:8080 -F=ssu://7:secret@host:5023
/// Shadowsocks: rspxy -L=ss://chacha20-ietf-poly1305:password@:8388
#[derive(Parser)]
#[command(name = "rspxy", version, verbatim_doc_comment)]
struct Cli {
    /// Listen node (repeatable): socks5://[user:pass@][ip]:port, http://[user:pass@][ip]:port,
    /// ss://METHOD:PASSWORD@[ip]:port[?mode=tcp_and_udp|tcp_only|udp_only],
    /// ssu://[id:secret@][ip]:port[?keys=FILE&key=ID:SECRET&cc=bbr&mtu=1200]
    #[arg(short = 'L', value_name = "NODE", action = ArgAction::Append, required = true)]
    listen: Vec<String>,

    /// Forward node: ssu://ID:SECRET@host:port[?cc=bbr|bbr1|cubic|newreno&mtu=1200..1439&pad=MIN-MAX&timeout=10s].
    /// Without it, -L proxies connect directly.
    #[arg(short = 'F', value_name = "NODE")]
    forward: Option<String>,

    /// Debug logging
    #[arg(short = 'D')]
    debug: bool,
}

fn is_ssu(scheme: &str) -> bool {
    matches!(scheme, "ssu" | "sockssimple")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| if cli.debug { "rspxy=debug,info" } else { "info" }.into());
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let dialer = match &cli.forward {
        None => Dialer::Direct,
        Some(f) => {
            let node = Node::parse(f)?;
            if !is_ssu(&node.scheme) {
                bail!("unsupported -F scheme {:?} (expected ssu://)", node.scheme);
            }
            tracing::info!("forward via ssu://{}", node.host_port()?);
            Dialer::Tunnel(TunnelClient::from_node(&node)?)
        }
    };

    let mut tasks = JoinSet::new();
    for l in &cli.listen {
        let node = Node::parse(l)?;
        match node.scheme.as_str() {
            "socks5" | "socks" | "http" => {
                let addr = node.bind_addr()?;
                let listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("listen {addr}"))?;
                tracing::info!("{} proxy on tcp {addr}", node.scheme);
                let (auth, dialer) = (node.auth(), dialer.clone());
                if node.scheme == "http" {
                    tasks.spawn(http::serve(listener, auth, dialer));
                } else {
                    tasks.spawn(socks5::serve(listener, auth, dialer));
                }
            }
            "ss" => {
                tasks.spawn(ss::serve(node, dialer.clone()));
            }
            s if is_ssu(s) => {
                // With -F, this server relays through the forward tunnel.
                tasks.spawn(tunnel::server::serve(node, dialer.clone()));
            }
            s => bail!("unsupported -L scheme {s:?}"),
        }
    }

    tokio::select! {
        Some(res) = tasks.join_next() => res?,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}
