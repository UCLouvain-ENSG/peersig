use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;

/// PeerSig Oblivious HTTP relay: forwards participants' encrypted requests
/// to the collection server without their address. Run it on a machine the
/// server's operator does not control.
#[derive(Parser)]
#[command(name = "peersig-relay", version)]
struct Cli {
    /// Address to listen on (put TLS in front, e.g. Caddy, with access logs off).
    #[arg(long, env = "PEERSIG_RELAY_LISTEN", default_value = "127.0.0.1:8081")]
    listen: String,
    /// The collection server's base URL.
    #[arg(long, env = "PEERSIG_GATEWAY")]
    gateway: String,
    /// Requests per minute and client address.
    #[arg(long, env = "PEERSIG_RELAY_RATE", default_value_t = 600)]
    per_minute: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();
    let relay = peersig_relay::Relay::new(&cli.gateway, cli.per_minute)?;
    let l = tokio::net::TcpListener::bind(&cli.listen).await.with_context(|| cli.listen.clone())?;
    tracing::info!("relaying {} -> {}", cli.listen, cli.gateway);
    axum::serve(l, peersig_relay::router(relay).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
