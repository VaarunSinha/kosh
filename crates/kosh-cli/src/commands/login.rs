use super::Context;
use crate::client::ServerClient;
use anyhow::{anyhow, Context as _};
use kosh_core::config::Config;
use kosh_core::keychain::Keychain;

#[derive(clap::Args)]
pub struct Args {
    /// Base URL of the Kosh server, e.g. https://kosh.example.com
    #[arg(long)]
    server: String,

    /// Access token (JWT). If omitted, you'll be prompted for it.
    #[arg(long)]
    token: Option<String>,
}

/// `kosh login --server <url> [--token <jwt>]`.
///
/// Tokens are minted out-of-band (the server has no password login). We verify
/// the supplied token by calling `POST /auth/refresh`, then persist the refreshed
/// token in the OS keychain and the server URL in the config.
pub async fn run(_ctx: &Context, args: Args) -> anyhow::Result<()> {
    let server = args.server.trim_end_matches('/').to_string();
    if server.is_empty() {
        return Err(anyhow!("--server must not be empty"));
    }

    let token = match args.token {
        Some(t) => t,
        None => rpassword::prompt_password("Enter Kosh access token: ")
            .context("failed to read token")?,
    };
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(anyhow!("token must not be empty"));
    }

    // Verify the token and obtain a fresh one bound to a new jti.
    let client = ServerClient::new(&server, &token);
    let fresh = client
        .refresh()
        .await
        .context("login failed — the server rejected the token")?;

    let kc = Keychain::new();
    kc.store_server_token(&fresh)?;

    let mut cfg = Config::load().unwrap_or_default();
    cfg.server_url = Some(server.clone());
    cfg.save()?;

    println!("Logged in to {server}");
    Ok(())
}
