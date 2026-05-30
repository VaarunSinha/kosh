use super::Context;
use crate::client::ServerClient;
use kosh_core::keychain::Keychain;

/// `kosh logout` — revoke the current token server-side and drop it locally.
pub async fn run(_ctx: &Context) -> anyhow::Result<()> {
    let kc = Keychain::new();

    // Best-effort server-side revocation; always clear the local token.
    if let Ok(client) = ServerClient::from_config(&kc) {
        let _ = client.logout().await;
    }
    let _ = kc.delete_server_token();

    println!("Logged out");
    Ok(())
}
