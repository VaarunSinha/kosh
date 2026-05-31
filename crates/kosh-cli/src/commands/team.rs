use super::sync::{resolve_env, resolve_workspace};
use super::Context;
use crate::client::ServerClient;
use anyhow::{anyhow, Context as _};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kosh_core::crypto::{self, SecretBytes};
use kosh_core::keychain::Keychain;
use uuid::Uuid;

#[derive(clap::Args)]
pub struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand)]
enum Cmd {
    /// List members of the current workspace
    List,
    /// Invite a user to the current workspace
    Invite {
        /// The invitee's user UUID
        user_id: Uuid,
        /// Role: owner | admin | developer | readonly | ci
        #[arg(long, default_value = "developer")]
        role: String,
    },
    /// Grant a member the current environment's key so they can decrypt secrets
    GrantEnv {
        /// The member's user UUID
        user_id: Uuid,
    },
}

/// `kosh team …` — workspace membership and env-key sharing.
pub async fn run(ctx: &Context, args: Args) -> anyhow::Result<()> {
    let kc = Keychain::new();
    let client = ServerClient::from_config(&kc)?;
    let ws_id = resolve_workspace(&client, &ctx.workspace).await?;

    match args.cmd {
        Cmd::List => list(ctx, &client, ws_id).await,
        Cmd::Invite { user_id, role } => invite(&client, ws_id, user_id, &role).await,
        Cmd::GrantEnv { user_id } => grant_env(ctx, &kc, &client, ws_id, user_id).await,
    }
}

async fn list(ctx: &Context, client: &ServerClient, ws: Uuid) -> anyhow::Result<()> {
    let members = client.list_members(ws).await?;
    if ctx.json {
        let arr: Vec<serde_json::Value> = members
            .iter()
            .map(|m| serde_json::json!({ "user_id": m.user_id, "role": m.role }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
    } else if members.is_empty() {
        println!("No members.");
    } else {
        for m in members {
            println!("{:<40} {}", m.user_id, m.role);
        }
    }
    Ok(())
}

async fn invite(client: &ServerClient, ws: Uuid, user_id: Uuid, role: &str) -> anyhow::Result<()> {
    let m = client.invite_member(ws, user_id, role).await?;
    println!("Invited {} as {}", m.user_id, m.role);
    Ok(())
}

/// Wrap our local env key to `member`'s published public key and upload it, so
/// the member can unwrap it on their next `kosh sync`. The env private key only
/// ever leaves this machine encrypted to the member — the server never sees it.
async fn grant_env(
    ctx: &Context,
    kc: &Keychain,
    client: &ServerClient,
    ws: Uuid,
    member: Uuid,
) -> anyhow::Result<()> {
    let (env_id, _created) = resolve_env(client, ws, &ctx.env).await?;

    let env_key_str = kc.get_env_key(&ctx.workspace, &ctx.env)?.ok_or_else(|| {
        anyhow!(
            "no local env key for {}/{} — run `kosh sync` first",
            ctx.workspace,
            ctx.env
        )
    })?;

    let pk = client
        .get_public_key(member)
        .await?
        .ok_or_else(|| anyhow!("member {member} has not published a public key yet"))?;
    let recipient_str = String::from_utf8(
        STANDARD
            .decode(pk.public_key.trim())
            .context("decoding member public key")?,
    )
    .context("member public key is not valid UTF-8")?;
    let recipient = crypto::recipient_from_string(&recipient_str)?;

    let wrapped =
        crypto::encrypt_for_recipient(&SecretBytes::new(env_key_str.into_bytes()), &recipient)?;
    client
        .put_env_key(ws, env_id, member, &STANDARD.encode(&wrapped))
        .await?;

    println!("Granted {member} access to {}/{}", ctx.workspace, ctx.env);
    Ok(())
}
