use super::{env_path, user_identity, Context};
use crate::client::ServerClient;
use crate::output;
use age::x25519::Identity;
use anyhow::{anyhow, Context as _};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kosh_core::crypto::{self, SecretBytes};
use kosh_core::env_file::EnvFile;
use kosh_core::keychain::Keychain;
use kosh_core::reference::RefId;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(clap::Args)]
pub struct Args {
    /// Only upload local secrets to the server
    #[arg(long)]
    push: bool,
    /// Only download server secrets into the local keychain
    #[arg(long)]
    pull: bool,
}

/// `kosh sync` — reconcile local secrets with the team server.
///
/// The server is the source of truth: in the default (no-flag) mode we pull
/// first (adopting server values for shared refs) and then push local-only
/// refs. The CLI only ever moves ciphertext and wrapped keys across the wire;
/// nothing is decrypted server-side.
pub async fn run(ctx: &Context, args: Args) -> anyhow::Result<()> {
    let kc = Keychain::new();
    let client = ServerClient::from_config(&kc)?;
    let me = client.user_id()?;

    // Resolve the human-facing workspace/env names to server UUIDs, creating
    // them when absent (the caller becomes the owner of a new workspace).
    let ws_id = resolve_workspace(&client, &ctx.workspace).await?;
    let env_id = resolve_env(&client, ws_id, &ctx.env).await?;

    // Publish our public key so teammates can wrap the env key to us (M5). PUT
    // is idempotent; the value is the age recipient string, base64 for transport.
    let user_id = user_identity(&kc)?;
    let pubkey_b64 = STANDARD.encode(crypto::recipient_to_string(&user_id.to_public()).as_bytes());
    client.put_public_key(&pubkey_b64).await?;

    // Make sure we hold this env's key locally: unwrap it from the server if a
    // teammate granted it, otherwise generate it (we are creating the env).
    ensure_env_key(ctx, &kc, &client, ws_id, env_id, me, &user_id).await?;

    let (do_push, do_pull) = match (args.push, args.pull) {
        (false, false) => (true, true),
        (p, q) => (p, q),
    };

    let mut pulled = 0;
    let mut pushed = 0;
    if do_pull {
        pulled = pull(ctx, &kc, &client, ws_id, env_id).await?;
    }
    if do_push {
        pushed = push(ctx, &kc, &client, ws_id, env_id).await?;
    }

    output::sync_result(ctx.json, pushed, pulled);
    Ok(())
}

/// Find the workspace by name, creating it if the caller has none by that name.
async fn resolve_workspace(client: &ServerClient, name: &str) -> anyhow::Result<Uuid> {
    if let Some(w) = client
        .list_workspaces()
        .await?
        .into_iter()
        .find(|w| w.name == name)
    {
        return Ok(w.id);
    }
    Ok(client.create_workspace(name).await?.id)
}

/// Find the environment by name within a workspace, creating it if absent.
async fn resolve_env(client: &ServerClient, ws: Uuid, name: &str) -> anyhow::Result<Uuid> {
    if let Some(e) = client
        .list_envs(ws)
        .await?
        .into_iter()
        .find(|e| e.name == name)
    {
        return Ok(e.id);
    }
    Ok(client.create_env(ws, name).await?.id)
}

/// Guarantee a local env key for `(ctx.workspace, ctx.env)`.
///
/// - If one is already stored locally, do nothing.
/// - Else, if the server holds an env key wrapped to us, unwrap it with our user
///   identity and store it.
/// - Else we are the env's creator: generate a fresh env keypair, migrate any
///   pre-existing solo (user-key) secrets to it, store it, and upload it wrapped
///   to our own public key.
async fn ensure_env_key(
    ctx: &Context,
    kc: &Keychain,
    client: &ServerClient,
    ws: Uuid,
    env: Uuid,
    me: Uuid,
    user_id: &Identity,
) -> anyhow::Result<()> {
    if kc.get_env_key(&ctx.workspace, &ctx.env)?.is_some() {
        return Ok(());
    }

    if let Some(dto) = client.get_env_key(ws, env, me).await? {
        let wrapped = STANDARD
            .decode(dto.encrypted_env_key.trim())
            .context("decoding wrapped env key")?;
        let plain = crypto::decrypt_with_identity(&wrapped, user_id, "env-key")?;
        let env_key_str =
            String::from_utf8(plain.as_bytes().to_vec()).context("env key is not valid UTF-8")?;
        // Validate before trusting it.
        crypto::identity_from_string(&env_key_str)?;
        kc.store_env_key(&ctx.workspace, &ctx.env, &env_key_str)?;
        return Ok(());
    }

    // Creating the env: mint its key.
    let (env_identity, _env_recipient) = crypto::generate_keypair();
    let env_key_str = crypto::identity_to_string(&env_identity);
    migrate_secrets_to_env(ctx, kc, user_id, &env_identity)?;
    kc.store_env_key(&ctx.workspace, &ctx.env, &env_key_str)?;

    // Wrap the env private key to our own public key and publish it.
    let wrapped = crypto::encrypt_for_recipient(
        &SecretBytes::new(env_key_str.into_bytes()),
        &user_id.to_public(),
    )?;
    client
        .put_env_key(ws, env, me, &STANDARD.encode(&wrapped))
        .await?;
    Ok(())
}

/// Re-encrypt any local secrets that currently decrypt under the user key so
/// they are readable by env-key holders. Secrets that don't decrypt under the
/// user key (already env-encrypted, or belonging to someone else) are left
/// untouched. Best-effort: a missing local blob is simply skipped.
fn migrate_secrets_to_env(
    ctx: &Context,
    kc: &Keychain,
    user_id: &Identity,
    env_identity: &Identity,
) -> anyhow::Result<()> {
    let path = env_path();
    if !path.exists() {
        return Ok(());
    }
    let envf = EnvFile::load(&path)?;
    let env_recipient = env_identity.to_public();
    for (_key, ref_id) in envf.references() {
        let Some(blob) = local_blob(kc, &ref_id, &ctx.env) else {
            continue;
        };
        if let Ok(plain) = crypto::decrypt_with_identity(&blob, user_id, ref_id.as_str()) {
            let reencrypted = crypto::encrypt_for_recipient(&plain, &env_recipient)?;
            kc.store_secret(&ref_id, &reencrypted)?;
        }
    }
    Ok(())
}

/// Upload local-only secrets; update those already present on the server.
async fn push(
    ctx: &Context,
    kc: &Keychain,
    client: &ServerClient,
    ws: Uuid,
    env: Uuid,
) -> anyhow::Result<usize> {
    let path = env_path();
    if !path.exists() {
        return Ok(0);
    }
    let envf = EnvFile::load(&path)?;
    let server_refs: HashSet<String> = client
        .list_secrets(ws, env)
        .await?
        .into_iter()
        .map(|m| m.ref_id)
        .collect();

    let mut pushed = 0;
    for (key, ref_id) in envf.references() {
        let Some(blob) = local_blob(kc, &ref_id, &ctx.env) else {
            continue;
        };
        let b64 = STANDARD.encode(&blob);
        if server_refs.contains(ref_id.as_str()) {
            client.update_secret(ws, env, ref_id.as_str(), &b64).await?;
        } else if !client
            .upload_secret(ws, env, ref_id.as_str(), &key, &b64)
            .await?
        {
            // Lost a race / stale listing: it already exists, so update instead.
            client.update_secret(ws, env, ref_id.as_str(), &b64).await?;
        }
        pushed += 1;
    }
    Ok(pushed)
}

/// Download every server secret into the local keychain and ensure the local
/// .env references it. Server values win on divergence.
async fn pull(
    _ctx: &Context,
    kc: &Keychain,
    client: &ServerClient,
    ws: Uuid,
    env: Uuid,
) -> anyhow::Result<usize> {
    let metas = client.list_secrets(ws, env).await?;
    if metas.is_empty() {
        return Ok(0);
    }

    let path = env_path();
    if !path.exists() {
        std::fs::write(&path, "")?;
    }
    let mut envf = EnvFile::load(&path)?;

    let mut pulled = 0;
    for meta in metas {
        let dto = client.get_secret(ws, env, &meta.ref_id).await?;
        let bytes = STANDARD
            .decode(dto.encrypted_blob.trim())
            .context("decoding secret blob")?;
        let ref_id = RefId::parse(&dto.ref_id)
            .ok_or_else(|| anyhow!("server returned invalid ref_id: {}", dto.ref_id))?;
        kc.store_secret(&ref_id, &bytes)?;
        envf.set_var(&dto.key_name, ref_id.as_str());
        pulled += 1;
    }
    envf.save()?;
    Ok(pulled)
}

/// The locally-stored ciphertext for a ref, or `None` if it isn't present.
fn local_blob(kc: &Keychain, ref_id: &RefId, env: &str) -> Option<Vec<u8>> {
    kc.get_secret(ref_id, env).ok()
}
