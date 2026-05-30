pub mod add;
pub mod delete;
pub mod edit;
pub mod init;
pub mod list;
pub mod login;
pub mod logout;
pub mod rotate;
pub mod run;
pub mod server;
pub mod status;
pub mod sync;

use anyhow::anyhow;
use kosh_core::config::Config;
use kosh_core::crypto;
use kosh_core::keychain::Keychain;
use std::path::PathBuf;

use age::x25519::{Identity, Recipient};

/// Resolved runtime context for a single CLI invocation: output mode plus the
/// effective workspace/env (flags override config, then sensible local defaults).
pub struct Context {
    pub json: bool,
    pub workspace: String,
    pub env: String,
}

impl Context {
    pub fn resolve(json: bool, workspace: Option<String>, env: Option<String>) -> Self {
        let cfg = Config::load().ok();
        let workspace = workspace
            .or_else(|| cfg.as_ref().and_then(|c| c.current_workspace.clone()))
            .unwrap_or_else(|| "local".to_string());
        let env = env
            .or_else(|| cfg.as_ref().and_then(|c| c.current_env.clone()))
            .unwrap_or_else(|| "dev".to_string());
        Self {
            json,
            workspace,
            env,
        }
    }
}

/// Default project secrets file.
pub fn env_path() -> PathBuf {
    PathBuf::from(".env")
}

/// The local user's age identity (private key) from the OS keychain.
/// Errors with a `kosh init` hint when no key is present.
pub fn user_identity(kc: &Keychain) -> anyhow::Result<Identity> {
    let s = kc
        .get_user_key()
        .map_err(|_| anyhow!("no Kosh user key found — run `kosh init` first"))?;
    Ok(crypto::identity_from_string(&s)?)
}

/// The age identity that secrets for `(ctx.workspace, ctx.env)` are encrypted
/// under. In **team mode** a per-env key exists locally (provisioned by
/// `kosh sync`) and is used; in **solo mode** none exists and we fall back to
/// the user's own identity. Solo behaviour is therefore byte-identical to
/// before per-env keys existed.
pub fn identity_for(ctx: &Context, kc: &Keychain) -> anyhow::Result<Identity> {
    match kc.get_env_key(&ctx.workspace, &ctx.env)? {
        Some(s) => Ok(crypto::identity_from_string(&s)?),
        None => user_identity(kc),
    }
}

/// The age recipient (public key) that secrets for `(ctx.workspace, ctx.env)`
/// are encrypted to: the env recipient in team mode, the user recipient in solo
/// mode. See [`identity_for`].
pub fn recipient_for(ctx: &Context, kc: &Keychain) -> anyhow::Result<Recipient> {
    Ok(identity_for(ctx, kc)?.to_public())
}
