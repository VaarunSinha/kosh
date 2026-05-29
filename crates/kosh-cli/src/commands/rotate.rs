use super::{env_path, user_identity, user_recipient, Context};
use anyhow::anyhow;
use kosh_core::crypto::{self, SecretBytes};
use kosh_core::env_file::EnvFile;
use kosh_core::error::KoshError;
use kosh_core::keychain::Keychain;
use kosh_core::store::Store;

#[derive(clap::Args)]
pub struct Args {
    /// The key whose value to rotate
    key: String,
}

pub fn run(ctx: &Context, args: Args) -> anyhow::Result<()> {
    let env = EnvFile::load(&env_path())?;
    let ref_id = env
        .references()
        .get(&args.key)
        .cloned()
        .ok_or_else(|| anyhow!("no secret found for key `{}`", args.key))?;

    let kc = Keychain::new();
    let identity = user_identity(&kc)?;
    let value = rpassword::prompt_password(format!("New value for {}: ", args.key))?;

    // Reject a no-op rotation (KE-700).
    let current = Store::new(&kc).get_secret(&ref_id, &identity, &ctx.env)?;
    if current.as_bytes() == value.as_bytes() {
        return Err(KoshError::RotationSameValue.into());
    }

    let recipient = user_recipient(&kc)?;
    let blob = crypto::encrypt_for_recipient(&SecretBytes::new(value.into_bytes()), &recipient)?;
    kc.store_secret(&ref_id, &blob)?;
    println!("Rotated {} ({})", args.key, ref_id);
    Ok(())
}
