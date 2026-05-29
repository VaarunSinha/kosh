use super::{env_path, user_recipient, Context};
use anyhow::anyhow;
use kosh_core::crypto::{self, SecretBytes};
use kosh_core::env_file::EnvFile;
use kosh_core::keychain::Keychain;

#[derive(clap::Args)]
pub struct Args {
    /// The key whose value to replace
    key: String,
}

pub fn run(_ctx: &Context, args: Args) -> anyhow::Result<()> {
    let env = EnvFile::load(&env_path())?;
    let ref_id = env
        .references()
        .get(&args.key)
        .cloned()
        .ok_or_else(|| anyhow!("no secret found for key `{}`", args.key))?;

    let kc = Keychain::new();
    let recipient = user_recipient(&kc)?;
    let value = rpassword::prompt_password(format!("New value for {}: ", args.key))?;

    let blob = crypto::encrypt_for_recipient(&SecretBytes::new(value.into_bytes()), &recipient)?;
    kc.store_secret(&ref_id, &blob)?;
    println!("Updated {} ({})", args.key, ref_id);
    Ok(())
}
