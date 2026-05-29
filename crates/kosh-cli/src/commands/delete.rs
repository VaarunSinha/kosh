use super::{env_path, Context};
use anyhow::anyhow;
use kosh_core::env_file::EnvFile;
use kosh_core::keychain::Keychain;
use kosh_core::store::Store;

#[derive(clap::Args)]
pub struct Args {
    /// The key to delete
    key: String,
}

pub fn run(ctx: &Context, args: Args) -> anyhow::Result<()> {
    let mut env = EnvFile::load(&env_path())?;
    let ref_id = env
        .references()
        .get(&args.key)
        .cloned()
        .ok_or_else(|| anyhow!("no secret found for key `{}`", args.key))?;

    let kc = Keychain::new();
    Store::new(&kc).delete_secret(&ref_id, &ctx.env)?;
    env.remove_var(&args.key);
    env.save()?;
    println!("Deleted {} ({})", args.key, ref_id);
    Ok(())
}
