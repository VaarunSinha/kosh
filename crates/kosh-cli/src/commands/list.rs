use super::{env_path, Context};
use crate::output;
use kosh_core::env_file::EnvFile;
use kosh_core::store::Store;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Args {
    /// Path to the .env file (defaults to ./.env)
    #[arg(long)]
    file: Option<PathBuf>,
}

pub fn run(ctx: &Context, args: Args) -> anyhow::Result<()> {
    let path = args.file.unwrap_or_else(env_path);
    let env = EnvFile::load(&path)?;
    let refs = Store::list_refs(&env);
    output::list(ctx.json, &refs);
    Ok(())
}
