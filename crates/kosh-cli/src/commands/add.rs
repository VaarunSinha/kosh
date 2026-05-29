use super::{env_path, user_recipient, Context};
use anyhow::bail;
use kosh_core::env_file::EnvFile;
use kosh_core::keychain::Keychain;
use kosh_core::reference::RefId;
use kosh_core::store::Store;
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct Args {
    /// Add a single secret by key name (prompts for the value)
    #[arg(long)]
    key: Option<String>,

    /// Import all plain values from a .env file
    #[arg(long)]
    file: Option<PathBuf>,

    /// Show what would change without writing anything
    #[arg(long = "dry-run")]
    dry_run: bool,
}

pub fn run(_ctx: &Context, args: Args) -> anyhow::Result<()> {
    match (args.file, args.key) {
        (Some(file), _) => add_from_file(&file, args.dry_run),
        (None, Some(key)) => add_single(&key, args.dry_run),
        (None, None) => bail!("specify --file <path> to import or --key <NAME> to add one secret"),
    }
}

fn add_from_file(file: &Path, dry_run: bool) -> anyhow::Result<()> {
    let mut env = EnvFile::load(file)?;
    let plain: Vec<(String, String)> = env.plain_secrets().into_iter().collect();

    if plain.is_empty() {
        println!("No plain secrets to add — every value is already a KOSH: reference.");
        return Ok(());
    }

    if dry_run {
        for (k, _v) in &plain {
            // A representative reference; nothing is encrypted or written.
            println!("{} -> {}", k, RefId::generate());
        }
        return Ok(());
    }

    let kc = Keychain::new();
    let recipient = user_recipient(&kc)?;
    let store = Store::new(&kc);
    for (k, v) in plain {
        let ref_id = store.add_secret(&mut env, &k, v.as_bytes(), &recipient)?;
        println!("{} -> {}", k, ref_id);
    }
    Ok(())
}

fn add_single(key: &str, dry_run: bool) -> anyhow::Result<()> {
    if dry_run {
        println!("{} -> {}", key, RefId::generate());
        return Ok(());
    }

    let kc = Keychain::new();
    let recipient = user_recipient(&kc)?;
    let value = rpassword::prompt_password(format!("Enter value for {key}: "))?;

    let path = env_path();
    if !path.exists() {
        std::fs::write(&path, "")?;
    }
    let mut env = EnvFile::load(&path)?;
    // Ensure the key exists so the ref rewrite has a line to replace.
    env.set_var(key, "");

    let store = Store::new(&kc);
    let ref_id = store.add_secret(&mut env, key, value.as_bytes(), &recipient)?;
    println!("{} -> {}", key, ref_id);
    Ok(())
}
