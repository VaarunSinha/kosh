use super::Context;
use kosh_core::config::Config;
use kosh_core::crypto;
use kosh_core::keychain::Keychain;

pub fn run(_ctx: &Context) -> anyhow::Result<()> {
    let kc = Keychain::new();
    if kc.get_user_key().is_ok() {
        println!("Kosh user key already present in the keychain.");
    } else {
        let (identity, _recipient) = crypto::generate_keypair();
        kc.store_user_key(&crypto::identity_to_string(&identity))?;
        println!("Generated a new Kosh user key and stored it in the OS keychain.");
    }

    let mut cfg = Config::load().unwrap_or_default();
    if cfg.current_workspace.is_none() {
        cfg.current_workspace = Some("local".to_string());
    }
    if cfg.current_env.is_none() {
        cfg.current_env = Some("dev".to_string());
    }
    cfg.save()?;

    println!("Initialized Kosh ({})", Config::config_path()?.display());
    Ok(())
}
