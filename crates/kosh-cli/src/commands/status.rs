use super::Context;
use crate::output;
use kosh_core::keychain::Keychain;

pub fn run(ctx: &Context) -> anyhow::Result<()> {
    let kc = Keychain::new();
    let key_present = kc.get_user_key().is_ok();
    output::status(ctx.json, &ctx.workspace, &ctx.env, key_present);
    Ok(())
}
