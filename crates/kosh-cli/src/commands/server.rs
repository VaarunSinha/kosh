use super::Context;
use anyhow::bail;

#[derive(clap::Args)]
pub struct Args {}

pub fn run(_ctx: &Context, _args: Args) -> anyhow::Result<()> {
    bail!("`kosh server` requires the Kosh server, which is not yet available in this build")
}
