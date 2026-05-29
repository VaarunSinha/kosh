use super::Context;
use anyhow::bail;

pub fn run(_ctx: &Context) -> anyhow::Result<()> {
    bail!("`kosh login` requires the Kosh server, which is not yet available in this build")
}
