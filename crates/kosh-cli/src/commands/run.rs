use super::{env_path, identity_for, Context};
use anyhow::{anyhow, bail};
use kosh_core::env_file::EnvFile;
use kosh_core::error::KoshError;
use kosh_core::keychain::Keychain;
use kosh_core::store::Store;
use kosh_redactor::Redactor;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(clap::Args)]
pub struct Args {
    /// The command (and its arguments) to run, after `--`
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,

    /// Allow shells and env-dump commands (e.g. bash, env, printenv).
    /// Must be run via sudo. Output is still redacted unless --no-redact
    /// is also passed.
    #[arg(long = "dangerously-allow-blocked")]
    dangerously_allow_blocked: bool,

    /// Disable real-time output redaction.
    /// Secret values will appear in stdout/stderr as-is.
    /// Must be run via sudo.
    #[arg(long = "dangerously-turn-off-redact")]
    dangerously_turn_off_redact: bool,
}

pub async fn run(ctx: &Context, args: Args) -> anyhow::Result<()> {
    if args.command.is_empty() {
        bail!("usage: kosh run -- <command> [args...]");
    }
    let cmd_str = args.command.join(" ");

    // Security gate: block shells and env-dump commands unless the caller
    // explicitly opted out *and* is running as root (sudo).
    if kosh_redactor::is_blocked(&cmd_str) {
        if args.dangerously_allow_blocked {
            require_sudo()?;
        } else {
            return Err(KoshError::BlockedCommand { cmd: cmd_str }.into());
        }
    }

    // Resolve and decrypt the secrets referenced by the project .env.
    let mut env_vars: Vec<(String, String)> = Vec::new();
    let mut secrets: Vec<(String, String)> = Vec::new();
    let path = env_path();
    if path.exists() {
        let envf = EnvFile::load(&path)?;
        let refs = envf.references();
        if !refs.is_empty() {
            let kc = Keychain::new();
            let identity = identity_for(ctx, &kc)?;
            let store = Store::new(&kc);
            for (key, ref_id) in refs {
                let pt = store.get_secret(&ref_id, &identity, &ctx.env)?;
                let value = String::from_utf8_lossy(pt.as_bytes()).to_string();
                secrets.push((value.clone(), ref_id.as_str().to_string()));
                env_vars.push((key, value));
            }
        }
    }

    if args.dangerously_turn_off_redact {
        require_sudo()?;
    }

    let redactor = if args.dangerously_turn_off_redact {
        None
    } else {
        Some(Arc::new(
            Redactor::new(&secrets).map_err(|_| KoshError::RedactorInitFailed)?,
        ))
    };

    let mut command = tokio::process::Command::new(&args.command[0]);
    command
        .args(&args.command[1..])
        .envs(env_vars)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|_| KoshError::SubprocessSpawnFailed { cmd: cmd_str })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("failed to capture stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("failed to capture stderr"))?;

    let out_task = {
        let red = redactor.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                match &red {
                    Some(r) => println!("{}", r.redact_line(&line)),
                    None => println!("{line}"),
                }
            }
        })
    };
    let err_task = {
        let red = redactor.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                match &red {
                    Some(r) => eprintln!("{}", r.redact_line(&line)),
                    None => eprintln!("{line}"),
                }
            }
        })
    };

    let status = child.wait().await?;
    let _ = out_task.await;
    let _ = err_task.await;

    std::process::exit(status.code().unwrap_or(1));
}

/// Soft friction check intended to make dangerous flag use feel deliberate.
///
/// Checks for `SUDO_UID`, which is set by sudo on macOS/Linux. This is NOT a
/// hard security boundary — any user can bypass it by setting the env var
/// manually (`SUDO_UID=1 kosh run --dangerously-allow-blocked -- bash`).
/// The real protection is output redaction; the blocked list and this check
/// exist only as a speed-bump that forces a conscious decision.
fn require_sudo() -> anyhow::Result<()> {
    if std::env::var("SUDO_UID").is_ok() {
        return Ok(());
    }
    anyhow::bail!(
        "pass this flag via sudo as a deliberate acknowledgement that you are \
         bypassing safety protections (output redaction remains active unless \
         --dangerously-turn-off-redact is also passed):\n  \
         sudo kosh run <dangerous-flags> -- <command>\n\n\
         Note: this is a soft check, not a hard security boundary."
    )
}
