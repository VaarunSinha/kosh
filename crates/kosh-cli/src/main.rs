mod client;
mod commands;
mod output;

use clap::{Parser, Subcommand};
use commands::Context;

#[derive(Parser)]
#[command(
    name = "kosh",
    about = "AI-safe secret guard for developers",
    version,
    author
)]
struct Cli {
    /// Output in JSON format
    #[arg(long, global = true)]
    json: bool,

    /// Workspace to use (overrides config)
    #[arg(long, short = 'w', global = true)]
    workspace: Option<String>,

    /// Environment (dev/staging/production)
    #[arg(long, short = 'e', global = true)]
    env: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all secrets in current env
    List(commands::list::Args),
    /// Add a secret (interactive or from file)
    Add(commands::add::Args),
    /// Run a command with secrets injected
    Run(commands::run::Args),
    /// Edit an existing secret
    Edit(commands::edit::Args),
    /// Delete a secret
    Delete(commands::delete::Args),
    /// Rotate a secret value
    Rotate(commands::rotate::Args),
    /// Sync secrets with server
    Sync(commands::sync::Args),
    /// Manage local Kosh server
    Server(commands::server::Args),
    /// Login to Kosh server
    Login(commands::login::Args),
    /// Log out of the Kosh server
    Logout,
    /// Show current status
    Status,
    /// Initialize Kosh in current directory
    Init,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let ctx = Context::resolve(cli.json, cli.workspace, cli.env);

    let result = match cli.command {
        Commands::List(a) => commands::list::run(&ctx, a),
        Commands::Add(a) => commands::add::run(&ctx, a),
        Commands::Run(a) => commands::run::run(&ctx, a).await,
        Commands::Edit(a) => commands::edit::run(&ctx, a),
        Commands::Delete(a) => commands::delete::run(&ctx, a),
        Commands::Rotate(a) => commands::rotate::run(&ctx, a),
        Commands::Sync(a) => commands::sync::run(&ctx, a).await,
        Commands::Server(a) => commands::server::run(&ctx, a),
        Commands::Login(a) => commands::login::run(&ctx, a).await,
        Commands::Logout => commands::logout::run(&ctx).await,
        Commands::Status => commands::status::run(&ctx),
        Commands::Init => commands::init::run(&ctx),
    };

    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
