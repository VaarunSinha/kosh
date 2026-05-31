# kosh

**AI-safe secret guard for developers.**

Kosh encrypts your `.env` secrets locally and — optionally — syncs them to a team server. When you run a command through `kosh run`, secrets are injected as environment variables and any accidental leaks are redacted from stdout/stderr in real time. Shell spawning and variable-dump commands are blocked entirely, so a compromised prompt or script can never exfiltrate secrets.

---

## Why kosh?

AI coding assistants read your terminal output. That's useful until the output contains `API_KEY=sk-…`. Kosh sits between your process and the terminal: it decrypts secrets into the child process's environment but intercepts every output line and scrubs values before they reach your screen — or your context window.

- **Local-first.** Secrets never leave your machine in plaintext. The server only ever receives ciphertext and public keys.
- **Age-native encryption.** Each secret is encrypted with [age](https://age-encryption.org/) (X25519). No passphrases, no symmetric master keys sitting in config files.
- **AI-safe redaction.** Every output line is scanned against known plaintexts before printing. Shells, `env`, `printenv`, and `echo $VAR` are blocked entirely.
- **Zero-knowledge team sync.** In team mode, secrets are encrypted to a per-environment key. That key is wrapped (re-encrypted) to each member's public key and stored on the server — the server never sees the plaintext key or any secret value.

---

## How it works

```
.env (before kosh add)        .env (after kosh add)
─────────────────────         ──────────────────────
API_KEY=sk-abc123      →      API_KEY=KOSH:a3f9c2b1
DB_PASS=hunter2        →      DB_PASS=KOSH:deadbeef
```

`KOSH:` references are safe to commit. The ciphertext lives in the OS keychain (or a file-backed keychain in CI). Running `kosh run -- your-server` decrypts on the fly, never touching disk.

### Key hierarchy (team mode)

```
User key  (X25519, per person)
  └─ used only to unwrap the env key

Env key   (X25519, per workspace/environment)
  └─ secrets are encrypted to the env public key
  └─ the env private key is age-encrypted to each
     member's user public key and stored on the server

Secret blob = age.encrypt(env_public_key, plaintext)
```

The server stores `{ ciphertext, encrypted_env_key, user_public_key }`. It never holds a plaintext key or secret value.

---

## Installation

**From source** (requires Rust ≥ 1.75):

```sh
git clone https://github.com/yourusername/kosh
cd kosh
cargo install --path crates/kosh-cli
```

---

## Quick start

### Solo mode (no server)

```sh
# Generate your user key and initialise the project config.
kosh init

# Encrypt all plain values in .env in place.
kosh add --file .env

# Run your dev server with secrets injected.
kosh run -- npm run dev

# Add a single secret interactively.
kosh add --key DATABASE_URL

# List what's managed.
kosh list

# Edit or rotate a value.
kosh edit --key API_KEY
kosh rotate --key API_KEY
```

### Team mode (with a server)

```sh
# ── On every team member's machine ─────────────────────────────────────────

# Log in with a token minted by your Kosh server admin.
kosh login --server https://kosh.example.com --token <jwt>

# Push local secrets to the server (creates the workspace + env on first run).
kosh -w acme -e dev sync --push

# Pull the team's secrets to a new machine.
kosh -w acme -e dev sync --pull

# Default sync reconciles both directions (server wins on conflict).
kosh -w acme -e dev sync


# ── Workspace owner / admin ────────────────────────────────────────────────

# Invite a teammate.
kosh -w acme team invite <user-uuid> --role developer

# Grant them the env decryption key so they can read secrets.
kosh -w acme -e dev team grant-env <user-uuid>

# List members.
kosh -w acme team list

# Log out and revoke the local token.
kosh logout
```

After `grant-env`, the teammate runs `kosh sync` and the env key is unwrapped locally — the server never sees the plaintext key.

---

## Commands

| Command | Description |
|---|---|
| `kosh init` | Generate user key, write default config |
| `kosh add --file <path>` | Encrypt all plain values in a `.env` file |
| `kosh add --key <NAME>` | Encrypt a single secret (prompts for value) |
| `kosh list` | List managed secrets in the current env |
| `kosh run -- <cmd>` | Run a command with secrets injected + redacted |
| `kosh edit --key <NAME>` | Replace a secret's value |
| `kosh rotate --key <NAME>` | Rotate a secret (new value, new ref) |
| `kosh delete <NAME>` | Remove a secret |
| `kosh status` | Show current workspace, env, and key status |
| `kosh sync [--push\|--pull]` | Reconcile local secrets with the team server |
| `kosh team invite <uuid>` | Add a member to the workspace |
| `kosh team grant-env <uuid>` | Share the env key with a member |
| `kosh team list` | List workspace members and roles |
| `kosh login --server <url>` | Authenticate with a Kosh server |
| `kosh logout` | Revoke the local session token |

Global flags: `--workspace / -w`, `--env / -e`, `--json`.

### Roles

| Role | Read secrets | Write secrets | Manage members |
|---|---|---|---|
| `owner` | ✓ | ✓ | ✓ |
| `admin` | ✓ | ✓ | ✓ |
| `developer` | ✓ | ✓ | — |
| `readonly` | ✓ | — | — |
| `ci` | ✓ | — | — |

---

## Security model

### What is blocked

`kosh run` refuses to launch shells (`bash`, `sh`, `zsh`, `fish`, `dash`, `ksh`, `tcsh`, `csh`) or env-dump utilities (`env`, `printenv`, `export`, `set`). Patterns like `echo $VAR` and `echo ${VAR}` are also blocked. This prevents prompt injection or a malicious script from exfiltrating secrets by spawning a sub-shell.

If you genuinely need to run a shell (e.g. a `bash` build script you own and trust), you can bypass the block — but only via sudo, as a forcing function for conscious intent. Output is still redacted unless you additionally pass `--dangerously-turn-off-redact`:

```sh
# Run a shell script — blocked commands allowed, output still redacted.
sudo kosh run --dangerously-allow-blocked -- bash build.sh

# Allow blocked commands AND turn off redaction.
sudo kosh run --dangerously-allow-blocked --dangerously-turn-off-redact -- bash build.sh
```

### What is redacted

For allowed commands, every line written to stdout or stderr is scanned against all known plaintext values before it reaches your terminal. Matches are replaced with `[REDACTED]`.

To disable redaction, pass `--dangerously-turn-off-redact` — also requires sudo:

```sh
sudo kosh run --dangerously-turn-off-redact -- npm run dev
```

### What the server never sees

- Plaintext secret values — only age ciphertext.
- Plaintext env keys — only each member's wrapped (re-encrypted) copy.
- Plaintext user private keys — only X25519 public keys.

### Threat model

Kosh protects against:
- Secrets leaking into AI assistant context windows via terminal output.
- Accidental `git add .env` (references are safe to commit; ciphertext stays local).
- A compromised server — the server holds only encrypted blobs and public keys.
- Rogue scripts dumping the environment.

Kosh does **not** protect against:
- A compromised OS keychain (if an attacker has keychain access they have the user key).
- A compromised process that reads its own environment directly (this is intentional — the process needs the plaintext to function).

---

## Project layout

```
crates/
  kosh-core/      — crypto, keychain, env-file parsing, reference IDs
  kosh-redactor/  — real-time output scrubber + blocked-command gate
  kosh-cli/       — the `kosh` binary (clap CLI, all commands)
  kosh-server/    — axum REST API, Postgres/RLS persistence, JWT auth
```

---

## Running the server

The server requires Postgres. A minimal setup:

```sh
# Start Postgres (Docker example).
docker run -d --name kosh-pg \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 postgres:16

# Set environment variables.
export DATABASE_URL="postgres://postgres:postgres@localhost/postgres"
export KOSH_JWT_SECRET="change-me-in-production"

# Run migrations and start.
cargo run -p kosh-server
```

Tokens are minted out-of-band — there is no password login. Use the `issue-token` subcommand on the server machine to create a JWT for a new user:

```sh
# Issue a token for a user (reads KOSH_JWT_SECRET from env).
kosh-server issue-token --user <user-uuid>

# Custom lifetime (e.g. 30 days for a CI token).
kosh-server issue-token --user <user-uuid> --ttl 2592000
```

Hand the printed token to the user, who runs `kosh login --server <url> --token <token>`. The user UUID is any UUIDv4 you assign — kosh has no user registration; identity is the JWT `sub` claim.

---

## Development

```sh
# All unit tests (no Docker needed).
cargo test --workspace --lib

# Full test suite including live-server integration tests (Docker required).
cargo test --workspace

# Lint + format.
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

The integration tests in `crates/kosh-cli/tests/sync_test.rs` spin up a real Postgres container via [testcontainers](https://testcontainers.com/), run migrations, start the real `kosh-server`, and drive the real `kosh` binary — no mocking.

---

## License

[Business Source License 1.1](LICENSE). Converts to Apache 2.0 four years after each release.
