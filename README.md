<div align="center">

<img src="website/public/icon.svg" width="80" height="80" alt="Kosh" />

# KOSH

**कोष**

Encrypted secret vault for developers and teams.

[Website](https://kosh.useyukti.com) · [Docs](https://kosh.useyukti.com/docs) · [Install](#installation)

</div>

---

Kosh encrypts your `.env` secrets locally, redacts them from terminal output, and syncs them securely with your team. Your secrets never touch disk in plaintext. The server, if you use one, never sees them at all.

```sh
kosh init                    # generate user key
kosh add --file .env         # encrypt secrets in place
kosh run -- node server.js   # inject + auto-redact
```

## Why Kosh

AI coding assistants read your terminal. That's useful until the output contains `API_KEY=sk-...`. Kosh sits between your process and the terminal: secrets are decrypted into the child process environment and every output byte is scanned and scrubbed before reaching your screen or your context window.

- **Local-first.** Decryption happens on your machine. Ciphertext is all that ever moves.
- **Strong crypto.** X25519 key exchange, XChaCha20-Poly1305 AEAD, Argon2id KDF, BLAKE3 hashing. No custom primitives.
- **AI-safe redaction.** All stdout and stderr is scanned against known plaintexts. Shells and env-dump commands are blocked entirely.
- **Zero-knowledge sync.** Secrets are encrypted to a per-environment key. The server stores only wrapped copies of that key, never plaintext.

## Installation

Requires Rust 1.75 or later.

```sh
cargo install kosh
```

Install the Claude Code skill:

```sh
npx skills add VaarunSinha/kosh
```

Build from source:

```sh
git clone https://github.com/VaarunSinha/kosh
cd kosh
cargo install --path crates/kosh-cli
```

## Quick start

### Solo

```sh
kosh init                        # generate user key, write config
kosh add --file .env             # encrypt all plain values in place
kosh run -- npm run dev          # inject secrets, redact output
kosh add --key DATABASE_URL      # add a single secret interactively
kosh list                        # show managed secrets
kosh edit --key API_KEY          # replace a value
kosh rotate --key API_KEY        # rotate to a new value and reference
```

### Team

```sh
# Authenticate
kosh login --server https://kosh.example.com --token <jwt>

# Push secrets to the server
kosh -w acme -e dev sync --push

# Pull on a new machine
kosh -w acme -e dev sync --pull

# Invite a teammate
kosh -w acme team invite <user-uuid> --role developer

# Share the env decryption key
kosh -w acme -e dev team grant-env <user-uuid>
```

After `grant-env`, the teammate runs `kosh sync` and the env key is unwrapped locally. The server never sees the plaintext key.

## Commands

| Command | Description |
|---|---|
| `kosh init` | Generate user key, write default config |
| `kosh add --file <path>` | Encrypt all plain values in a `.env` file |
| `kosh add --key <NAME>` | Encrypt a single secret (prompts for value) |
| `kosh list [--json]` | List managed secrets in the current env |
| `kosh run -- <cmd>` | Run with secrets injected and output redacted |
| `kosh edit --key <NAME>` | Replace a secret's value |
| `kosh rotate --key <NAME>` | Rotate to a new value and new reference |
| `kosh delete <NAME>` | Remove a secret |
| `kosh status` | Show current workspace, env, and key status |
| `kosh sync [--push\|--pull]` | Reconcile local secrets with the server |
| `kosh team invite <uuid>` | Add a member to the workspace |
| `kosh team grant-env <uuid>` | Share the env key with a member |
| `kosh team list` | List workspace members and roles |
| `kosh login --server <url> --token <jwt>` | Authenticate with a Kosh server |
| `kosh logout` | Revoke the local session token |

Global flags: `--workspace / -w`, `--env / -e`, `--json`.

### Roles

| Role | Read | Write | Manage |
|---|:---:|:---:|:---:|
| `owner` | ✓ | ✓ | ✓ |
| `admin` | ✓ | ✓ | ✓ |
| `developer` | ✓ | ✓ | |
| `readonly` | ✓ | | |
| `ci` | ✓ | | |

## Security

### Blocked commands

`kosh run` refuses to launch shells (`bash`, `sh`, `zsh`, `fish`, `dash`, `ksh`) or env-dump utilities (`env`, `printenv`, `export`, `set`). To run a blocked command you own and trust, pass `--dangerously-allow-blocked` (requires sudo). Output is still redacted unless you also pass `--dangerously-turn-off-redact`.

```sh
sudo kosh run --dangerously-allow-blocked -- bash build.sh
sudo kosh run --dangerously-allow-blocked --dangerously-turn-off-redact -- bash build.sh
```

### What the server never sees

- Plaintext secret values — only ciphertext.
- Plaintext env keys — only each member's wrapped copy.
- Plaintext user private keys — only X25519 public keys.

### Threat model

Kosh protects against secrets leaking into AI context windows, accidental `.env` commits, a compromised server, and rogue scripts dumping the environment.

Kosh does not protect against a compromised OS keychain or a process reading its own environment directly (this is intentional — the process needs the plaintext to function).

## Project layout

```
crates/
  kosh-core/      crypto, keychain, env-file parsing, reference IDs
  kosh-redactor/  real-time output scrubber + blocked-command gate
  kosh-cli/       the kosh binary (clap CLI, all commands)
  kosh-server/    axum REST API, Postgres/RLS persistence, JWT auth
```

## Server setup

The server requires Postgres.

```sh
docker run -d --name kosh-pg \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 postgres:16

export DATABASE_URL="postgres://postgres:postgres@localhost/postgres"
export KOSH_JWT_SECRET="change-me-in-production"

cargo run -p kosh-server
```

Mint a token for a user:

```sh
kosh-server issue-token --user <user-uuid>
kosh-server issue-token --user <user-uuid> --ttl 2592000   # 30-day CI token
```

## Development

```sh
cargo test --workspace --lib          # unit tests, no Docker
cargo test --workspace                # full suite including live-server tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

Integration tests in `crates/kosh-cli/tests/sync_test.rs` spin up a real Postgres container via [testcontainers](https://testcontainers.com/), run migrations, and drive the real `kosh` binary end-to-end.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

[AGPL-3.0](./LICENSE)
