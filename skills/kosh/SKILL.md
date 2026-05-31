---
name: kosh
description: Manage secrets safely with kosh — an AI-safe, local-first secret guard for developers. Use this skill when the user wants to add, edit, rotate, or delete secrets; run commands with secrets injected; sync secrets with a team server; manage team members and env-key access; or when a .env file contains plain-text values that should be encrypted.
---

# Kosh

Kosh encrypts `.env` secrets locally using age (X25519) and injects them into subprocesses at runtime. It redacts secret values from all stdout/stderr before they reach the terminal — protecting against leaks into AI context windows. In team mode, secrets are encrypted to a per-environment key and synced to a self-hosted server; the server never sees plaintext.

## When to Use This Skill

Use this skill when the user:

- Has plain-text secrets in a `.env` file that should be encrypted
- Wants to run a command (dev server, tests, scripts) with secrets injected
- Asks to add, edit, rotate, or delete a secret
- Wants to sync secrets across machines or share them with teammates
- Is setting up kosh for the first time
- Wants to manage workspace members or grant env-key access
- Asks why their secret appeared in terminal output (redaction issue)

## Prerequisites

Kosh must be installed. Check with:

```bash
which kosh
kosh --version
```

If missing:

```bash
cargo install --path crates/kosh-cli
# or once published:
cargo install kosh
```

Run `kosh init` once per machine to generate the user key and write default config:

```bash
kosh init
```

## Core Concepts

- **KOSH: references** — plain values in `.env` are replaced with `KOSH:xxxxxxxx` tokens after `kosh add`. The token is safe to commit; the ciphertext lives in the OS keychain.
- **Solo mode** — no server, secrets encrypted to the user's own key. Default.
- **Team mode** — secrets encrypted to a per-environment key shared across members via a self-hosted `kosh-server`.
- **Redaction** — `kosh run` scans every output line and replaces known secret values with `[REDACTED]` before printing.

## Workflows

### Set up a new project

```bash
kosh init                        # generate user key (once per machine)
kosh add --file .env             # encrypt all plain values in .env in place
cat .env                         # values are now KOSH: references
```

### Add a single secret interactively

```bash
kosh add --key DATABASE_URL      # prompts for the value securely
```

### Run a command with secrets injected

```bash
kosh run -- npm run dev
kosh run -- pytest tests/
kosh run -- cargo test
```

Secrets are decrypted into the child process environment only. All output is redacted in real time.

### List, edit, rotate, delete

```bash
kosh list                        # list managed secrets in current env
kosh edit --key API_KEY          # replace a secret's value
kosh rotate --key API_KEY        # rotate (new value, new ref)
kosh delete API_KEY              # remove a secret
```

### Check current state

```bash
kosh status                      # workspace, env, key presence
```

## Team Mode

### First-time login (token provided by server admin)

```bash
kosh login --server https://kosh.example.com --token <jwt>
```

### Sync secrets with the server

```bash
kosh -w acme -e dev sync         # reconcile both directions (server wins)
kosh -w acme -e dev sync --push  # upload local secrets only
kosh -w acme -e dev sync --pull  # download server secrets only
```

### Manage workspace members

```bash
kosh -w acme team list
kosh -w acme team invite <user-uuid> --role developer
kosh -w acme team invite <user-uuid> --role readonly
```

Roles: `owner`, `admin`, `developer`, `readonly`, `ci`. Only `owner`, `admin`, and `developer` can write secrets.

### Grant a member the env decryption key

```bash
kosh -w acme -e dev team grant-env <user-uuid>
```

The member then runs `kosh sync` to unwrap the env key locally. The server never sees the plaintext key.

### Log out

```bash
kosh logout
```

## Server Administration

To issue a first-time token for a new user:

```bash
# On the server machine, with KOSH_JWT_SECRET set
kosh-server issue-token --user <user-uuid>
kosh-server issue-token --user <user-uuid> --ttl 2592000  # 30-day CI token
```

## Escape Hatches (use with caution)

By default, shells and env-dump commands (`bash`, `sh`, `env`, `printenv`, `echo $VAR`) are blocked entirely. To override:

```bash
# Allow a blocked command — requires sudo, output still redacted
sudo kosh run --dangerously-allow-blocked -- bash build.sh

# Disable redaction — requires sudo
sudo kosh run --dangerously-turn-off-redact -- npm run dev

# Both
sudo kosh run --dangerously-allow-blocked --dangerously-turn-off-redact -- bash build.sh
```

Both flags require `sudo` as a forcing function for conscious intent.

## Global Flags

| Flag | Short | Description |
|---|---|---|
| `--workspace` | `-w` | Override the current workspace |
| `--env` | `-e` | Override the current environment |
| `--json` | | Output as JSON |

## Security Rules (never violate these)

- **Never read a `.env` file's contents directly** — it may contain `KOSH:` references that are not secrets, but the plain values before `kosh add` are.
- **Never print or log a decrypted secret value** — always use `kosh run` so the redactor is active.
- **Never suggest `echo $SECRET` or `env | grep`** — these are blocked by kosh for good reason.
- **Never suggest storing secrets in shell history** — always use `kosh add --key` which prompts without echoing.
- **`KOSH:xxxxxxxx` tokens are not secrets** — they are safe to read, display, and commit.

## Common Mistakes to Avoid

- Running `kosh run -- bash -c "echo $SECRET"` — blocked and wrong; use `kosh run -- node -e "console.log(process.env.SECRET)"` instead.
- Forgetting `kosh add` before `kosh sync` — sync only pushes `KOSH:` refs, not plain values.
- Running `kosh sync` before `kosh login` in team mode — will fail with no server configured.
- Expecting `kosh list` to show values — it shows refs only, by design.
