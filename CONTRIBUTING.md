# Contributing to Kosh

Thank you for your interest in contributing. Kosh is a security-critical tool — contributions are welcome, but the bar for correctness is high.

## Before you start

- Read the [README](./README.md) to understand what Kosh is and how it works.
- Open an issue before starting significant work. This ensures the direction aligns with the project before you invest time.
- For security issues, **do not open a public issue**. Email the maintainer directly (see profile).

## Development setup

You need:

- Rust stable (≥ 1.76)
- Cargo

```bash
git clone https://github.com/VaarunSinha/kosh
cd kosh
cargo build
cargo test
```

The workspace has four crates:

| Crate | Purpose |
|-------|---------|
| `kosh-core` | Crypto primitives, env parsing, vault logic |
| `kosh-redactor` | Output stream scrubbing |
| `kosh-cli` | CLI interface (clap) |
| `kosh-server` | Optional team sync server |

## Guidelines

### Cryptography

- Do not introduce custom cryptography. Use the existing primitives (`x25519-dalek`, `chacha20poly1305`, `argon2`, `blake3`).
- Any change to the encryption scheme requires a design document and explicit sign-off.

### Code style

- Follow standard Rust idioms. Run `cargo fmt` and `cargo clippy` before submitting.
- Avoid `unwrap()` in library code — propagate errors with `?`.
- Write unit tests for all new logic. Integration tests for CLI commands.

### Commits

- Use short, imperative commit messages: `fix: redactor skips empty values`, `feat(cli): add --json to kosh list`.
- Keep commits focused. One logical change per commit.

### Pull requests

- Reference the issue your PR addresses.
- Include a test that would have caught the bug (for bug fixes).
- Update documentation in `website/content/docs/` if you add or change a command.

## Licence

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0 License](./LICENSE).
