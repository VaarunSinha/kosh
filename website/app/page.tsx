import Link from "next/link";
import Image from "next/image";
import { Nav } from "@/components/nav";
import { CopyButton } from "@/components/copy-button";

const GITHUB = "https://github.com/VaarunSinha/kosh";

const features = [
  {
    icon: "▣",
    title: "Encrypted at rest",
    body: "X25519 + XChaCha20-Poly1305 AEAD. Your secrets never touch disk in plaintext.",
  },
  {
    icon: "◎",
    title: "Automatic redaction",
    body: "kosh run intercepts stdout and stderr, scrubbing secret values before they reach your terminal.",
  },
  {
    icon: "⊕",
    title: "Team-ready",
    body: "Sync encrypted secrets across your team. Role-based access: owner, admin, developer, readonly, ci.",
  },
  {
    icon: "◈",
    title: "Local-first",
    body: "Works fully offline. The server is optional, use it only when you need team sync.",
  },
];

const steps = [
  {
    step: "01",
    cmd: "kosh init",
    desc: "Generate your user key and write the default config. One time, per machine.",
    slug: "init",
  },
  {
    step: "02",
    cmd: "kosh add --file .env",
    desc: "Encrypt every plain value in your .env file. References replace the originals.",
    slug: "add",
  },
  {
    step: "03",
    cmd: "kosh run -- node server.js",
    desc: "Inject decrypted secrets into the child process. Output is automatically redacted.",
    slug: "run",
  },
  {
    step: "04",
    cmd: "kosh sync --push",
    desc: "Push encrypted secrets to the server when your team needs access.",
    slug: "sync",
  },
];

const securityDetails = [
  {
    label: "Key exchange",
    value: "X25519",
    detail: "Elliptic-curve Diffie-Hellman over Curve25519. Each team member's public key is used to derive a shared secret, no key material is ever transmitted.",
  },
  {
    label: "Encryption",
    value: "XChaCha20-Poly1305",
    detail: "Authenticated encryption with associated data (AEAD). Provides both confidentiality and integrity. Nonces are 192-bit, making collisions computationally impossible.",
  },
  {
    label: "Key derivation",
    value: "Argon2id",
    detail: "Memory-hard KDF designed to resist GPU and ASIC brute-force attacks. Used to derive the local encryption key from your passphrase.",
  },
  {
    label: "Hashing",
    value: "BLAKE3",
    detail: "Fast, secure cryptographic hash function used for content-addressed secret references.",
  },
  {
    label: "Key storage",
    value: "OS keychain",
    detail: "Your private key is stored in the operating-system keychain (macOS Keychain, Windows Credential Manager, or Linux libsecret). Kosh never writes plaintext keys to disk.",
  },
  {
    label: "On-device only",
    value: "Zero server trust",
    detail: "Decryption happens exclusively on your machine. The sync server stores only ciphertext and never receives your private key or any plaintext value.",
  },
];

export default function HomePage() {
  return (
    <>
      <Nav />

      {/* Hero */}
      <section
        style={{
          minHeight: "calc(100svh - 60px)",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          textAlign: "center",
          padding: "60px 24px",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Grid background */}
        <div
          aria-hidden
          style={{
            position: "absolute",
            inset: 0,
            backgroundImage: `
              linear-gradient(var(--border) 1px, transparent 1px),
              linear-gradient(90deg, var(--border) 1px, transparent 1px)
            `,
            backgroundSize: "48px 48px",
            opacity: 0.35,
            maskImage:
              "radial-gradient(ellipse 80% 60% at 50% 50%, black 30%, transparent 100%)",
          }}
        />

        <div style={{ position: "relative", maxWidth: "720px", width: "100%" }}>
          {/* Logo tile */}
          <div style={{ display: "flex", justifyContent: "center", marginBottom: "32px" }}>
            <div
              style={{
                width: "80px",
                height: "80px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                borderRadius: "16px",
                border: "1px solid var(--border)",
                backgroundColor: "var(--surface)",
              }}
            >
              <Image
                src="/icon.svg"
                alt="Kosh vault icon"
                width={48}
                height={48}
                style={{
                  filter:
                    "var(--icon-filter)",
                }}
              />
            </div>
          </div>

          {/* Wordmark */}
          <h1
            style={{
              fontFamily: "var(--font-sans)",
              fontSize: "clamp(56px, 10vw, 96px)",
              fontWeight: 700,
              letterSpacing: "0.22em",
              color: "var(--text)",
              margin: "0 0 4px",
              lineHeight: 1,
            }}
          >
            KOSH
          </h1>
          <p
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              letterSpacing: "0.2em",
              color: "var(--accent)",
              marginBottom: "24px",
              textTransform: "uppercase",
            }}
          >
            कोष, a treasury
          </p>

          <p
            style={{
              fontSize: "18px",
              color: "var(--text-muted)",
              lineHeight: 1.65,
              maxWidth: "480px",
              margin: "0 auto 48px",
            }}
          >
            Encrypt your secrets locally. Redact them from terminal output. Sync securely with your team.
          </p>

          {/* Install blocks */}
          <div className="install-grid">
            <InstallBlock label="macOS / Linux" cmd="curl -fsSL https://kosh.useyukti.com/install.sh | sh" />
            <InstallBlock label="Homebrew" cmd="brew install VaarunSinha/kosh/kosh" />
            <InstallBlock label="Windows (PowerShell)" cmd="irm https://kosh.useyukti.com/install.ps1 | iex" />
            <InstallBlock label="Cargo" cmd="cargo install kosh" />
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)", marginBottom: "32px" }}>
            <Link href="/docs/installation" style={{ color: "var(--accent)", textDecoration: "none" }}>
              All installation methods →
            </Link>
          </p>

          {/* CTAs */}
          <div
            style={{
              display: "flex",
              gap: "12px",
              justifyContent: "center",
              flexWrap: "wrap",
            }}
          >
            <Link
              href="/docs"
              style={{
                padding: "12px 28px",
                borderRadius: "8px",
                backgroundColor: "var(--accent)",
                color: "var(--background)",
                fontWeight: 600,
                fontSize: "15px",
                textDecoration: "none",
              }}
            >
              Read the docs
            </Link>
            <a
              href={GITHUB}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                padding: "12px 28px",
                borderRadius: "8px",
                border: "1px solid var(--border)",
                color: "var(--text)",
                fontWeight: 500,
                fontSize: "15px",
                textDecoration: "none",
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <GitHubIcon />
              GitHub
            </a>
          </div>
        </div>
      </section>

      {/* Features */}
      <section
        style={{
          padding: "96px 24px",
          maxWidth: "1100px",
          margin: "0 auto",
          width: "100%",
        }}
      >
        <SectionLabel>What it does</SectionLabel>
        <h2
          style={{
            fontSize: "clamp(28px, 4vw, 42px)",
            fontWeight: 700,
            color: "var(--text)",
            marginBottom: "48px",
            letterSpacing: "-0.02em",
          }}
        >
          Built for secrets that matter.
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
            gap: "16px",
          }}
        >
          {features.map((f) => (
            <div
              key={f.title}
              style={{
                padding: "28px",
                borderRadius: "12px",
                border: "1px solid var(--border)",
                backgroundColor: "var(--surface)",
              }}
            >
              <div
                style={{
                  fontSize: "20px",
                  color: "var(--accent)",
                  marginBottom: "14px",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {f.icon}
              </div>
              <h3
                style={{
                  fontSize: "16px",
                  fontWeight: 600,
                  color: "var(--text)",
                  margin: "0 0 8px",
                }}
              >
                {f.title}
              </h3>
              <p
                style={{
                  fontSize: "14px",
                  color: "var(--text-muted)",
                  lineHeight: 1.65,
                  margin: 0,
                }}
              >
                {f.body}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section
        style={{
          padding: "0 24px 96px",
          maxWidth: "1100px",
          margin: "0 auto",
          width: "100%",
        }}
      >
        <SectionLabel>How it works</SectionLabel>
        <h2
          style={{
            fontSize: "clamp(28px, 4vw, 42px)",
            fontWeight: 700,
            color: "var(--text)",
            marginBottom: "48px",
            letterSpacing: "-0.02em",
          }}
        >
          Four commands from zero to secure.
        </h2>
        <div style={{ display: "flex", flexDirection: "column" }}>
          {steps.map((s, i) => (
            <div
              key={s.step}
              style={{
                display: "grid",
                gridTemplateColumns: "48px 1fr auto",
                gap: "20px",
                alignItems: "start",
                padding: "28px 0",
                borderBottom:
                  i < steps.length - 1 ? "1px solid var(--border)" : "none",
              }}
            >
              <span
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "11px",
                  color: "var(--accent)",
                  paddingTop: "4px",
                  letterSpacing: "0.08em",
                }}
              >
                {s.step}
              </span>
              <div>
                {/* Copyable command */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    marginBottom: "8px",
                    backgroundColor: "var(--surface)",
                    border: "1px solid var(--border)",
                    borderRadius: "8px",
                    padding: "8px 12px",
                  }}
                >
                  <code
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: "14px",
                      color: "var(--text)",
                      flexGrow: 1,
                    }}
                  >
                    {s.cmd}
                  </code>
                  <CopyButton text={s.cmd} label={s.cmd} />
                </div>
                <p
                  style={{
                    fontSize: "14px",
                    color: "var(--text-muted)",
                    lineHeight: 1.65,
                    margin: 0,
                  }}
                >
                  {s.desc}
                </p>
              </div>
              <Link
                href={`/docs/${s.slug}`}
                style={{
                  fontSize: "12px",
                  color: "var(--accent)",
                  textDecoration: "none",
                  paddingTop: "11px",
                  whiteSpace: "nowrap",
                  opacity: 0.8,
                }}
              >
                Docs →
              </Link>
            </div>
          ))}
        </div>
        <div style={{ marginTop: "40px" }}>
          <Link
            href="/docs"
            style={{
              fontSize: "14px",
              color: "var(--accent)",
              textDecoration: "none",
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            View all commands →
          </Link>
        </div>
      </section>

      {/* Privacy & Security */}
      <section
        style={{
          padding: "0 24px 96px",
          maxWidth: "1100px",
          margin: "0 auto",
          width: "100%",
        }}
      >
        <SectionLabel>Privacy & Security</SectionLabel>
        <h2
          style={{
            fontSize: "clamp(28px, 4vw, 42px)",
            fontWeight: 700,
            color: "var(--text)",
            marginBottom: "16px",
            letterSpacing: "-0.02em",
          }}
        >
          Cryptography you can audit.
        </h2>
        <p
          style={{
            fontSize: "16px",
            color: "var(--text-muted)",
            lineHeight: 1.7,
            maxWidth: "640px",
            marginBottom: "48px",
          }}
        >
          Kosh uses established, audited primitives from the Rust{" "}
          <code style={{ fontFamily: "var(--font-mono)", fontSize: "13px", color: "var(--text)", backgroundColor: "var(--surface)", padding: "2px 6px", borderRadius: "4px" }}>dalek</code>,{" "}
          <code style={{ fontFamily: "var(--font-mono)", fontSize: "13px", color: "var(--text)", backgroundColor: "var(--surface)", padding: "2px 6px", borderRadius: "4px" }}>chacha20poly1305</code>, and{" "}
          <code style={{ fontFamily: "var(--font-mono)", fontSize: "13px", color: "var(--text)", backgroundColor: "var(--surface)", padding: "2px 6px", borderRadius: "4px" }}>argon2</code> crates.
          No custom crypto. No telemetry. No cloud accounts required.
        </p>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))",
            gap: "1px",
            backgroundColor: "var(--border)",
            border: "1px solid var(--border)",
            borderRadius: "12px",
            overflow: "hidden",
          }}
        >
          {securityDetails.map((item) => (
            <div
              key={item.label}
              style={{
                padding: "24px",
                backgroundColor: "var(--surface)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "baseline",
                  gap: "10px",
                  marginBottom: "10px",
                  flexWrap: "wrap",
                }}
              >
                <span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "11px",
                    color: "var(--text-muted)",
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    flexShrink: 0,
                  }}
                >
                  {item.label}
                </span>
                <span
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "12px",
                    fontWeight: 600,
                    color: "var(--accent)",
                    backgroundColor: "rgba(200, 164, 90, 0.1)",
                    padding: "2px 8px",
                    borderRadius: "4px",
                    border: "1px solid rgba(200, 164, 90, 0.2)",
                  }}
                >
                  {item.value}
                </span>
              </div>
              <p
                style={{
                  fontSize: "13px",
                  color: "var(--text-muted)",
                  lineHeight: 1.65,
                  margin: 0,
                }}
              >
                {item.detail}
              </p>
            </div>
          ))}
        </div>

        {/* Zero-trust callout */}
        <div
          style={{
            marginTop: "16px",
            padding: "20px 24px",
            borderRadius: "10px",
            border: "1px solid rgba(200, 164, 90, 0.25)",
            backgroundColor: "rgba(200, 164, 90, 0.05)",
            display: "flex",
            alignItems: "flex-start",
            gap: "14px",
          }}
        >
          <span style={{ fontSize: "18px", flexShrink: 0, paddingTop: "1px" }}>⊛</span>
          <p
            style={{
              fontSize: "14px",
              color: "var(--text-muted)",
              lineHeight: 1.65,
              margin: 0,
            }}
          >
            <strong style={{ color: "var(--text)" }}>On-device decryption, always.</strong>{" "}
            Your private key never leaves your machine. The Kosh server (if used) stores only encrypted blobs.
            Even if the server is compromised, your secrets remain ciphertext without your local key.
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer
        style={{
          borderTop: "1px solid var(--border)",
          padding: "32px 24px",
          textAlign: "center",
        }}
      >
        <p style={{ fontSize: "13px", color: "var(--text-muted)", margin: 0 }}>
          Kosh is open source under the{" "}
          <a
            href={`${GITHUB}/blob/main/LICENSE`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "var(--accent)", textDecoration: "none" }}
          >
            AGPL-3.0 License
          </a>
          {" · "}
          <a
            href={GITHUB}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "var(--accent)", textDecoration: "none" }}
          >
            GitHub ↗
          </a>
          {" · "}
          <Link href="/about" style={{ color: "var(--text-muted)", textDecoration: "none" }}>
            About
          </Link>
          {" · "}
          <Link href="/docs" style={{ color: "var(--text-muted)", textDecoration: "none" }}>
            Docs
          </Link>
        </p>
      </footer>
    </>
  );
}

function InstallBlock({ label, cmd }: { label: string; cmd: string }) {
  return (
    <div
      style={{
        borderRadius: "10px",
        border: "1px solid var(--border)",
        backgroundColor: "var(--surface)",
        overflow: "hidden",
        textAlign: "left",
      }}
    >
      <div
        style={{
          padding: "8px 14px",
          borderBottom: "1px solid var(--border)",
          fontSize: "11px",
          color: "var(--text-muted)",
          letterSpacing: "0.06em",
          fontFamily: "var(--font-mono)",
        }}
      >
        {label}
      </div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 14px",
          gap: "8px",
        }}
      >
        <code
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "12px",
            color: "var(--text)",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {cmd}
        </code>
        <CopyButton text={cmd} label={label} />
      </div>
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: "11px",
        letterSpacing: "0.15em",
        color: "var(--accent)",
        textTransform: "uppercase",
        margin: "0 0 12px",
      }}
    >
      {children}
    </p>
  );
}

function GitHubIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
    </svg>
  );
}
