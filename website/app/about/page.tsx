import type { Metadata } from "next";
import Link from "next/link";
import Image from "next/image";
import { Nav } from "@/components/nav";

const GITHUB = "https://github.com/VaarunSinha/kosh";

export const metadata: Metadata = {
  title: "About",
  description:
    "About Kosh, the encrypted secret vault built from first principles, and the author behind it.",
};

export default function AboutPage() {
  return (
    <>
      <Nav />
      <main
        style={{
          maxWidth: "720px",
          margin: "0 auto",
          padding: "80px 24px 120px",
        }}
      >
        {/* About the project */}
        <section style={{ marginBottom: "96px" }}>
          <p
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              letterSpacing: "0.15em",
              color: "var(--accent)",
              textTransform: "uppercase",
              margin: "0 0 20px",
            }}
          >
            The project
          </p>
          <h1
            style={{
              fontSize: "clamp(32px, 5vw, 52px)",
              fontWeight: 700,
              letterSpacing: "-0.02em",
              color: "var(--text)",
              lineHeight: 1.15,
              margin: "0 0 32px",
            }}
          >
            Kosh
          </h1>

          <div
            style={{
              fontSize: "16px",
              color: "var(--text-muted)",
              lineHeight: 1.8,
              display: "flex",
              flexDirection: "column",
              gap: "18px",
            }}
          >
            <p style={{ margin: 0 }}>
              <strong style={{ color: "var(--text)" }}>Kosh</strong> (Sanskrit:{" "}
              <em style={{ fontFamily: "var(--font-mono)", color: "var(--accent)" }}>कोष</em>, Koṣa) means
              treasury, a place where valuables are kept. That is exactly what this tool is.
            </p>
            <p style={{ margin: 0 }}>
              Developer secrets live in{" "}
              <code
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "14px",
                  color: "var(--text)",
                  backgroundColor: "var(--surface)",
                  padding: "2px 6px",
                  borderRadius: "4px",
                }}
              >
                .env
              </code>{" "}
              files, passed in plaintext, leaked in logs, and accidentally committed. Kosh fixes that. It
              encrypts your secrets locally using{" "}
              <strong style={{ color: "var(--text)" }}>X25519 key exchange</strong> and{" "}
              <strong style={{ color: "var(--text)" }}>XChaCha20-Poly1305 AEAD</strong>, stores only opaque
              references on disk, injects plaintext into child processes at runtime, and automatically
              redacts values from terminal output.
            </p>
            <p style={{ margin: 0 }}>
              When your team needs the same secrets, Kosh syncs them through a server, encrypted
              end-to-end, with role-based access control. The server never sees plaintext. Neither does your
              terminal history.
            </p>
            <p style={{ margin: 0 }}>
              It is local-first, offline-capable, and built in Rust. No daemon, no cloud dependency, no
              vendor lock-in.
            </p>
          </div>

          <div
            style={{
              marginTop: "40px",
              padding: "24px",
              borderRadius: "12px",
              border: "1px solid var(--border)",
              backgroundColor: "var(--surface)",
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "24px",
            }}
          >
            {[
              { label: "License", value: "AGPL-3.0" },
              { label: "Language", value: "Rust" },
              { label: "Encryption", value: "X25519 + XChaCha20-Poly1305" },
              { label: "KDF", value: "Argon2id" },
            ].map((item) => (
              <div key={item.label}>
                <p
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "11px",
                    color: "var(--text-muted)",
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    margin: "0 0 4px",
                  }}
                >
                  {item.label}
                </p>
                <p
                  style={{
                    fontFamily: "var(--font-mono)",
                    fontSize: "13px",
                    color: "var(--text)",
                    margin: 0,
                  }}
                >
                  {item.value}
                </p>
              </div>
            ))}
          </div>

          <div style={{ marginTop: "28px", display: "flex", gap: "12px", flexWrap: "wrap" }}>
            <Link
              href="/docs"
              style={{
                padding: "10px 22px",
                borderRadius: "8px",
                backgroundColor: "var(--accent)",
                color: "var(--background)",
                fontWeight: 600,
                fontSize: "14px",
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
                padding: "10px 22px",
                borderRadius: "8px",
                border: "1px solid var(--border)",
                color: "var(--text)",
                fontWeight: 500,
                fontSize: "14px",
                textDecoration: "none",
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <GitHubIcon />
              View on GitHub
            </a>
            <a
              href={`${GITHUB}/blob/main/CONTRIBUTING.md`}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                padding: "10px 22px",
                borderRadius: "8px",
                border: "1px solid var(--border)",
                color: "var(--text-muted)",
                fontWeight: 500,
                fontSize: "14px",
                textDecoration: "none",
              }}
            >
              Contributing
            </a>
          </div>
        </section>

        {/* Divider */}
        <div style={{ height: "1px", backgroundColor: "var(--border)", marginBottom: "96px" }} />

        {/* About the author */}
        <section>
          <p
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              letterSpacing: "0.15em",
              color: "var(--accent)",
              textTransform: "uppercase",
              margin: "0 0 20px",
            }}
          >
            The author
          </p>

          {/* Author header with photo */}
          <div
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "28px",
              marginBottom: "32px",
              flexWrap: "wrap",
            }}
          >
            <div
              style={{
                width: "80px",
                height: "80px",
                borderRadius: "12px",
                overflow: "hidden",
                border: "1px solid var(--border)",
                flexShrink: 0,
                backgroundColor: "var(--surface)",
              }}
            >
              <Image
                src="/vaarun.jpeg"
                alt="Vaarun Sinha"
                width={80}
                height={80}
                style={{ objectFit: "cover", width: "100%", height: "100%" }}
              />
            </div>
            <div>
              <h2
                style={{
                  fontSize: "clamp(24px, 4vw, 36px)",
                  fontWeight: 700,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                  lineHeight: 1.15,
                  margin: "0 0 8px",
                }}
              >
                Vaarun Sinha
              </h2>
              {/* Social links */}
              <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
                <a
                  href="https://github.com/VaarunSinha"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "5px",
                    fontSize: "13px",
                    color: "var(--text-muted)",
                    textDecoration: "none",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  <GitHubIcon />
                  VaarunSinha
                </a>
                <a
                  href="https://nexshastra.tech"
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "5px",
                    fontSize: "13px",
                    color: "var(--text-muted)",
                    textDecoration: "none",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  nexshastra.tech ↗
                </a>
              </div>
            </div>
          </div>

          <div
            style={{
              fontSize: "16px",
              color: "var(--text-muted)",
              lineHeight: 1.8,
              display: "flex",
              flexDirection: "column",
              gap: "18px",
            }}
          >
            <p style={{ margin: 0 }}>
              Self-taught since 12. Not from curiosity alone, from an obsession with understanding how
              things actually work, and then making them work better.
            </p>
            <p style={{ margin: 0 }}>
              Across{" "}
              <a
                href="https://digitea.in"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: "var(--text)", textDecoration: "none", borderBottom: "1px solid var(--border)" }}
              >
                Digitea
              </a>
              ,{" "}
              <a
                href="https://aajsecode.com"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: "var(--text)", textDecoration: "none", borderBottom: "1px solid var(--border)" }}
              >
                Aaj Se Code
              </a>
              , and{" "}
              <a
                href="https://upkram.ai"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: "var(--text)", textDecoration: "none", borderBottom: "1px solid var(--border)" }}
              >
                Upkram.ai
              </a>
              , I kept running into the same problem: secrets scattered across machines, shared over chat,
              committed by accident, leaked in logs. Every project, every team, the same failure mode.
            </p>
            <p style={{ margin: 0 }}>
              Kosh is the tool I needed. Built to handle secrets the way infrastructure should, encrypted
              on device, redacted from output, synced without trust assumptions. No ceremony, no cloud
              accounts, no exposure.
            </p>
          </div>

          {/* Lineage */}
          <div
            style={{
              marginTop: "40px",
              display: "flex",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "0",
              fontFamily: "var(--font-mono)",
              fontSize: "12px",
              color: "var(--text-muted)",
            }}
          >
            {[
              { name: "Digitea", href: "https://digitea.in" },
              { name: "Aaj Se Code", href: "https://aajsecode.com" },
              { name: "Upkram.ai", href: "https://upkram.ai" },
              { name: "Nexshastra", href: "https://nexshastra.tech" },
            ].map((item, i, arr) => (
              <span key={item.name} style={{ display: "flex", alignItems: "center" }}>
                {item.href ? (
                  <a
                    href={item.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      color: "var(--text)",
                      padding: "4px 10px",
                      borderRadius: "4px",
                      backgroundColor: "var(--surface)",
                      border: "1px solid var(--border)",
                      textDecoration: "none",
                    }}
                  >
                    {item.name}
                  </a>
                ) : (
                  <span
                    style={{
                      color: "var(--text)",
                      padding: "4px 10px",
                      borderRadius: "4px",
                      backgroundColor: "var(--surface)",
                      border: "1px solid var(--border)",
                    }}
                  >
                    {item.name}
                  </span>
                )}
                {i < arr.length - 1 && (
                  <span style={{ color: "var(--accent)", padding: "0 8px" }}>→</span>
                )}
              </span>
            ))}
          </div>
        </section>
      </main>
    </>
  );
}

function GitHubIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
    </svg>
  );
}
