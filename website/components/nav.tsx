"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import Image from "next/image";
import { useEffect, useState } from "react";

const links = [
  { href: "/", label: "Home" },
  { href: "/about", label: "About" },
  { href: "/docs", label: "Docs" },
];

export function Nav() {
  const pathname = usePathname();
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  const isDark = resolvedTheme === "dark";

  return (
    <header
      style={{
        borderBottom: "1px solid var(--border)",
        backgroundColor: "var(--background)",
        position: "sticky",
        top: 0,
        zIndex: 50,
      }}
    >
      <div
        style={{
          maxWidth: "1100px",
          margin: "0 auto",
          padding: "0 24px",
          height: "60px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <Link href="/" style={{ display: "flex", alignItems: "center", gap: "10px", textDecoration: "none" }}>
          <Image
            src="/icon.svg"
            alt="Kosh"
            width={28}
            height={28}
            style={{ filter: "var(--icon-filter)" }}
          />
          <span
            style={{
              fontFamily: "var(--font-sans)",
              fontSize: "17px",
              fontWeight: 600,
              letterSpacing: "0.18em",
              color: "var(--text)",
              textTransform: "uppercase",
            }}
          >
            KOSH
          </span>
        </Link>

        <nav style={{ display: "flex", gap: "2px", alignItems: "center" }}>
          {links.map((link) => {
            const active = pathname === link.href || (link.href !== "/" && pathname.startsWith(link.href));
            return (
              <Link
                key={link.href}
                href={link.href}
                style={{
                  padding: "6px 14px",
                  borderRadius: "6px",
                  fontSize: "14px",
                  fontWeight: active ? 500 : 400,
                  color: active ? "var(--accent)" : "var(--text-muted)",
                  textDecoration: "none",
                  transition: "color 0.15s",
                  backgroundColor: active ? "rgba(200, 164, 90, 0.08)" : "transparent",
                }}
              >
                {link.label}
              </Link>
            );
          })}

          {/* Theme toggle */}
          <button
            onClick={() => setTheme(isDark ? "light" : "dark")}
            aria-label="Toggle theme"
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              width: "34px",
              height: "34px",
              borderRadius: "6px",
              border: "none",
              background: "transparent",
              color: "var(--text-muted)",
              cursor: "pointer",
              flexShrink: 0,
              opacity: mounted ? 1 : 0,
            }}
          >
            {mounted && (isDark ? <SunIcon /> : <MoonIcon />)}
          </button>

          <a
            href="https://github.com/VaarunSinha/kosh"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub"
            style={{
              display: "flex",
              alignItems: "center",
              padding: "6px 10px",
              borderRadius: "6px",
              color: "var(--text-muted)",
              textDecoration: "none",
            }}
          >
            <GitHubIcon />
          </a>
        </nav>
      </div>
    </header>
  );
}

function SunIcon() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4" />
      <line x1="12" y1="2" x2="12" y2="4" />
      <line x1="12" y1="20" x2="12" y2="22" />
      <line x1="4.93" y1="4.93" x2="6.34" y2="6.34" />
      <line x1="17.66" y1="17.66" x2="19.07" y2="19.07" />
      <line x1="2" y1="12" x2="4" y2="12" />
      <line x1="20" y1="12" x2="22" y2="12" />
      <line x1="4.93" y1="19.07" x2="6.34" y2="17.66" />
      <line x1="17.66" y1="6.34" x2="19.07" y2="4.93" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

function GitHubIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
    </svg>
  );
}
