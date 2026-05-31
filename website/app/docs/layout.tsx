import { DocsLayout } from "fumadocs-ui/layouts/docs";
import type { ReactNode } from "react";
import { source } from "@/lib/source";
import Image from "next/image";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={source.pageTree}
      links={[
        { text: "Home", url: "/", type: "main" },
        { text: "About", url: "/about", type: "main" },
        {
          text: "GitHub",
          url: "https://github.com/VaarunSinha/kosh",
          type: "main",
          external: true,
        },
      ]}
      nav={{
        title: (
          <span
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
            }}
          >
            <Image
              src="/icon.svg"
              alt="Kosh"
              width={20}
              height={20}
              style={{
                filter:
                  "var(--icon-filter)",
              }}
            />
            <span
              style={{
                fontWeight: 600,
                letterSpacing: "0.15em",
                fontSize: "14px",
                textTransform: "uppercase",
              }}
            >
              KOSH
            </span>
          </span>
        ),
      }}
    >
      {children}
    </DocsLayout>
  );
}
