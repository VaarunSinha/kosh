"use client";

import { useState } from "react";

interface CopyButtonProps {
  text: string;
  label?: string;
}

export function CopyButton({ text, label }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={copy}
      aria-label={`Copy ${label ?? text}`}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "6px",
        padding: "4px 8px",
        borderRadius: "5px",
        border: "none",
        background: "transparent",
        color: copied ? "var(--accent)" : "var(--text-muted)",
        cursor: "pointer",
        fontSize: "12px",
        transition: "color 0.15s",
        flexShrink: 0,
      }}
    >
      {copied ? <CheckIcon /> : <CopyIcon />}
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

function CopyIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}
