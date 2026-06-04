#!/bin/sh
# kosh installer — https://kosh.useyukti.com
#
# Downloads the prebuilt kosh binary from GitHub Releases and installs it.
# Supports: Linux (x86_64, arm64), macOS (x86_64, arm64).
#
# Usage:
#   curl -fsSL https://kosh.useyukti.com/install.sh | sh
#
# NOTE: Prebuilt binaries are published when a version tag (v*) is pushed to
# GitHub. If no release exists yet, this script will exit with a clear error.
# In that case, install via Cargo:
#   cargo install kosh

set -e

REPO="VaarunSinha/kosh"
BINARY="kosh"
INSTALL_DIR="/usr/local/bin"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
bold()    { printf '\033[1m%s\033[0m\n' "$1"; }
green()   { printf '\033[0;32m%s\033[0m\n' "$1"; }
yellow()  { printf '\033[1;33m%s\033[0m\n' "$1"; }
err()     { printf '\033[0;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------
OS=$(uname -s 2>/dev/null || echo "unknown")
case "$OS" in
  Linux)  OS="linux"  ;;
  Darwin) OS="darwin" ;;
  *)      err "Unsupported OS: $OS — use 'cargo install kosh' instead." ;;
esac

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------
ARCH=$(uname -m 2>/dev/null || echo "unknown")
case "$ARCH" in
  x86_64)        ARCH="x86_64"  ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *)             err "Unsupported architecture: $ARCH — use 'cargo install kosh' instead." ;;
esac

# ---------------------------------------------------------------------------
# Map to GitHub release asset
# ---------------------------------------------------------------------------
if [ "$OS" = "linux" ]; then
  TARGET="${ARCH}-unknown-linux-musl"
elif [ "$OS" = "darwin" ]; then
  TARGET="${ARCH}-apple-darwin"
fi

ARCHIVE="${BINARY}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/latest/download/${ARCHIVE}"

bold "kosh installer"
printf '  Platform : %s / %s\n' "$OS" "$ARCH"
printf '  Asset    : %s\n' "$ARCHIVE"
printf '  URL      : %s\n\n' "$URL"

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

ARCHIVE_PATH="$TMP_DIR/$ARCHIVE"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL --retry 3 "$URL" -o "$ARCHIVE_PATH" \
    || err "Download failed — no release published yet? Try: cargo install kosh"
  curl -fsSL --retry 3 "${URL}.sha256" -o "${ARCHIVE_PATH}.sha256" \
    || err "Checksum file download failed."
elif command -v wget >/dev/null 2>&1; then
  wget -q "$URL" -O "$ARCHIVE_PATH" \
    || err "Download failed — no release published yet? Try: cargo install kosh"
  wget -q "${URL}.sha256" -O "${ARCHIVE_PATH}.sha256" \
    || err "Checksum file download failed."
else
  err "Neither curl nor wget found — install one and retry."
fi

# ---------------------------------------------------------------------------
# Verify checksum
# ---------------------------------------------------------------------------
EXPECTED=$(cat "${ARCHIVE_PATH}.sha256")
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')
else
  yellow "Warning: no sha256sum or shasum found — skipping checksum verification."
  ACTUAL="$EXPECTED"
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
  err "Checksum mismatch — download may be corrupted or tampered.
  Expected: $EXPECTED
  Got:      $ACTUAL"
fi

# ---------------------------------------------------------------------------
# Extract
# ---------------------------------------------------------------------------
tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"

BINARY_PATH="$TMP_DIR/$BINARY"
if [ ! -f "$BINARY_PATH" ]; then
  BINARY_PATH=$(find "$TMP_DIR" -name "$BINARY" -not -name "*.gz" -type f 2>/dev/null | head -1)
  [ -n "$BINARY_PATH" ] || err "Binary not found in archive."
fi

chmod +x "$BINARY_PATH"

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
if [ -w "$INSTALL_DIR" ]; then
  mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY"
elif sudo -n true 2>/dev/null; then
  sudo mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY"
else
  printf 'Installing to %s requires elevated permissions.\n' "$INSTALL_DIR"
  if sudo mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY" 2>/dev/null; then
    : # sudo succeeded
  else
    # Final fallback: ~/.local/bin
    LOCAL_BIN="$HOME/.local/bin"
    mkdir -p "$LOCAL_BIN"
    mv "$BINARY_PATH" "$LOCAL_BIN/$BINARY"
    INSTALL_DIR="$LOCAL_BIN"
    yellow "Installed to $LOCAL_BIN (not in /usr/local/bin)."
    yellow "Add it to your PATH:"
    yellow '  export PATH="$HOME/.local/bin:$PATH"'
  fi
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
printf '\n'
if "$INSTALL_DIR/$BINARY" --version >/dev/null 2>&1; then
  VERSION=$("$INSTALL_DIR/$BINARY" --version)
  green "kosh installed successfully!"
  printf '  Version  : %s\n' "$VERSION"
  printf '  Location : %s\n' "$INSTALL_DIR/$BINARY"
  printf '\nRun \033[1mkosh init\033[0m to get started.\n'
else
  err "Installed but 'kosh --version' failed — check $INSTALL_DIR/$BINARY"
fi
