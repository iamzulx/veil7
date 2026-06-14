#!/usr/bin/env bash
# Sign release binaries with GPG
# Usage: ./scripts/sign-release.sh [binary_path]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${1:-$ROOT/target/release/veil7}"

if [ ! -f "$BINARY" ]; then
    echo "Error: binary not found at $BINARY"
    echo "Run 'cargo build --release' first."
    exit 1
fi

echo "Signing: $BINARY"
sha256sum "$BINARY" > "${BINARY}.sha256"
echo "Checksum: ${BINARY}.sha256"

if command -v gpg &>/dev/null; then
    gpg --detach-sign --armor "$BINARY"
    echo "Signature: ${BINARY}.asc"
else
    echo "Warning: gpg not found, skipping GPG signature"
fi

echo ""
echo "Release artifacts:"
ls -la "${BINARY}" "${BINARY}.sha256" "${BINARY}.asc" 2>/dev/null || true
