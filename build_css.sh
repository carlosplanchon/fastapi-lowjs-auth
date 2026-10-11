#!/bin/bash
# -*- coding: utf-8 -*-

# Rebuilds src/web/static/app.css from src/web/tailwind.css with the Tailwind
# standalone CLI (no Node.js needed). Run it after changing classes in the
# templates: the generated CSS is committed, so running the app needs no build.

set -euo pipefail
cd "$(dirname "$0")"

TAILWIND_VERSION="v4.3.3"

# Checksums from the release's sha256sums.txt.
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  ASSET="tailwindcss-linux-x64"   SHA256="dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a" ;;
    Linux-aarch64) ASSET="tailwindcss-linux-arm64" SHA256="55fd0b241214eff3de1e8ee4f22796662f2d2e7a49bcfca7477cfd0bac398195" ;;
    Darwin-x86_64) ASSET="tailwindcss-macos-x64"   SHA256="7922e0953f2110c05976e3bf58f14e643d90427575e766b7d433f5f80cbee7e1" ;;
    Darwin-arm64)  ASSET="tailwindcss-macos-arm64" SHA256="cdf646702987a743464dff4d9c60fd4480d1c1e73dd819a9a67f1078815dce9d" ;;
    *) echo "Unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

BIN=".tools/$ASSET-$TAILWIND_VERSION"
if [ ! -x "$BIN" ]; then
    mkdir -p .tools
    curl -fsSL -o "$BIN.download" \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/$TAILWIND_VERSION/$ASSET"
    if command -v sha256sum >/dev/null; then
        echo "$SHA256  $BIN.download" | sha256sum --check --quiet
    else
        echo "$SHA256  $BIN.download" | shasum -a 256 --check --quiet
    fi
    chmod +x "$BIN.download"
    mv "$BIN.download" "$BIN"
fi

"$BIN" -i src/web/tailwind.css -o src/web/static/app.css --minify
