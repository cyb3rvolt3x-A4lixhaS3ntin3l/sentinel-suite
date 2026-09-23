#!/usr/bin/env bash
# Linux AppImage via Tauri — attempts local build; exits honestly if blocked.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  echo "BLOCKED: cargo missing — cannot build Tauri AppImage"
  exit 2
fi
if ! cargo tauri --version >/dev/null 2>&1; then
  echo "BLOCKED: tauri-cli missing"
  echo "  Install (timeboxed): cargo install tauri-cli --version '^2'"
  echo "  Also need webkit2gtk / patchelf on the builder."
  echo "  Prefer scripts/build_pyinstaller_linux.sh for a verified CLI binary this week."
  exit 2
fi

cargo tauri build --bundles appimage
echo "If successful, AppImage is under src-tauri/target/release/bundle/appimage/"
echo "Label UNSIGNED unless you signed it."
