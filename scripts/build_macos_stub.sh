#!/usr/bin/env bash
# macOS .app / .dmg — STUB ONLY.
# This Linux builder cannot produce a real notarized (or even unsigned) .dmg/.app.
# Native build requires a Mac + Xcode/webkit + (optional) Apple Developer ID.
# NEVER invent a .dmg artifact on Releases from this script.
set -euo pipefail
cat <<'MSG'
BLOCKED: macOS native packaging
- Reason: no Mac builder / no Apple notarization in this environment
- Tauri targets (dmg) remain scaffolded under src-tauri/; see docs/ci-pending/tauri.yml
- When a Mac is available:
    cargo install tauri-cli --version "^2"
    cargo tauri build   # produces unsigned .app/.dmg — label Gatekeeper / not notarized
- Do NOT upload a fake .dmg from Linux
MSG
exit 2
