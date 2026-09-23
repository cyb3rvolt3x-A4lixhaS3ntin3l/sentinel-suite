# Sentinel Suite — Tauri shell (Phase D4)

Wraps the **same** local SPA served by `sentinel ui` at `http://127.0.0.1:8888`.

## Browser vs Tauri

| Mode | How |
| --- | --- |
| **Browser (first-class)** | `sentinel ui` → open http://127.0.0.1:8888 |
| **Tauri desktop** | Start API (`sentinel ui`), then `cargo tauri dev` (loads 127.0.0.1:8888) |

Tauri does **not** replace the browser UI. No Electron.

## Build artifacts

```bash
# Install CLI once (host must have rustc + system deps for webview)
cargo install tauri-cli --version "^2"
cargo tauri build
# → .dmg (macOS) / .msi (Windows) / .AppImage + .deb (Linux) when tooling present
```

Dry-run (no full compile):

```bash
python scripts/tauri_dry_run.py
# or: npm run tauri:dry-run
python scripts/packaging_dry_run.py   # Phase F: targets + honest blockers
```

## Packaging CI

GitHub workflow OAuth may still HOLD — **do not push** new `.github/workflows`.
See `docs/ci-pending/tauri.yml` for the proposed job.
