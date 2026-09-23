# Productization research (Step 0) — pointer

**Status:** RESEARCH COMPLETE (2026-09-23 IST). Demos, packaging, and README product rewrite have all shipped — this file stays a research pointer.

Full evidence-based packet (competitors, README SEO, Tauri vs Releases, webopen notes, blockers):

`/workspace/deliverables/SENTINEL_SUITE_PRODUCTIZATION_RESEARCH.md`

## This-week ship path (summary)

1. **Demos first** on `andraxpentester.in` + `sentinelreign.com` only.
2. Keep **path/git + Docker Compose** as the only guaranteed multi-OS install (PyPI unpublished; packaging CI OAuth HOLD).
3. **`sentinel ui --open` / `demo` / `full-run`** shipped in packaging.
4. Optional binaries via **manual GitHub Release** assets only if actually built — label **unsigned** (ZAP honesty). Prefer Linux AppImage / PyInstaller CLI before claiming macOS notarized DMG.
5. **Tauri** stays the desktop-shell direction (`src-tauri` targets dmg/msi/AppImage/deb); do not invent green CI — see `ci-pending/tauri.yml`.
6. **cargo-dist** is a poor primary fit (Rust-centric; suite is Python + thin Tauri wrap).
7. README SEO pass shipped — one-liner + GIF + features/comparison tables — **no fake metrics**.

## Blockers for packaging step

- Workflow OAuth HOLD (`HUMAN-QUEUE.md`) — no push of `.github/workflows`
- No Apple notarization / Windows Authenticode
- `tauri-cli` often missing (`scripts/packaging_dry_run.py` reports this)
- PyPI unpublished; `ENGINE_ALLOWLIST` empty

## Related

- [`INSTALL.md`](INSTALL.md) · [`WSL2.md`](WSL2.md) · [`PHASE_F_SHIP.md`](PHASE_F_SHIP.md) · [`ci-pending/tauri.yml`](ci-pending/tauri.yml)
