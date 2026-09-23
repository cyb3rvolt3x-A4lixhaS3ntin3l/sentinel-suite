# Phase D slice0 — local UI shell

**Goal:** Minimal god-level local UI shell (not all Founder screens).

## CLI

```bash
sentinel ui
# alias:
sentinel serve-ui
# defaults → http://127.0.0.1:8888
# non-loopback bind requires --i-understand-lab
sentinel ui --bind 0.0.0.0 --port 8888 --i-understand-lab   # lab only
```

## D0 Can

- Serve SPA + JSON API on **127.0.0.1:8888** by default
- Home: doctor status, program list, pack list (12 Phase C packs)
- Read-only: programs, packs, findings for selected program
- One gated action: **pack run** requiring UI `i_own_this` (+ optional scope path / lab flag)
- Bind gate: refuse `0.0.0.0` / `::` without `--i-understand-lab`
- Tests: bind localhost-only + API smoke

## D0 Cannot

- Tauri / Electron
- Full Scope / Assets / Changes / Reports / Modules / Coach / Settings screens
- Team mode, cloud sync, Burp replacement
- Silent live pack runs / auto-VERIFIED findings
- New hunt packs; ENGINE_ALLOWLIST population

## Layout

- Static SPA: repo `ui/` (`index.html`, `app.js`, `style.css`)
- Server: `sentinel_cli.ui_server` (stdlib `http.server`)
- API: `/api/doctor`, `/api/programs`, `/api/packs`, `/api/programs/<id>/findings`, `POST /api/pack/run`

## Next

**D1** — Hunt/Scope/Reports polish + optional bcrypt first-run + confirm-finding UX.
