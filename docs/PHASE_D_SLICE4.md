# Phase D slice4 — Tauri wrap + deferred screens

**Goal:** Desktop Tauri shell (same SPA) + OSINT graph / Surface / Auth lab / Workbench density; Ctrl+K. Browser at `http://127.0.0.1:8888` remains first-class.

Full can/cannot: `/workspace/deliverables/SENTINEL_SUITE_PHASE_D4_SLICE.md`

## Open

```bash
# Browser (unchanged)
sentinel ui   # http://127.0.0.1:8888

# Tauri desktop wrap (loads same URL; start API first)
# cargo install tauri-cli --version "^2"   # once
npm run tauri:dry-run   # config/scaffold check (no full build required)
# cargo tauri build     # .dmg / .msi / .AppImage when host tooling present
```

## Tabs (D4)

- **OSINT** — filterable org→domains→people/emails→certs from graph
- **Surface** — endpoints / params / JS / OpenAPI-ish catalog
- **Auth lab** — roles vault display + replay stub (no silent live)
- **Workbench** — repeater-lite; export curl/Burp/Caido; live send needs `i_own_this`

## D4 Can

- Tauri scaffolding + dry-run; same SPA/API
- RO viz/catalog APIs with honest empties
- Workbench live gated; exports without network
- Ctrl+K palette; tests rise from 486

## D4 Cannot

- Electron; new packs; allowlist pins; Guard SDK
- Invented findings; auto-VERIFIED; silent live
- New `.github/workflows` while OAuth HOLD (packaging CI → `docs/ci-pending/`)
- Burp replacement

## Packaging CI blocker

Workflow OAuth may still HOLD — **do not push** new `.github/workflows`. Proposed Tauri packaging job lives only under `docs/ci-pending/tauri.yml` until Founder unblocks OAuth.
