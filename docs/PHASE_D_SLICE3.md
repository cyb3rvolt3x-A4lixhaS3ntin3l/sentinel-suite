# Phase D slice3 — Coach + Settings

**Goal:** Methodology coach (rule/count hints, never invents bugs) + denser Settings chrome.

Full can/cannot: `/workspace/deliverables/SENTINEL_SUITE_PHASE_D3_SLICE.md`

## CLI

```bash
sentinel ui   # http://127.0.0.1:8888
```

## Tabs

- **Coach** — stage checklist, pack-rule hints from graph counts, FP school, report-school impact templates, Eye time-budget; structured hints only (no LLM)
- **Settings** — SENTINEL_HOME, bind display, local auth (set/skip/clear), doctor/engines (allowlist `{}`), theme stub, rates if present

## D3 Can

- Live-data coach hints derived from graph/assets/findings/Eye age — never claim a vuln absent from findings store
- Settings RO status + clear-password behind D1 auth gate
- Tests for coach hints + settings read/auth clear; count rises from 474

## D3 Cannot

- New hunt packs; ENGINE_ALLOWLIST population; Guard SDK; Tauri/Electron (D4 proposal only)
- Invented findings; auto-VERIFIED; LLM chatbot
- Non-loopback without `--i-understand-lab`

## Next

**D4 (propose only)** — Tauri wrap of same SPA; deferred screens (OSINT graph viz, Surface, Auth lab, Workbench). Wait for Founder GO.
