# Phase D slice2 — Assets / Changes / Modules

**Goal:** Eye inventory + watch diffs + read-only module catalog in the local UI.

Full can/cannot: `/workspace/deliverables/SENTINEL_SUITE_PHASE_D2_SLICE.md`

## CLI

```bash
sentinel ui   # http://127.0.0.1:8888
```

## Tabs

- **Assets** — domains / DNS / IPs / ports / URLs from program graph (sorted by interestingness when scored)
- **Changes** — 24h / 7d / latest watch deltas (ranked); honest empty if no `runs/` store
- **Modules** — read-only listing of the 12 hunt pack manifests (no install)

## D2 Can

- Graph-backed asset tables + filters; no fabricated rows
- Windowed watch diffs from Phase B Eye snapshots
- RO modules catalog; RO APIs open under D1 auth split
- Tests for new routes + SPA smoke

## D2 Cannot

- New hunt packs; ENGINE_ALLOWLIST population; Guard SDK; Tauri/Electron
- Coach chatbot (D3); silent live runs; auto-VERIFIED; module install/publish
- Non-loopback without `--i-understand-lab`

## Next

**D3** — Coach panel + Settings denser chrome (Coach never invents bugs).
