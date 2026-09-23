# Phase D slice1 — Hunt / Scope / Reports + optional bcrypt

**Goal:** Polish hunt loop in the local UI (map → pack → confirm → report) without leaving the browser (lab).

Full can/cannot + auth split: `/workspace/deliverables/SENTINEL_SUITE_PHASE_D1_SLICE.md`

## CLI

```bash
sentinel ui   # http://127.0.0.1:8888
```

## D1 Can

- Hunt polish: pack picker, role paths, scope/`--i-own-this` clarity, denser run log, visible Stop
- Scope screen: view/edit `scope.txt`, brief import summary, hard-kill probe
- Reports: markdown export per pack / all-packs
- Confirm-finding UX (never auto-VERIFIED)
- Optional bcrypt first-run under `SENTINEL_HOME/ui_auth.json` (or skip-for-lab)
- Tests for new routes + bcrypt gate + scope dry-run

## D1 Cannot

- New hunt packs; ENGINE_ALLOWLIST population; Guard SDK; Tauri/Electron
- Non-loopback bind without `--i-understand-lab`; silent live runs; auto-VERIFIED
- New GitHub workflows; malware/exploit PoCs

## Auth split (summary)

- **RO open:** health, doctor, programs, packs, findings, scope GET, report export
- **Mutating gated** when password hash present: pack run/stop, scope edit, brief import, confirm-finding
- Missing `ui_auth.json` → first-run (set password **or** skip-for-lab) before mutating
- Skip-lab mode trusts loopback (primary fence unchanged)

## Next

**D2** — Assets + Changes (Eye); Modules catalog read-only.
