# gungnir (monorepo package)

**Honest status (Sprint 0 Phase A, days 6–10):** bridge + thin hunt runner + optional thin correlate.

## What this package IS

- Depends on `sentinel_core`
- Bridge: `emit_finding_event`, `emit_evidence_event`, `emit_verified_finding`
- Scope/lab gate: `require_scope_or_lab(scope_path=None, i_own_this=False)`
- Thin runner (`gungnir.runner.run_hunt` / CLI `sentinel hunt run`):
  - accepts finding dicts (stdin JSON, `--findings`, or `--title` demo)
  - emits into the program event graph with verification fields
  - requires `--scope` **or** `--i-own-this`
- Thin correlate (`gungnir.correlate.correlate_findings`):
  - dedupes by title+host
  - default verification `unverified`
  - optional empty `chain_stubs` (no fabricated multi-finding theater)

## What this package is NOT (yet)

- **Not** a port of the full Gungnir product (bugforge, web UI, hunt pack library)
- **Not** the enhanced 26-chain correlation library from legacy `enhanced_correlate.py`
- **Not** feature parity with live/public Gungnir packages for reports or pack orchestration

For historical enhanced correlate / verify code, see the separate legacy harden /
public Gungnir repositories — they are **not** vendored wholesale into this suite.

Prefer small honest code over a lying README. When chains land, they will be
auditable and tested — not claimed early.

Do not claim live Gungnir capabilities from this package.
