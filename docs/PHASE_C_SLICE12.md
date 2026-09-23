# Phase C slice12 — http_desync pack v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice12 — http_desync pack v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `http_desync` v0 | **real (candidates)** | `needs_roles=0` |
| CL.TE / TE.CL / header-smuggle fixtures | **real** | differential response markers only |
| Lab dual-flag gate | **real** | beyond fixtures → `--i-own-this` **and** `--i-understand-lab` |
| Open-internet default refuse | **real** | needs scope + ownership + lab flag |
| Hard request caps | **real** | requests≤10 for non-pure-fixture paths |
| Human gate | **real** | findings `needs_human`; never auto-VERIFIED |
| Prior packs | **intact** | all Phase C packs through `jwt_session` |
| race_toctou hard caps | **untouched** | workers≤4, requests≤20, duration≤5s |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Emit CL.TE / TE.CL / header-smuggle **candidates** when fixtures show
  differential responses (status/body/header/marker) across ambiguous
  request interpretations
- Run pure fixture mode in CI **without** `--i-understand-lab`
- Prefer `127.0.0.1` / in-process fixture differentials (no live smuggle I/O)
- Enforce hard request caps (≤10) on live-mock / non-fixture paths
- Attach finding-gate checklist + honest verification enum
- Scope-gate via `--scope` or `--i-own-this`; lab flag is **additional**

## What the pack cannot do

- **Production CDN/WAF smuggling** campaigns / live desync weaponization
- **DoS / flood** / unlimited request spray
- Open-internet without `--scope` **and** `--i-own-this` **and** `--i-understand-lab`
- Non-fixture paths without **both** ownership and lab acknowledgment flags
- Auto-VERIFIED / confirmed findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X
- Raise `race_toctou` hard caps

## Honesty fence

Authorized **detection scaffolding** only — fixture-driven by default.
Evidence = differential response markers in fixtures — **not** a production
smuggling weapon. Coach: *desync is lab/staging; production needs written
auth + careful coordination*.

## Lab gate enforcement

| Code path | Behavior |
| --- | --- |
| `http_desync.caps.assert_lab_dual_flag` | Beyond `fixtures_only` → require `i_own_this` **and** `i_understand_lab` |
| `http_desync.caps.assert_target_allowed` | Open-internet → triple gate (scope + ownership + lab); lab-local live → dual flag |
| `http_desync.checks.run_checks` | Classifies pure fixtures vs live URLs / `live_mock` / `opener`; raises `PackRunError` on gate fail |
| Fail-closed tests | `test_fail_closed_open_internet_without_lab_flag`, `test_fail_closed_lab_local_live_without_lab_flag`, `test_fail_closed_live_mock_without_lab_flag`, `test_cli_fail_closed_without_lab_flag_on_live_url`, `test_assert_open_internet_triple_gate`, `test_assert_non_fixture_requires_dual_flag` |

## CLI

```bash
sentinel hunt pack list
# Pure fixtures (CI-friendly; no lab flag):
sentinel hunt pack run http_desync --program demo --i-own-this
# Beyond fixtures / acknowledged lab:
sentinel hunt pack run http_desync --program demo --i-own-this --i-understand-lab
# Open-internet staging (written auth + coordination):
sentinel hunt pack run http_desync --program demo --scope ./scope.txt \
  --i-own-this --i-understand-lab --url 'https://staging.example/'
sentinel hunt report demo --pack http_desync -o ./http-desync-report.md
```

### Fixture shape (lab)

```json
{
  "desync_scenarios": [
    {
      "name": "cl-te-diff",
      "kind": "cl_te",
      "url": "http://127.0.0.1/lab/desync",
      "interpretation_a": {"status": 200, "body": "OK-CL", "marker": "CL_VIEW"},
      "interpretation_b": {"status": 404, "body": "TE-path", "marker": "TE_VIEW"},
      "expect": {"differential": true}
    }
  ],
  "te_cl": [],
  "header_smuggle": []
}
```

## Caps

Constants in `gungnir.packs.http_desync.caps`: `HARD_MAX_REQUESTS=10` (default 6).
Over-limit → hard fail. Pure fixture runs do not consume the live budget.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this` to start; lab flag additional for this pack
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no live CDN/WAF smuggling; no DoS; no `--tools`; no X
