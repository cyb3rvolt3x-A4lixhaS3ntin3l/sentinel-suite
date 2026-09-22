# Phase C slice5 — race_toctou pack with hard caps

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice5 — race_toctou pack with hard caps`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `race_toctou` v0 | **real (scaffolding)** | `needs_roles=1`; fixture mock default |
| Hard caps | **real** | workers≤4, requests≤20, duration≤5s — over-limit hard-fails |
| `--i-understand-lab` | **real** | unlocks open-internet only with `--scope` + `--i-own-this`; does **not** raise caps |
| Fixture TOCTOU mock | **real (in-process)** | coupon + balance timing windows; 127.0.0.1 default |
| Human gate | **real** | findings `needs_human`; never auto-VERIFIED |
| Coach | **real** | “race packs are lab-first; production programs need written authorization + rate limits” |
| Prior packs | **intact** | `ato_oauth_oidc` · `bola_idor_bfla` · `business_logic` |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Detect TOCTOU / race **candidates** from in-process fixture timing windows
- Enforce hard caps on every run (CLI over-limit → hard fail + coach message)
- Default to fixture / `127.0.0.1` mock (no open-internet I/O by default)
- Emit FINDING + EVIDENCE stubs at `needs_human` for human review
- Soft OOS filter via scope hard-kill for non-local scenario hosts

## What the pack cannot do

- Act as a DoS / flood / lockout weapon
- Capture payments or harm other customers
- Auto-VERIFIED / confirmed findings
- Raise caps above workers≤4 / requests≤20 / duration≤5s (even with `--i-understand-lab`)
- Hit open internet without `--scope` **and** `--i-own-this` **and** `--i-understand-lab`
- Guard SDK, `--tools`, workflows, X, nuclei-all

## Honesty fence

Authorized **detection scaffolding** only — lab-first. Not live bank-race abuse.

## How caps are enforced (code path)

```text
CLI --max-workers|--max-requests|--max-duration|--i-understand-lab
  → sentinel_cli.cmd_hunt_pack_run
  → gungnir.packs.runner.run_pack(... into ctx)
  → gungnir.packs.race_toctou.run → checks.run_checks
  → caps.resolve_caps()          # HARD FAIL if > HARD_MAX_*
  → caps.assert_target_allowed() # open-internet triple gate
  → fixture_mock.run_fixture_race(caps)
       ThreadPoolExecutor(max_workers=caps.workers)
       RequestBudget.try_acquire()  # refuse past max_requests
       wall-clock deadline = start + max_duration_s
```

Constants live in `gungnir.packs.race_toctou.caps`:
`HARD_MAX_WORKERS=4`, `HARD_MAX_REQUESTS=20`, `HARD_MAX_DURATION_S=5.0`.

## CLI

```bash
sentinel hunt pack list
# fixture / lab default (Role A required):
sentinel hunt pack run race_toctou --program demo --i-own-this --i-understand-lab
# explicit caps (must stay ≤ maxima):
sentinel hunt pack run race_toctou --program demo --i-own-this --i-understand-lab \
  --max-workers 4 --max-requests 20 --max-duration 5
# over-limit → hard fail:
sentinel hunt pack run race_toctou --program demo --i-own-this --max-workers 99
# open internet (triple gate):
sentinel hunt pack run race_toctou --program demo \
  --scope ./scope.txt --i-own-this --i-understand-lab \
  --url 'https://app.example/wallet/withdraw'
sentinel hunt report demo --pack race_toctou -o ./race-report.md
# prior packs still work:
sentinel hunt pack run business_logic --program demo --i-own-this
sentinel hunt pack run bola_idor_bfla --program demo --i-own-this \
  --role-a ./roles/a.json --role-b ./roles/b.json
sentinel hunt pack run ato_oauth_oidc --program demo --i-own-this \
  --url 'https://lab.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://lab.example/cb'
```

### Fixture shape (lab)

```json
{
  "race_scenarios": [
    {
      "name": "coupon-once",
      "kind": "coupon_toctou",
      "url": "http://127.0.0.1/lab/coupon/redeem",
      "host": "127.0.0.1",
      "uses_left": 1,
      "check_delay_s": 0.02,
      "force_candidate_signal": true
    }
  ]
}
```

Fixtures are injected in tests via `run_pack(..., fixtures={...})`.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this` to start
- Open internet: `--scope` + `--i-own-this` + `--i-understand-lab`
- Hard caps non-overridable above maxima
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no nuclei-all; no `--tools`; no X

## Explicit defer

Live SSRF collaborator, full coach UI, LLM prose, Guard, `--tools`, workflows, X, payment-flow live races (GraphQL → see PHASE_C_SLICE6.md)
