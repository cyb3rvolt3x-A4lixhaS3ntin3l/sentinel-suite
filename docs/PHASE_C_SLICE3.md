# Phase C slice3 — BOLA/IDOR/BFLA pack v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice3 — BOLA/IDOR/BFLA pack v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `bola_idor_bfla` v0 | **real (candidates)** | `needs_roles=2`; fixture-driven only |
| Horizontal IDOR | **real (fixture)** | A↔B object swap / A reads B object |
| Vertical / BFLA | **real (fixture)** | A hits admin-ish path B/admin can access |
| Sibling methods | **real (fixture)** | GET vs DELETE/PUT/PATCH confusion |
| Fail-closed Role B | **real** | coach-style message; will not start without A+B |
| Checklist + verification | **real** | `in_scope` / `reproducible` / `impact` / `evidence_attached` |
| CLI list\|run\|report | **wired** | existing pack registry + `--pack bola_idor_bfla` |
| ATO pack | **intact** | `ato_oauth_oidc` still listed/runnable |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Require Role A **and** Role B session fixtures before start
- Emit horizontal IDOR / BOLA candidates from dual-role response fixtures
- Emit vertical privilege / BFLA candidates from admin-path fixtures
- Emit sibling-method confusion candidates (mutating method allowed in fixture)
- Honest `confirmed` vs `unverified` verification; evidence stubs from fixtures only
- Soft OOS filter via scope hard-kill (same as ATO pack)

## What the pack cannot do

- Live multi-tenant abuse or other-customer probing
- Data destruction / destructive exploit PoCs
- Full business-logic assistant, race packs, live collaborator SSRF
- Report factory polish beyond existing markdown
- nuclei-all, Guard SDK, workflows, X

## CLI

```bash
sentinel hunt pack list
# prepare roles/a.json + roles/b.json under the program
sentinel hunt pack run bola_idor_bfla --program demo --scope ./scope.txt \
  --role-a ./roles/a.json --role-b ./roles/b.json
# lab:
sentinel hunt pack run bola_idor_bfla --program demo --i-own-this
sentinel hunt report demo --pack bola_idor_bfla -o ./bola-report.md
# ATO still works:
sentinel hunt pack run ato_oauth_oidc --program demo --i-own-this \
  --url 'https://lab.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://lab.example/cb'
```

Fixtures are injected in tests via `run_pack(..., fixtures={...})` (mocked HTTP). Production CLI remains scope-gated and role-gated; no live multi-tenant automation.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this`
- Role A **and** Role B fail-closed
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no nuclei-all

## Explicit defer

Full business-logic assistant, race packs, live collaborator SSRF, report factory polish beyond existing md, coach UI, Tauri, `--tools`, desync, Guard, X, workflows
