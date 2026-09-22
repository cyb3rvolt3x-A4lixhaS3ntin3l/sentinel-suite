# Phase C slice1 — Hunt Pack framework + ATO/OAuth/OIDC v0

**Date:** 2026-09-22 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice1 — hunt pack framework + ATO/OAuth/OIDC v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack manifest + registry | **real** | dataclass under `gungnir.packs`; discover submodules with `MANIFEST` + `run` |
| CLI `hunt pack list\|run` | **real** | `--program`, `--scope`/`--i-own-this`, `--url`, `--role-a`/`--role-b` |
| Role session fail-closed | **real** | coach-style stderr text; needs Role A (Role B if `needs_roles=2`) |
| Pack `ato_oauth_oidc` v0 | **real (candidates)** | surface heuristics + OAuth param / token-leak / reset-enum checks |
| Graph wire | **real** | `require_scope_or_lab` + `emit_verified_finding` / `emit_evidence_event` |
| Finding gate checklist | **real** | `in_scope`, `reproducible`, `impact`, `evidence_attached` |

## What the pack can do

- Detect auth/OAuth/OIDC/SAML/reset/magic-link **URL candidates** (heuristics)
- Flag missing `state`, missing PKCE on `response_type=code`, suspicious `redirect_uri` patterns
- Flag token leakage **pattern candidates** from fixtures / URL fragments (`access_token`/`id_token`/`code`)
- Flag password-reset enumeration **candidates** when known vs unknown fixtures differ (no lockout loops)
- Emit honest verification + checklist into the program graph

## What the pack cannot do

- Full ATO chain automation
- Live IdP attacks or token-theft malware
- BOLA / IDOR (deferred)
- Report factory / coach UI / Tauri / `--tools` / Guard / workflows / desync
- nuclei-all or destructive PoCs

## CLI

```bash
sentinel hunt pack list
sentinel hunt pack run ato_oauth_oidc --program demo --scope ./scope.txt \
  --url 'https://app.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://evil.example/cb'
# lab:
sentinel hunt pack run ato_oauth_oidc --program demo --i-own-this \
  --url 'https://lab.example/login'
```

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK touch; no live mirror-repo edits this ship

## Explicit defer

Report factory, coach UI, Tauri, `--tools`, BOLA pack, desync, Guard, X, workflows
