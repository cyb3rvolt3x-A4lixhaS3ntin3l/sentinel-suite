# Phase C slice2 — OAuth nonce/PKCE stubs, client hints, report md

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice2 — OAuth nonce/PKCE stubs, client hints, report md`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Nonce / PKCE verify stubs | **real (fixture-driven)** | presence/format; `confirmed` only with proving `expect` |
| Client-type hints | **real (low confidence)** | discovery / HTML / JSON fixtures |
| Thin report markdown | **real** | `sentinel hunt report <program> [--pack ...] [-o FILE]` |
| Pack `ato_oauth_oidc` | **deepened (v0.2)** | wired into existing checks + graph emit |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do (slice2 delta)

- Observe `nonce`, `code_challenge`, `code_challenge_method` on authorize URLs / fixtures
- Mark verification **`unverified`** when live proof / `expect` is missing
- Mark **`confirmed`** only when fixture `expect` matches observed absence/mismatch patterns
- Emit low-confidence **public** / **confidential** / **mixed** client-type hints
- Export platform-shaped markdown: Title, Summary, Steps (from evidence only), Impact, Remediation placeholders

## What the pack cannot do

- Full ATO chain automation
- Live IdP attacks or token-theft malware
- BOLA / IDOR (still deferred)
- LLM-authored Steps to Reproduce
- Report factory / coach UI / Tauri / `--tools` / Guard / workflows / desync
- nuclei-all or destructive PoCs

## CLI

```bash
sentinel hunt pack list
sentinel hunt pack run ato_oauth_oidc --program demo --scope ./scope.txt \
  --url 'https://app.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://app.example/cb'
sentinel hunt report demo --pack ato_oauth_oidc -o ./report.md
# stdout:
sentinel hunt report demo --pack ato_oauth_oidc
```

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this`
- Role A fail-closed
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no live IdP abuse

## Explicit defer

BOLA pack, coach UI, Tauri, `--tools`, desync, Guard, X, workflows, full report factory
