# shadowseye (monorepo package)

**Honest status (Sprint 0 Phase A complete):** thin bridge + thin Eye runner.

## What this package IS

- Depends on `sentinel_core`
- Bridge emitters: DOMAIN / DNS_NAME / IP / OPEN_PORT + `inventory_to_events`
- Thin runner (`shadowseye.runner.run_eye` / CLI `sentinel eye run`):
  - stdlib DNS resolve + tiny subdomain wordlist + bounded TCP port probe
  - builds inventory → `inventory_to_events` → program graph under `SENTINEL_HOME`
  - requires `--scope` **or** `--i-own-this`
  - hard_kill domains when a scope file is loaded

## What this package is NOT

- **Not** feature parity with the live ShadowsEye CLI (full DNS/sub/ports/modules)
- **No** whois / social / password-leak stalking
- Full Eye L0–L6 + watch is **Phase B** — see the God-level plan
- Historical / richer code may live in the public `ShadowsEye` repo (thin README mirror → this monorepo); this package is the suite bridge + thin runner only

Do not claim live ShadowsEye capabilities from this package.
