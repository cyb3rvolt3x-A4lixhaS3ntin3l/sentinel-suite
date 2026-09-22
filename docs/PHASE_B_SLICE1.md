# Phase B slice1 — ShadowsEye that pays (first shippable)

**Date:** 2026-09-22 (Asia/Colombo)  
**Commit intent:** `feat: Phase B slice1 — Eye L0/L2/L5 lite, ranker, watch`

## Layers

| Layer | Status | Notes |
| --- | --- | --- |
| L0 Program brain | **real** | import-brief + `program.yml`: name, platform, allow/deny counts, updated_at, layers_enabled |
| L1 Identity | **deferred** | Cert SAN / RDAP / ASN / MX — next slice |
| L2 Passive DNS/CT | **real (native) + stub (crt.sh)** | native socket+wordlist; `crtsh_query` injectable; tools deferred |
| L3 Code OSINT | **deferred** | |
| L4 Cloud | **deferred** | |
| L5 Live map | **lite real** | resolve + bounded ports + stdlib HTTP probe; `tech: []` stub |
| L6 Watch | **MVP real** | `runs/latest.json` + history; `--watch` diffs |
| Ranker | **real** | interestingness.py logic in `ranker.py` |

## CLI

`sentinel eye run <program> <domains…> [--scope|--i-own-this] [--json] [--watch] [--no-tools|--tools] [--no-crtsh] [--no-http]`

Default `--no-tools` until `ENGINE_ALLOWLIST` has hashes.
