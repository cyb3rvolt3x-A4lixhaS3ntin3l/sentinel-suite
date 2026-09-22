# Phase B slice2 — L1 identity lite + deeper CT / reverse-IP

**Date:** 2026-09-22 (Asia/Colombo)  
**Commit intent:** `feat: Phase B slice2 — L1 identity lite + deeper CT/reverse-IP`

## Layers (reality table)

| Layer | Status | Notes |
| --- | --- | --- |
| L0 Program brain | **real** | import-brief + `program.yml` fields / `layers_enabled` |
| L1 Identity | **lite real (low confidence)** | RDAP org/email + ASN stub + MX + SPF; injectable fetchers; `confirmed: false` until DNS/cert confirms; **no** sherlock/maigret |
| L2 Passive DNS/CT | **real (native) + hardened crt.sh + reverse-IP stub** | crt.sh timeouts/parse/dedupe/wildcard care; reverse-IP injectable with hard scope-distance cap; tools still deferred |
| L3 Code OSINT | **deferred** | |
| L4 Cloud | **deferred** | |
| L5 Live map | **lite real** | resolve + bounded ports + stdlib HTTP probe; `tech: []` stub |
| L6 Watch | **MVP real** | `runs/latest.json` + history; snapshot may include identity keys |
| Ranker | **real** | interestingness + light MX-only demotion when identity says mx |

## CLI flags added

```text
sentinel eye run … [--no-identity] [--no-reverse-ip] [--scope-distance N]
```

- `--identity` is default **on**; `--no-identity` skips L1
- `--reverse-ip` default **on** (honest empty stub without fetcher); `--no-reverse-ip` skips
- `--scope-distance` int, default `1` (hard cap on reverse-IP neighbours)

## Honesty

- Empty allowlist remains; engine hashes proposed only (see hash proposal doc) — **not** auto-downloaded
- Reverse-IP without injectable fetcher returns `[]` + source note
- Identity confidence ~0.35–0.40; ASN may be `stub:asn-unavailable` when domain RDAP lacks ASN
