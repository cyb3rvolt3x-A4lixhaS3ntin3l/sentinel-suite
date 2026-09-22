# Phase B slice3 — L5 tech fingerprint heuristics

**Date:** 2026-09-22 (Asia/Colombo)  
**Commit intent:** `feat: Phase B slice3 — L5 tech fingerprint heuristics`

## Layers (reality table)

| Layer | Status | Notes |
| --- | --- | --- |
| L0 Program brain | **real** | import-brief + `program.yml` fields / `layers_enabled` |
| L1 Identity | **lite real (low confidence)** | RDAP org/email + ASN stub + MX + SPF; injectable; no sherlock/maigret |
| L2 Passive DNS/CT | **real (native) + hardened crt.sh + reverse-IP stub** | tools still deferred; ENGINE_ALLOWLIST empty (Founder HOLD) |
| L3 Code OSINT | **deferred** | |
| L4 Cloud | **deferred** | |
| L5 Live map | **lite real + tech fingerprint** | resolve + bounded ports + stdlib HTTP probe + native header/body heuristics → `tech[]` + TECH events |
| L6 Watch | **MVP real** | `runs/latest.json` + history |
| Ranker | **real** | interestingness + rare/admin tech boosts (jenkins/graphql/wordpress/…) |

## What fingerprint covers (honest, not Wappalyzer)

- **Headers:** Server (nginx/apache/cloudflare/IIS), X-Powered-By (PHP/ASP.NET/Express/Next), X-Jenkins, CF-Ray, ASP.NET version headers
- **Cookies:** wordpress_*, laravel_session, PHPSESSID, JSESSIONID, csrftoken / django, _rails_session
- **Path / body:** /graphql, /jenkins, /actuator (Spring), wp-content, generator meta, jQuery / React / Next.js signatures

Confidence labelled **low–med** (≈0.40–0.65). No live net required for unit tests — injectable headers/body.

## CLI flags

```text
sentinel eye run … [--no-http] [--no-fingerprint] [--fingerprint]
```

- Fingerprint **default on** when HTTP probes run
- `--no-http` skips probes **and** fingerprint
- `--no-fingerprint` keeps HTTP but skips tech heuristics
- `--fingerprint` explicit enable (optional; same as default with HTTP)

## Honesty / HOLD

- **ENGINE_ALLOWLIST remains empty** — Founder HOLD via Arisha; do not pin hashes or wire `--tools` downloads
- Proposal doc only: `/workspace/deliverables/PHASE_B_ENGINE_HASH_PROPOSAL.md` (and `docs/ENGINE_HASH_PROPOSAL.md`)
- No L3/L4 stalk; no Guard; no workflows; MIT; scope gates unchanged
