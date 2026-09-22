# Phase B slice4 — deeper L5 fingerprints + L6 tech diffs

**Date:** 2026-09-22 (Asia/Colombo)  
**Commit intent:** `feat: Phase B slice4 — deeper L5 fingerprints + L6 tech diffs`

## Layers (reality table)

| Layer | Status | Notes |
| --- | --- | --- |
| L0 Program brain | **real** | import-brief + `program.yml` fields / `layers_enabled` |
| L1 Identity | **lite real (low confidence)** | RDAP org/email + ASN stub + MX + SPF; injectable; no sherlock/maigret |
| L2 Passive DNS/CT | **real (native) + hardened crt.sh + reverse-IP stub** | tools still deferred; ENGINE_ALLOWLIST empty (Founder HOLD) |
| L3 Code OSINT | **deferred** | |
| L4 Cloud | **deferred** | |
| L5 Live map | **lite real + deeper tech fingerprint** | resolve + ports + HTTP probe + expanded native heuristics → `tech[]` + TECH events |
| L6 Watch | **MVP real + tech diffs** | `runs/latest.json` + history; snapshot `tech[]` keys; diffs `tech.added` / `tech.removed` (24h/7d via timestamps) |
| Ranker | **real** | interestingness + rare/admin tech boosts (expanded set) |

## Deeper fingerprint coverage (honest, not Wappalyzer)

Still **stdlib-only**, injectable headers/body/url. Confidence **low–med** (≈0.40–0.65).

**New / expanded stacks:** Tomcat, Jira, Confluence, Grafana, Kibana, Vercel, Netlify, Shopify, Magento, Drupal/Joomla extras, Flask/Werkzeug, FastAPI/Uvicorn, Gin (weak), `wp-json` path, more cookie names.

**`git-exposure` (CONF_LOW):** fingerprint-only clue when `/.git` already appears in the fetched URL or body metadata (`ref: refs/heads/…`). Does **not** probe or fetch `/.git` — no exploit path.

## L6 tech diffs

- `snapshot_from_inventory` stores sorted tech **name** keys
- `diff_snapshots` / `watch_compare_and_persist` emit `tech.added` / `tech.removed`
- Second watch run detects newly fingerprinted stacks

## Honesty / HOLD

- **ENGINE_ALLOWLIST remains empty** — Founder HOLD; no `--tools` download wiring
- No L3/L4; no Guard; no workflows; MIT; scope fences unchanged
