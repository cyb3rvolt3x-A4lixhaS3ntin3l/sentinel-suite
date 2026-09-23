# Free promise — forever local vs paid later

**Status:** Productization complete. Free-promise lock (historical G0) still holds — no G1.  
**Date:** 2026-09-23 (Asia/Colombo)  
**Rule:** a solo authorized hunter can map scope, watch diffs, run official packs, coach/labs, confirm findings, and export reports **without** an account, without a credit card, and without calling home.

Legal disclaimer language for marketing sites is **pending counsel review** — see `docs/HUMAN-QUEUE.md`. Product ethics fence (authorized use only) stays.

---

## Free forever vs paid later

| Layer | **Free forever** (open / local) | **Paid later** (SaaS / team — only after prerequisites) |
| --- | --- | --- |
| **Install & runtime** | Local single-user suite (pipx/path/git, Compose, Tauri shell when packaging is real) | Cloud-hosted watch workers; managed collaborator / interactsh-class receive |
| **Modules** | Official modules on `stable` (+ documented `lab` / `nightly` community channels) | Marketplace + **certified** packs (review, signature, SLA) |
| **Data** | Local `~/.sentinel/programs/` + **local graph zip export** (`sentinel program export`) | Encrypted sync of programs/graph; private team vaults |
| **Collaboration** | Single operator; optional local multi-process on loopback | Team claims / shared programs / seat invites |
| **Identity** | No SSO required; local bind `127.0.0.1` | SSO (OIDC/SAML) for org seats |
| **Brand CLIs** | `shadowseye`, `gungnir`, `sentinel` / `sentinel-suite` stay usable offline | Optional cloud login for paid surfaces only |
| **Trust** | MIT (now); signed module index when ready | SLA, private programs, seat pricing, support tiers |
| **Sister products** | — | Guard SaaS / `sentinelreign.com` stay **separate** — never bundled into this suite |

Paid surfaces (when they exist) are **additive** — never a cripple switch on local packs, Eye watch, Coach, labs, or offline reports.

---

## User-visible free-promise checklist

A solo authorized hunter can do all of the following **offline**, with **no account**, **no credit card**, and **no calling home**:

1. **Install & run locally** — path/git/Compose (`docs/INSTALL.md`); UI at `http://127.0.0.1:8888`
2. **Map scope** — `sentinel program init` / `import-brief` + scope kernel
3. **Watch** — `sentinel eye run` (diffs / interestingness)
4. **Run official packs** — `sentinel hunt pack run` (12 official packs)
5. **Coach / labs** — labs + Coach (no LLM invent)
6. **Confirm findings** — `sentinel hunt confirm-finding` (human gate)
7. **Export reports offline** — `sentinel hunt report` / `sentinel lab report` → markdown on disk
8. **Zip-export program/graph** — `sentinel program export <id>` → `~/.sentinel/exports/` (or `-o`)

### Explicitly not required for the free path

| Not required | Notes |
| --- | --- |
| Account / signup | Optional local UI bcrypt under `ui_auth.json` is device-local only |
| Credit card / payment SDK | No Stripe/Razorpay in this tree |
| Calling home / always-on telemetry | Telemetry **OFF by default**; see below |
| Cloud workers / SSO / marketplace | Paid-later only; not started |
| Guard SDK | Separate product — never bundled |

---

## Telemetry (optional, OFF by default)

| | |
| --- | --- |
| **Default** | **OFF** — unset / `SENTINEL_TELEMETRY=0` |
| **Opt-in** | `SENTINEL_TELEMETRY=1` (also `true` / `yes` / `on`) |
| **CLI** | `sentinel telemetry status` |
| **Settings UI** | `/api/settings` → `telemetry` object |
| **Sink today** | Local JSONL under `SENTINEL_HOME/telemetry/local.jsonl` only |
| **Network** | **No phone-home** even when opted in (no remote endpoint wired) |

```bash
# default — no-op collector
sentinel telemetry status
# opt-in local stub only (still no network):
SENTINEL_TELEMETRY=1 sentinel telemetry status
```

Do **not** invent ARR / users / stars from telemetry files.

---

## Zip export (free path)

```bash
sentinel program init demo
# … hunt / eye / confirm …
sentinel program export demo
# → ~/.sentinel/exports/demo-<timestamp>.zip
sentinel program export demo -o ./demo-backup.zip --json
```

Includes `program.yml`, `scope.txt`, `graph.sqlite`, roles, runs, reports, and an `EXPORT_MANIFEST.txt`. Local only — no upload.

---

## Still out of scope

- Payments, Stripe/Razorpay, accounts, marketplace, cloud workers, SSO
- Guard SDK / `sentinelagent-guard`
- New hunt packs / `ENGINE_ALLOWLIST` hashes
- Team/cloud/marketplace (not started)
- Invented metrics
