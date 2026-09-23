# Phase C slice13 — confirm-finding + report polish

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice13 — confirm-finding + report polish`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| `confirm-finding` harden | **real** | statuses + required note + who/when stamp |
| Refuse pack auto-confirm | **real** | runner coerces confirmed/verified → needs_human |
| `hunt findings` list | **real** | `--pack` / `--status needs_human|pending|…` |
| Report polish | **real** | Summary / Scope / Steps / Impact / Remediation |
| `--all-packs` report | **real** | default all when `--pack` omitted |
| Docs hunter workflow | **real** | `docs/HUNTER_WORKFLOW.md` |
| New vuln pack | **none** | deferred |
| ENGINE_ALLOWLIST | **still {}** | no change |
| Prior 11 packs | **intact** | see pack list below |

## Confirm statuses

Primary: `confirmed` | `not_reproduced` | `unverified` | `skipped` | `rejected`  
Aliases kept: `verified` (≈ confirmed), `needs_human` (re-queue).

## CLI

```bash
sentinel hunt findings demo --status needs_human
sentinel hunt findings demo --pack http_desync --status pending
sentinel hunt confirm-finding demo <id> --status confirmed --note 'lab review' --who alice
sentinel hunt report demo --pack business_logic -o ./bl.md
sentinel hunt report demo --all-packs -o ./all.md
```

## Packs intact (11)

`ato_oauth_oidc` · `bola_idor_bfla` · `business_logic` · `cache_host` · `csrf_state` · `graphql` · `http_desync` · `jwt_session` · `open_redirect` · `race_toctou` · `xss_dom`

## Deferred (not this ship)

- Full H1/BC API submit
- Coach UI / Tauri
- SSRF pack
- PyPI publish
- Engine hash allowlist populate
- `.github/workflows` push (needs workflow OAuth scope)

## Can / Cannot

**Can:** list pending findings; human-confirm with stamped note/who/when;
export multi-pack markdown with evidence-only Steps + checklist fields.

**Cannot:** auto-confirm from packs; invent Steps with LLM; touch Guard SDK;
raise race_toctou / http_desync caps; populate ENGINE_ALLOWLIST.
