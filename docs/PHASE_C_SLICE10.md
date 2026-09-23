# Phase C slice10 — cache_host pack v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice10 — cache_host pack v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `cache_host` v0 | **real (candidates)** | `needs_roles=0` |
| Host / X-Forwarded-Host reflection | **real** | only with header-in → body/header-out evidence + cacheable signal |
| X-Forwarded-Scheme reflection | **real** | fixture scheme-in → body/header-out |
| Path confusion / cache-key mismatch | **real** | fixture cache_key_a vs cache_key_b + content/path diff |
| Cache-Control / Vary | **hints only** | coach hints; not auto-confirm |
| Live-mock hard caps | **real** | requests≤10 when opener/live_mock used |
| Human gate | **real** | findings `needs_human` / `unverified`; never auto-VERIFIED |
| Prior packs | **intact** | `ato_oauth_oidc` · `bola_idor_bfla` · `business_logic` · `race_toctou` · `graphql` · `xss_dom` · `csrf_state` · `open_redirect` |
| race_toctou hard caps | **untouched** | workers≤4, requests≤20, duration≤5s |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Emit Host / X-Forwarded-Host / X-Forwarded-Scheme reflection candidates when
  fixtures show the injected value landing in a **cacheable** body or response
  header (evidence diffs — never bare header name)
- Emit path-confusion / URL-normalization cache-key mismatch candidates when
  fixtures show differing keys (key A vs B) with a content/header/path diff
- Emit Cache-Control / Vary **needs_human coach hints only**
- Enforce hard request caps if any live mock / opener is used
- Attach finding-gate checklist + honest verification enum
- Scope-gate via `--scope` or `--i-own-this`

## What the pack cannot do

- **Poison production CDN** / live CDN purge-poison tooling / mass Host-header spray / browser farms
- Emit on bare Host / X-Forwarded-* header name alone (no reflection/key-mismatch evidence → skip)
- Auto-VERIFIED / confirmed findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X
- Raise `race_toctou` hard caps

## Honesty fence

Authorized **detection scaffolding** only — fixture-driven by default. Evidence =
concrete fixture diffs (header-in vs body/header-out; cache-key A vs B;
Cache-Control/Vary strings for coach hints). Staging/lab first — **not** a live
CDN poison weapon.

## CLI

```bash
sentinel hunt pack list
sentinel hunt pack run cache_host --program demo --i-own-this
sentinel hunt pack run cache_host --program demo --scope ./scope.txt
sentinel hunt report demo --pack cache_host -o ./cache-host-report.md
# prior packs still work:
sentinel hunt pack run open_redirect --program demo --i-own-this
sentinel hunt pack run csrf_state --program demo --i-own-this
sentinel hunt pack run xss_dom --program demo --i-own-this
sentinel hunt pack run graphql --program demo --i-own-this
sentinel hunt pack run race_toctou --program demo --i-own-this --i-understand-lab
sentinel hunt pack run business_logic --program demo --i-own-this
sentinel hunt pack run bola_idor_bfla --program demo --i-own-this \
  --role-a ./roles/a.json --role-b ./roles/b.json
sentinel hunt pack run ato_oauth_oidc --program demo --i-own-this \
  --url 'https://lab.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://lab.example/cb'
```

### Fixture shape (lab)

```json
{
  "host_reflect": [
    {
      "name": "host-in-canonical",
      "url": "http://127.0.0.1/app",
      "request_headers": {"Host": "evil.example"},
      "response": {
        "status": 200,
        "headers": {"Cache-Control": "public, max-age=3600"},
        "body": "<link rel=\"canonical\" href=\"https://evil.example/app\"/>"
      },
      "expect": {"host_reflects": true, "cacheable": true}
    }
  ],
  "scheme_reflect": [
    {
      "url": "http://127.0.0.1/login",
      "request_headers": {
        "Host": "127.0.0.1",
        "X-Forwarded-Scheme": "http"
      },
      "response": {
        "status": 200,
        "headers": {"Cache-Control": "public, max-age=120"},
        "body": "<a href=\"http://127.0.0.1/login\">continue</a>"
      },
      "expect": {"scheme_reflects": true, "cacheable": true}
    }
  ],
  "path_confusion": [
    {
      "url": "http://127.0.0.1/static",
      "path_a": "/static/../admin",
      "path_b": "/admin",
      "cache_key_a": "GET|/static/../admin|host=127.0.0.1",
      "cache_key_b": "GET|/admin|host=127.0.0.1",
      "body_a": "cached-static-poison",
      "body_b": "real-admin",
      "expect": {"key_mismatch": true, "path_confusion": true}
    }
  ],
  "cache_control_vary": [
    {
      "pattern": "cache_control",
      "cache_control": "public, max-age=86400",
      "note": "Long max-age on sensitive page?"
    }
  ]
}
```

Fixtures are injected in tests via `run_pack(..., fixtures={...})`.

## Caps (live mock only)

Constants in `gungnir.packs.cache_host.caps`: `HARD_MAX_REQUESTS=10` (default 6).
Over-limit → hard fail. Fixture-only runs do not consume the budget.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this` to start
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no production CDN poison; no `--tools`; no X
