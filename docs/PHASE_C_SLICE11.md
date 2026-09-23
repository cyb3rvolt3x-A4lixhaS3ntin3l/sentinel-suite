# Phase C slice11 — jwt_session pack v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice11 — jwt_session pack v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `jwt_session` v0 | **real (candidates)** | `needs_roles=0` |
| Session fixation (not rotated) | **real** | only when fixtures show pre-login cookie == post-login cookie |
| JWT alg=none / weak alg / missing exp / kid confusion | **real** | decoded from **fixture token strings only** |
| Token in query/fragment leakage | **real** | when fixtures show JWT in URL query or fragment |
| Coach hints | **hints only** | rotate session on auth; reject alg=none; cookies not query |
| Live-mock hard caps | **real** | requests≤10 when opener/live_mock used |
| Human gate | **real** | findings `needs_human` / `unverified`; never auto-VERIFIED |
| Prior packs | **intact** | `ato_oauth_oidc` · `bola_idor_bfla` · `business_logic` · `race_toctou` · `graphql` · `xss_dom` · `csrf_state` · `open_redirect` · `cache_host` |
| race_toctou hard caps | **untouched** | workers≤4, requests≤20, duration≤5s |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Emit session-fixation candidates when fixtures show the same session cookie
  before and after login (not rotated)
- Emit JWT weak-handling candidates (alg=none / weak alg vs expected asymmetric /
  missing exp / kid confusion) by **decoding fixture token strings only**
- Emit token-in-query/fragment leakage candidates when fixtures show a JWT in
  the URL query or fragment
- Enforce hard request caps if any live mock / opener is used
- Attach finding-gate checklist + honest verification enum
- Scope-gate via `--scope` or `--i-own-this`

## What the pack cannot do

- **Live IdP hammering** / credential stuffing / session-hijack runbooks against real IdPs
- **Token exfiltration modules** / mint attack payloads for unauthorized use / forge live sessions
- Auto-VERIFIED / confirmed findings (use `sentinel hunt confirm-finding`)
- Replace or alter `ato_oauth_oidc` (OAuth/OIDC pack stays as-is; this pack is session + JWT crypto/handling)
- Coach UI, Guard SDK, workflows, X
- Raise `race_toctou` hard caps

## Honesty fence

Authorized **detection scaffolding** only — fixture-driven by default. Evidence =
concrete fixture signals (same session cookie before+after login; decoded JWT
header alg/kid/exp fields from fixture strings; token appearing in query/fragment
in fixture URL). Analyze fixture tokens only — **not** a live token-theft toolkit.

## CLI

```bash
sentinel hunt pack list
sentinel hunt pack run jwt_session --program demo --i-own-this
sentinel hunt pack run jwt_session --program demo --scope ./scope.txt
sentinel hunt report demo --pack jwt_session -o ./jwt-session-report.md
# prior packs still work:
sentinel hunt pack run cache_host --program demo --i-own-this
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
  "session_fixation": [
    {
      "name": "not-rotated",
      "url": "http://127.0.0.1/login",
      "pre_login": {"cookies": {"session": "SAME-SID"}},
      "post_login": {"cookies": {"session": "SAME-SID"}},
      "expect": {"fixation": true}
    }
  ],
  "jwt": [
    {
      "name": "alg-none",
      "url": "http://127.0.0.1/api/me",
      "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYWItdXNlciIsImlhdCI6MX0.",
      "expect": {"alg_none": true}
    },
    {
      "name": "weak-alg",
      "url": "http://127.0.0.1/api/me",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYWItdXNlciIsImV4cCI6OTk5OTk5OTk5OX0.lab-sig",
      "expected_alg": "RS256",
      "expect": {"weak_alg": true, "expected_alg": "RS256"}
    }
  ],
  "token_query": [
    {
      "url": "http://127.0.0.1/callback?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYWItdXNlciIsImlhdCI6MX0.lab-sig&token_type=bearer",
      "expect": {"token_in_query": true}
    }
  ]
}
```

Fixtures are injected in tests via `run_pack(..., fixtures={...})`.

## Caps (live mock only)

Constants in `gungnir.packs.jwt_session.caps`: `HARD_MAX_REQUESTS=10` (default 6).
Over-limit → hard fail. Fixture-only runs do not consume the budget.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this` to start
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no live IdP hammering; no token exfil; no `--tools`; no X
