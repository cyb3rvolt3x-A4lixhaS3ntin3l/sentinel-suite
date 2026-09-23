# Phase C slice8 — csrf_state pack v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice8 — csrf_state pack v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `csrf_state` v0 | **real (candidates)** | `needs_roles=0` |
| Missing CSRF on state-changing methods | **real** | explicit fixture signal required (no spray) |
| Unbound / reusable token | **real** | fixture `unbound_marker` / `session_bound=false` |
| SameSite=None without Secure | **real** | Set-Cookie flag string evidence |
| Double-submit vs synchronizer | **hints only** | coach hints; not auto-confirm |
| Live-mock hard caps | **real** | requests≤10 when opener/live_mock used |
| Human gate | **real** | findings `needs_human` / `unverified`; never auto-VERIFIED |
| Prior packs | **intact** | `ato_oauth_oidc` · `bola_idor_bfla` · `business_logic` · `race_toctou` · `graphql` · `xss_dom` |
| race_toctou hard caps | **untouched** | workers≤4, requests≤20, duration≤5s |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Emit missing-CSRF candidates on POST/PUT/DELETE/PATCH when fixtures carry an
  **explicit** missing-token signal (`expect.missing_csrf`, `csrf_present=false`, …)
- Emit unbound / reusable token candidates from fixture markers
- Emit SameSite=None without Secure (and weak cookie-flag) candidates from
  Set-Cookie fixture strings
- Emit double-submit vs synchronizer-token **needs_human coach hints only**
- Enforce hard request caps if any live mock / opener is used
- Attach finding-gate checklist + honest verification enum
- Scope-gate via `--scope` or `--i-own-this`

## What the pack cannot do

- Cross-site CSRF farms / browser automation / auto form-flood
- Live mass state-changing spray against random hosts
- Auto-VERIFIED / confirmed findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X
- Raise `race_toctou` hard caps

## Honesty fence

Authorized **detection scaffolding** only — fixture-driven by default. Evidence =
concrete fixture signals (missing token field, unbound marker, cookie flag string).
Blind form POSTs are rejected.

## CLI

```bash
sentinel hunt pack list
sentinel hunt pack run csrf_state --program demo --i-own-this
sentinel hunt pack run csrf_state --program demo --scope ./scope.txt
sentinel hunt report demo --pack csrf_state -o ./csrf-report.md
# prior packs still work:
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
  "state_changing": [
    {
      "name": "email-change",
      "url": "http://127.0.0.1/account/email",
      "method": "POST",
      "body": {"email": "new@lab.example"},
      "csrf_present": false,
      "expect": {"missing_csrf": true}
    }
  ],
  "unbound_token": [
    {
      "url": "http://127.0.0.1/transfer",
      "method": "POST",
      "token": "STATIC_CSRF_TOKEN_DEMO",
      "session_bound": false,
      "reusable": true,
      "unbound_marker": "STATIC_CSRF_TOKEN_DEMO",
      "expect": {"unbound": true, "reusable": true}
    }
  ],
  "cookie_flags": [
    {
      "url": "http://127.0.0.1/",
      "set_cookie": "session=abc; Path=/; SameSite=None",
      "expect": {"samesite_none_without_secure": true}
    }
  ],
  "csrf_patterns": [
    {
      "pattern": "double_submit_cookie",
      "cookie_name": "csrf",
      "form_field": "csrf"
    }
  ]
}
```

Fixtures are injected in tests via `run_pack(..., fixtures={...})`.

## Caps (live mock only)

Constants in `gungnir.packs.csrf_state.caps`: `HARD_MAX_REQUESTS=10` (default 6).
Over-limit → hard fail. Fixture-only runs do not consume the budget.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this` to start
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no CSRF farms; no `--tools`; no X
