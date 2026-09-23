# Phase C slice9 — open_redirect pack v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice9 — open_redirect pack v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `open_redirect` v0 | **real (candidates)** | `needs_roles=0` |
| Param redirect (next/return/url/redirect/continue) | **real** | only with Location/external evidence (no bare-param noise) |
| Protocol-relative `//evil` | **real** | fixture `//` + Location/expect signal |
| Encoded bypass (`%2F%2F`, double-encode) | **real** | fixture encoded target + evidence |
| Location header reflection | **real** | attacker-controlled value reflected in Location |
| Allowlist vs denylist | **hints only** | coach hints; not auto-confirm |
| Live-mock hard caps | **real** | requests≤10 when opener/live_mock used |
| Human gate | **real** | findings `needs_human` / `unverified`; never auto-VERIFIED |
| Prior packs | **intact** | `ato_oauth_oidc` · `bola_idor_bfla` · `business_logic` · `race_toctou` · `graphql` · `xss_dom` · `csrf_state` |
| race_toctou hard caps | **untouched** | workers≤4, requests≤20, duration≤5s |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Emit param-redirect candidates when fixtures show concrete redirect evidence
  to an **external** host (Location / redirect_to / expect flags — never bare param name)
- Emit protocol-relative `//evil` and encoded-bypass candidates from fixtures
- Emit Location-header reflection candidates when Location reflects an
  attacker-controlled external value
- Emit allowlist vs denylist **needs_human coach hints only**
- Enforce hard request caps if any live mock / opener is used
- Attach finding-gate checklist + honest verification enum
- Scope-gate via `--scope` or `--i-own-this`

## What the pack cannot do

- Blind param spray / live open-redirect farms / browser automation
- Emit on bare query-param name alone (no redirect evidence → skip)
- Auto-VERIFIED / confirmed findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X
- Raise `race_toctou` hard caps

## Honesty fence

Authorized **detection scaffolding** only — fixture-driven by default. Evidence =
concrete fixture signals (Location header value, external host in redirect target,
`//evil` or encoded bypass). Bare param-name noise is rejected.

## CLI

```bash
sentinel hunt pack list
sentinel hunt pack run open_redirect --program demo --i-own-this
sentinel hunt pack run open_redirect --program demo --scope ./scope.txt
sentinel hunt report demo --pack open_redirect -o ./or-report.md
# prior packs still work:
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
  "param_redirect": [
    {
      "name": "next-external",
      "url": "http://127.0.0.1/login",
      "params": {"next": "https://evil.example/phish"},
      "response": {
        "status": 302,
        "headers": {"Location": "https://evil.example/phish"}
      },
      "expect": {
        "open_redirect": true,
        "external_redirect": true,
        "location_reflects": true
      }
    }
  ],
  "protocol_relative": [
    {
      "url": "http://127.0.0.1/out",
      "params": {"url": "//evil.example/path"},
      "response": {"status": 302, "headers": {"Location": "//evil.example/path"}},
      "expect": {"protocol_relative": true, "open_redirect": true}
    }
  ],
  "encoded_bypass": [
    {
      "url": "http://127.0.0.1/go",
      "params": {"redirect": "%2F%2Fevil.example%2F"},
      "response": {
        "status": 302,
        "headers": {"Location": "%2F%2Fevil.example%2F"}
      },
      "expect": {"encoded_bypass": true, "open_redirect": true}
    }
  ],
  "location_reflect": [
    {
      "url": "http://127.0.0.1/redirect",
      "params": {"continue": "https://evil.example/x"},
      "response": {
        "status": 302,
        "headers": {"Location": "https://evil.example/x"}
      },
      "expect": {"location_reflects": true, "external_redirect": true}
    }
  ],
  "redirect_validation": [
    {
      "pattern": "allowlist",
      "note": "Prefer allowlist of known-good hosts."
    }
  ]
}
```

Fixtures are injected in tests via `run_pack(..., fixtures={...})`.

## Caps (live mock only)

Constants in `gungnir.packs.open_redirect.caps`: `HARD_MAX_REQUESTS=10` (default 6).
Over-limit → hard fail. Fixture-only runs do not consume the budget.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this` to start
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no redirect farms; no `--tools`; no X
