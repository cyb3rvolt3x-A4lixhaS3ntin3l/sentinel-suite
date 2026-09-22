# Phase C slice6 — graphql pack v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice6 — graphql pack v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `graphql` v0 | **real (candidates)** | `needs_roles=0`; Role A optional |
| Introspection fixtures | **real** | enabled / disabled candidates |
| Mutation auth-diff | **real (soft)** | unauth vs Role A; soft coach if Role A missing |
| Global / opaque ID | **real (fixture)** | enumeration-ish candidates only |
| Batch / alias | **hints only** | `needs_human` hints — no alias floods |
| Live-mock hard caps | **real** | requests≤10 when opener/live_mock used |
| Human gate | **real** | findings `needs_human` / `unverified`; never auto-VERIFIED |
| Prior packs | **intact** | `ato_oauth_oidc` · `bola_idor_bfla` · `business_logic` · `race_toctou` |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Treat GraphQL as **schema + mutations + ID encoding**, not “a URL”
- Emit introspection-enabled candidates from fixtures (built-in 127.0.0.1 defaults)
- Soft-skip mutation auth-diff checks with coach text when Role A is absent; still run introspection / global-id / batch hints
- Emit unauth-vs-auth mutation candidates when Role A is present
- Emit opaque/global ID enumeration-ish candidates from fixtures
- Emit batch/alias **needs_human hints only** (no automated alias abuse)
- Enforce hard request caps if any live mock / opener is used
- Attach finding-gate checklist + honest verification enum
- Scope-gate via `--scope` or `--i-own-this`

## What the pack cannot do

- Full InQL fork / schema dumping / data-exfiltration modules
- Live third-party GraphQL hammering or alias floods
- Live SSRF collaborator
- Auto-VERIFIED / confirmed findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, `--tools`, workflows, X, nuclei-all

## Honesty fence

Authorized **detection scaffolding** only — fixture-driven by default. GraphQL is not a single URL; this pack surfaces review candidates for humans, not exploit chains.

## CLI

```bash
sentinel hunt pack list
# Role A optional — introspection still runs:
sentinel hunt pack run graphql --program demo --i-own-this
# with Role A for mutation auth-diff:
sentinel hunt pack run graphql --program demo --i-own-this --role-a ./roles/a.json
# scoped:
sentinel hunt pack run graphql --program demo --scope ./scope.txt
sentinel hunt report demo --pack graphql -o ./graphql-report.md
# prior packs still work:
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
  "introspection": [
    {
      "name": "enabled",
      "url": "http://127.0.0.1/graphql",
      "response": {
        "status": 200,
        "body": "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}}",
        "data": {"__schema": {"queryType": {"name": "Query"}}}
      },
      "expect": {"introspection_enabled": true}
    }
  ],
  "mutations": [
    {
      "url": "http://127.0.0.1/graphql",
      "mutation": "createUser",
      "unauth_response": {"status": 200, "body": "{\"data\":{\"createUser\":{\"id\":\"1\"}}}"},
      "auth_response": {"status": 200, "body": "{\"data\":{\"createUser\":{\"id\":\"1\"}}}"},
      "expect": {"unauth_mutation_allowed": true}
    }
  ],
  "global_ids": [
    {
      "url": "http://127.0.0.1/graphql",
      "samples": ["VXNlcjox", "VXNlcjoy"],
      "responses": [
        {"status": 200, "body": "{\"data\":{\"node\":{\"id\":\"1\"}}}"},
        {"status": 200, "body": "{\"data\":{\"node\":{\"id\":\"2\"}}}"}
      ],
      "expect": {"enumerable": true}
    }
  ],
  "batch_alias": [
    {"url": "http://127.0.0.1/graphql", "alias_count": 50, "expect": {"alias_abuse": true}}
  ]
}
```

Fixtures are injected in tests via `run_pack(..., fixtures={...})`.

## Caps (live mock only)

Constants in `gungnir.packs.graphql.caps`: `HARD_MAX_REQUESTS=10` (default 6). Over-limit → hard fail. Fixture-only runs do not consume the budget.

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this` to start
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no nuclei-all; no `--tools`; no X

## Explicit defer

InQL full fork; live SSRF collaborator; coach UI; Guard; `--tools`; workflows; X
