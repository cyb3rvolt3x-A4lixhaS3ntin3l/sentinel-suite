# Hunter workflow — map → pack → confirm → report

Authorized hunter loop. Packs never auto-confirm;
`confirm-finding` is the only path to `confirmed` / `verified`.

Productization is complete. Historical build-phase notes live in `docs/PHASE_*`.

## 1) Map (ShadowsEye)

```bash
sentinel program init demo
sentinel program import-brief demo ./brief.txt --platform auto
sentinel eye run demo example.com --i-own-this --json --watch --no-tools
```

Use `--scope FILE` instead of `--i-own-this` for real program scope.

## 2) Pack (Gungnir)

```bash
sentinel hunt pack list
sentinel hunt pack run business_logic --program demo --i-own-this
# findings land as needs_human / unverified — never auto-confirmed
```

Lab-gated packs (`race_toctou`, `http_desync` beyond fixtures) also need
`--i-understand-lab`. Open-internet needs `--scope` too.

Optional owned collaborator listener (ssrf_collaborator; loopback default):

```bash
sentinel collaborator serve --program demo
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this --listen
```

## 3) Confirm (human gate)

```bash
# List pending findings
sentinel hunt findings demo --status needs_human
sentinel hunt findings demo --pack business_logic --status pending

# Explicit human confirm (note required; stamps who/when)
sentinel hunt confirm-finding demo <finding-id> \
  --status confirmed \
  --note 'reproduced price tamper in lab' \
  --who 'alice' \
  --mark-role a

# Other clear statuses
sentinel hunt confirm-finding demo <finding-id> --status not_reproduced --note '...'
sentinel hunt confirm-finding demo <finding-id> --status rejected --note '...'
sentinel hunt confirm-finding demo <finding-id> --status skipped --note '...'
sentinel hunt confirm-finding demo <finding-id> --status unverified --note '...'
```

Statuses: `confirmed` | `not_reproduced` | `unverified` | `skipped` | `rejected`
(aliases: `verified` ≈ confirmed; `needs_human` re-queues).

## 4) Report (evidence log only)

```bash
# Single pack
sentinel hunt report demo --pack business_logic -o ./bl-report.md

# All packs (default when --pack omitted; or explicit)
sentinel hunt report demo --all-packs -o ./all-packs-report.md
```

Report sections: **Summary**, **Scope**, **Steps to Reproduce** (evidence +
checklist fields only — never LLM-invented), **Impact**, **Remediation**
placeholders.

## 5) Zip-export (offline backup — free path)

```bash
sentinel program export demo
# → ~/.sentinel/exports/demo-<timestamp>.zip  (or -o ./demo.zip)
```

Local only — no account, no upload. See [`FREE_PROMISE.md`](FREE_PROMISE.md).


## Official hunt packs (12)

`sentinel hunt pack list` — Role A at `roles/a.json` (`cookies|headers|bearer`) unless `needs_roles=0`.
`bola_idor_bfla` also needs Role B. All findings stay `needs_human` / `unverified` until `confirm-finding`.

| Pack | Roles | Extra flags |
| --- | ---: | --- |
| `ato_oauth_oidc` | 1 | |
| `bola_idor_bfla` | 2 | |
| `business_logic` | 1 | |
| `race_toctou` | 1 | `--i-understand-lab` (+ caps) |
| `graphql` | 0 (Role A optional) | |
| `xss_dom` | 0 | |
| `csrf_state` | 0 | |
| `open_redirect` | 0 | |
| `cache_host` | 0 | |
| `jwt_session` | 0 | |
| `http_desync` | 0 | `--i-understand-lab` beyond fixtures |
| `ssrf_collaborator` | 0 | `--listen` / `--collaborator`; `--i-understand-lab` beyond local mock |

```bash
sentinel hunt pack run ato_oauth_oidc --program demo --i-own-this \
  --url 'https://lab.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://lab.example/cb'
sentinel hunt pack run bola_idor_bfla --program demo --i-own-this \
  --role-a ./roles/a.json --role-b ./roles/b.json
sentinel hunt pack run business_logic --program demo --i-own-this
sentinel hunt pack run race_toctou --program demo --i-own-this --i-understand-lab \
  --max-workers 4 --max-requests 20 --max-duration 5
sentinel hunt pack run graphql --program demo --i-own-this
sentinel hunt pack run xss_dom --program demo --i-own-this
sentinel hunt pack run csrf_state --program demo --i-own-this
sentinel hunt pack run open_redirect --program demo --i-own-this
sentinel hunt pack run cache_host --program demo --i-own-this
sentinel hunt pack run jwt_session --program demo --i-own-this
sentinel hunt pack run http_desync --program demo --i-own-this --i-understand-lab
sentinel collaborator serve --program demo --bind 127.0.0.1 --port 8765
sentinel hunt pack run ssrf_collaborator --program demo --i-own-this --listen
# --collaborator must be operator-owned; refuses cloud metadata IPs unless lab fixture + --i-understand-lab
```

`http_desync` / `ssrf_collaborator` beyond pure fixtures also require `--i-understand-lab` (with `--i-own-this`); open-internet needs `--scope` too. `ssrf_collaborator` defaults to a local 127.0.0.1 collaborator mock. Public bind (`0.0.0.0`) needs `--i-understand-lab`. No interactsh / outbound scan.

Also: `sentinel demo` (does not scan random hosts) and `sentinel full-run --target … --scope …` (scope-gated). UI: `sentinel ui --open` → http://127.0.0.1:8888.

## Honesty fence

- Packs emit candidates with `needs_human` / `unverified` only.
- Pack-claimed `confirmed`/`verified` is coerced to `needs_human` on emit.
- Steps come from stored evidence stubs + checklist — no generative fill.
- ENGINE_ALLOWLIST stays empty until Founder pins hashes.
