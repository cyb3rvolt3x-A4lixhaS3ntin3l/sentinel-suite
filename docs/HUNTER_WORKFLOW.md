# Hunter workflow — map → pack → confirm → report

Short Phase C loop for authorized hunting. Packs never auto-confirm;
`confirm-finding` is the only path to `confirmed` / `verified`.

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

## Honesty fence

- Packs emit candidates with `needs_human` / `unverified` only.
- Pack-claimed `confirmed`/`verified` is coerced to `needs_human` on emit.
- Steps come from stored evidence stubs + checklist — no generative fill.
- ENGINE_ALLOWLIST stays empty until Founder pins hashes.
