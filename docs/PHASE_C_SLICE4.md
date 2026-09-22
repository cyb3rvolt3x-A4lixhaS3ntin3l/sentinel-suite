# Phase C slice4 — business_logic assistant v0

**Date:** 2026-09-23 (Asia/Colombo)  
**Commit intent:** `feat: Phase C slice4 — business_logic assistant v0`

## Shipped

| Piece | Status | Notes |
| --- | --- | --- |
| Pack `business_logic` v0 | **real (assistant)** | `needs_roles=1`; fixture + HTML/form stubs |
| FLOW / STEP event types | **real** | `sentinel_core.EVENT_TYPES`; parents wired |
| Flow mapper | **real (fixture)** | cart→checkout, invite→accept, transfer→confirm, apply→approve |
| HTML/form crawl stubs | **stub** | fixture HTML only; scope-gated; no live crawl abuse |
| Coach hints | **real** | questions a hunter should ask (price tamper, step skip, replay, qty overflow, …) |
| Human gate | **real** | findings default `needs_human`; never auto-VERIFIED/confirmed |
| `sentinel hunt confirm-finding` | **real** | explicit human confirm / role mark |
| CLI list\|run\|report | **wired** | existing pack registry + `--pack business_logic` |
| ATO + BOLA packs | **intact** | `ato_oauth_oidc` + `bola_idor_bfla` still listed/runnable |
| ENGINE_ALLOWLIST | **still {}** | no change |

## What the pack can do

- Map multi-step flow candidates from lab fixtures (`fixtures.flows` with ≥2 steps)
- Optionally parse fixture HTML forms/links into flow stubs (scope hard-kill)
- Emit FLOW and STEP graph events (low confidence until human marks)
- Attach **coach hints** (checklist of hunter questions) on finding payloads / hint records
- Keep all findings at `needs_human` / `unverified` until `confirm-finding`
- Soft OOS filter via scope hard-kill (same as other packs)

## What the pack cannot do

- Invent confirmed bugs / auto-VERIFIED findings
- Live payment capture, other-customer harm, or destructive actions
- Race/TOCTOU packs, live SSRF collaborator, full coach UI, LLM prose
- Guard SDK, workflows, X, `--tools`, nuclei-all

## Honesty fence

This is a **business-logic assistant**, not a spray chatbot:

- Default output is FLOW/STEP maps + coach questions
- Humans confirm before any finding is `confirmed` / `verified`
- No live abuse automation

## CLI

```bash
sentinel hunt pack list
# prepare roles/a.json under the program
sentinel hunt pack run business_logic --program demo --scope ./scope.txt
# lab:
sentinel hunt pack run business_logic --program demo --i-own-this
sentinel hunt report demo --pack business_logic -o ./bl-report.md
# after human review:
sentinel hunt confirm-finding demo <finding-id> --status confirmed --note 'reproduced in lab' --mark-role a
# prior packs still work:
sentinel hunt pack run ato_oauth_oidc --program demo --i-own-this \
  --url 'https://lab.example/oauth/authorize?client_id=1&response_type=code&redirect_uri=https://lab.example/cb'
sentinel hunt pack run bola_idor_bfla --program demo --i-own-this \
  --role-a ./roles/a.json --role-b ./roles/b.json
```

Fixtures are injected in tests via `run_pack(..., fixtures={...})` (mocked). Production CLI remains scope-gated and role-gated.

### Fixture shape (lab)

```json
{
  "flows": [
    {
      "name": "cart-checkout",
      "url": "https://lab.example/cart",
      "steps": [
        {"name": "cart", "url": "https://lab.example/cart"},
        {"name": "checkout", "url": "https://lab.example/checkout"}
      ]
    }
  ],
  "html_pages": [
    {
      "url": "https://lab.example/shop",
      "html": "<form action=\"/cart\"></form><a href=\"/checkout\">Checkout</a>"
    }
  ]
}
```

## Fences / HOLD

- Scope hard kill; `--scope` or `--i-own-this`
- Role A fail-closed (`needs_roles=1`)
- Findings never auto-`verified` / `confirmed`
- **ENGINE_ALLOWLIST remains {}**
- MIT; no workflows; no Guard SDK; no nuclei-all

## Explicit defer

Race/TOCTOU, live SSRF collaborator, full coach UI, LLM prose, Guard, `--tools`, workflows, X
