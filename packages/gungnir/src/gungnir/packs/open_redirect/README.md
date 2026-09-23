# Pack `open_redirect` v0

Open redirect / unvalidated redirect candidates with **fixture evidence**, not
blind parameter spray.

## Can

- Emit param-redirect candidates (next/return/url/redirect/continue/…) when
  fixtures show concrete redirect evidence to an external host
- Emit protocol-relative `//evil` and encoded-bypass candidates from fixtures
- Emit Location-header reflection candidates when fixtures show Location
  reflecting an attacker-controlled external value
- Emit allowlist vs denylist **coach hints only** (not auto-confirm)
- Attach checklist + honest `needs_human` / `unverified` verification (never auto-VERIFIED)
- Hard-cap live-mock requests (≤10)
- Run with `needs_roles=0` (no Role A/B required)

## Cannot

- Blind param spray / live open-redirect farms / browser automation
- Emit on bare query-param name alone (no redirect evidence → skip)
- Auto-confirm findings (use `sentinel hunt confirm-finding`)
- Coach UI, Guard SDK, workflows, X

Authorized / lab only. Scope via `--scope` or `--i-own-this`.
